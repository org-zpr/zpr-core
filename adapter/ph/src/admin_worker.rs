//! Receives commands, either from the cli or from someone directly interfacing
//! with the socket, performs action based on received command
//! To avoid excess parsing, the command must not have spaces

#![allow(unused_imports)]
#![allow(dead_code)]

use crate::assembly::Assembly;
use crate::config;
use crate::link_state::{LinkEvent, LinkState};
use crate::logging;
use crate::logging::targets::RPC;
use crate::logging::{levels, targets};
use crate::test_packet::TestPacketMetrics;
use crate::zdp::TerminateReason;
use cbpf_rs;
use cli_proto::cli_capnp as cli;
use cli_proto::cli_capnp::cmd_line_inter as svc;
use core::future::Future;
use hdrhistogram::Histogram;
use std::f64::consts::SQRT_2;
use std::fmt::Write;
use std::io::Error;
use std::io::IoSliceMut;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot::error::RecvError;
use tokio::task::JoinSet;
use tokio::time::interval;
use tokio_util::compat::*;
use tracing::error;
use tracing::*;
use zpr::rpc_commands::RpcCommands;
use zpr::LinkId;
use zpr_ext::std::os::unix::net::{AncillaryData, SocketAncillary};
use zpr_ext::tokio::net::*;

pub async fn launch_capnp(
    asm: Arc<Assembly>,
    listener: UnixListener,
) -> Result<(), Box<dyn std::error::Error>> {
    // let listener = tokio::net::UnixListener::bind(path)?;

    loop {
        let (sock, _addr) = listener.accept().await?;
        // TODO add connect info to log
        // println!("Connect from {addr:?}");
        let (reader, writer) = sock.into_split();
        let network = capnp_rpc::twoparty::VatNetwork::new(
            tokio::io::BufReader::new(reader).compat(),
            tokio::io::BufWriter::new(writer).compat_write(),
            capnp_rpc::rpc_twoparty_capnp::Side::Server,
            capnp::message::ReaderOptions::new(),
        );

        let service: svc::Client = capnp_rpc::new_client(AdminServiceImpl { asm: asm.clone() });

        let rpc_system = capnp_rpc::RpcSystem::new(Box::new(network), Some(service.clone().client));
        tokio::task::spawn_local(async move {
            let err = rpc_system.await;
            err
        });
    }
}

pub async fn launch(asm: Arc<Assembly>, listener: UnixListener) {
    match launch_capnp(asm.clone(), listener).await {
        Ok(()) => println!("SUCCESS"), // TODO remove this print
        Err(e) => println!("ERROR {}", e),
    };
}

struct AdminServiceImpl {
    asm: Arc<Assembly>,
}

impl svc::Server for AdminServiceImpl {
    fn echo(
        &mut self,
        _: svc::EchoParams,
        _: svc::EchoResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        // TODO add logging here and in the other commands
        capnp::capability::Promise::ok(())
    }

    fn reset_counters(
        &mut self,
        _: svc::ResetCountersParams,
        _: svc::ResetCountersResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        for value in self.asm.counters.management.values() {
            value.reset();
        }

        for fastpath in self.asm.counters.fastpaths.lock().unwrap().iter() {
            for value in fastpath.values() {
                value.reset();
            }
        }

        capnp::capability::Promise::ok(())
    }

    fn counters(
        &mut self,
        _: svc::CountersParams,
        mut results: svc::CountersResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        let mut counts: String = String::new();
        let _ = write!(&mut counts, "Management counts:\n");
        for (key, &ref value) in &self.asm.counters.management {
            let _ = write!(&mut counts, "{}: {}\n", key, value.get_count());
        }

        for (i, fastpath) in self
            .asm
            .counters
            .fastpaths
            .lock()
            .unwrap()
            .iter()
            .enumerate()
        {
            let _ = write!(&mut counts, "Fastpath counts: #{}\n", i);
            for (key, &ref value) in fastpath {
                let _ = write!(&mut counts, "{}: {}\n", key, value.get_count());
            }
        }

        let _ = write!(
            &mut counts,
            "Uptime: {}.{} s\n",
            self.asm.get_uptime().as_secs(),
            self.asm.get_uptime().subsec_millis()
        );
        let mut results_builder = results.get();
        results_builder.set_counts(counts);

        capnp::capability::Promise::ok(())
    }

    fn set_capture_file(
        &mut self,
        _: svc::SetCaptureFileParams,
        _: svc::SetCaptureFileResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        ::capnp::capability::Promise::err(::capnp::Error::unimplemented(
            "method cmd_line_inter::Server::set_capture_file not implemented".to_string(),
        ))
    }

    fn close_capture_file(
        &mut self,
        _: svc::CloseCaptureFileParams,
        _: svc::CloseCaptureFileResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        let task_asm = self.asm.clone();
        capnp::capability::Promise::from_future(async move {
            let _ = task_asm.capture_worker.close_capture_file().await;
            task_asm.flow_control.delete_program();

            Ok(())
        })
    }

    fn flush_capture_file(
        &mut self,
        _: svc::FlushCaptureFileParams,
        _: svc::FlushCaptureFileResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        let task_asm = self.asm.clone();
        capnp::capability::Promise::from_future(async move {
            let _ = task_asm.capture_worker.flush_capture_file().await;

            Ok(())
        })
    }

    fn set_capture_program(
        &mut self,
        params: svc::SetCaptureProgramParams,
        mut results: svc::SetCaptureProgramResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        let task_asm = self.asm.clone();
        capnp::capability::Promise::from_future(async move {
            let program = params.get()?.get_program()?.to_str()?;
            // Splits the rest of the string into the various instructions
            let mut serialized_program: Vec<&str> = program.split(',').collect();
            let mut insn_vec = Vec::new();
            serialized_program.remove(0); // removes number of programs from beginning of vector

            // Creates a vector of BpfInsns
            for insn in serialized_program {
                let split_insn: Vec<&str> = insn.split_whitespace().collect();
                let bpf_insn = cbpf_rs::BpfInsn {
                    code: split_insn[0].parse().unwrap(),
                    jt: split_insn[1].parse().unwrap(),
                    jf: split_insn[2].parse().unwrap(),
                    k: split_insn[3].parse().unwrap(),
                };
                insn_vec.push(bpf_insn);
            }

            let results_builder = results.get().init_result();

            match cbpf_rs::BpfProgram::validate(&insn_vec) {
                Ok(final_program) => {
                    task_asm.flow_control.set_program(final_program);
                    let mut success_builder = results_builder.init_success();
                    success_builder.set_none(());
                }
                _ => {
                    let mut error_builder = results_builder.init_error();
                    error_builder.set_txt("Invalid program")
                }
            }

            Ok(())
        })
    }

    fn delete_capture_program(
        &mut self,
        _: svc::DeleteCaptureProgramParams,
        _: svc::DeleteCaptureProgramResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        self.asm.flow_control.delete_program();
        capnp::capability::Promise::ok(())
    }

    fn perf_sample(
        &mut self,
        _: svc::PerfSampleParams,
        mut results: svc::PerfSampleResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        let mut results_builder = results.get();
        results_builder.set_result("Not currently supported");
        capnp::capability::Promise::ok(())
    }

    fn show_link_summary(
        &mut self,
        _: svc::ShowLinkSummaryParams,
        mut results: svc::ShowLinkSummaryResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        let mut results_builder = results.get();
        let mut response: String = String::new();
        let _ = write!(&mut response, "Link summary:\n");

        for id in self.asm.peer_ids.lock().unwrap().clone() {
            let _ = write!(
                &mut response,
                "  {id}: {}\n",
                get_link_summary(&self.asm, id)
            );
        }

        results_builder.set_summary(response);

        capnp::capability::Promise::ok(())
    }

    fn show_link(
        &mut self,
        params: svc::ShowLinkParams,
        mut results: svc::ShowLinkResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        let task_asm = self.asm.clone();
        capnp::capability::Promise::from_future(async move {
            let id = params.get()?.get_id();

            let mut results_builder = results.get();
            let response = match task_asm.peer_table.get(id) {
                Some(peer) => {
                    let lsm = &peer.link_state_machine;

                    format!(
                        "Link {id} info:\nSubstrate Address: {}\n{}",
                        peer.substrate_addr, lsm,
                    )
                }
                None => format!("No such link {id}\n"),
            };

            results_builder.set_result(response);

            Ok(())
        })
    }

    fn configure_link(
        &mut self,
        _: svc::ConfigureLinkParams,
        _: svc::ConfigureLinkResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        capnp::capability::Promise::ok(())
    }

    fn start_link(
        &mut self,
        params: svc::StartLinkParams,
        mut results: svc::StartLinkResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        let task_asm = self.asm.clone();
        capnp::capability::Promise::from_future(async move {
            let id = params.get()?.get_id();
            let results_builder = results.get().init_result();

            match task_asm.process_link_state_event(id, LinkEvent::Start) {
                Ok(_) => {
                    let mut success_builder = results_builder.init_success();
                    success_builder.set_none(());
                }
                Err(e) => {
                    let resp = format!("Failed to start link {}: {:?}\n", id, e);
                    let mut error_builder = results_builder.init_error();
                    error_builder.set_txt(resp);
                }
            }
            Ok(())
        })
    }

    fn stop_link(
        &mut self,
        params: svc::StopLinkParams,
        mut results: svc::StopLinkResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        let task_asm = self.asm.clone();
        capnp::capability::Promise::from_future(async move {
            let id = params.get()?.get_id();
            let results_builder = results.get().init_result();

            match task_asm.process_link_state_event(id, LinkEvent::Close(TerminateReason::Other)) {
                Ok(_) => {
                    let mut success_builder = results_builder.init_success();
                    success_builder.set_none(());
                }
                Err(e) => {
                    let resp = format!("Failed to stop link {}: {:?}\n", id, e);
                    let mut error_builder = results_builder.init_error();
                    error_builder.set_txt(resp);
                }
            }
            Ok(())
        })
    }

    fn reset_link(
        &mut self,
        params: svc::ResetLinkParams,
        _: svc::ResetLinkResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        let task_asm = self.asm.clone();
        capnp::capability::Promise::from_future(async move {
            let id = params.get()?.get_id();

            task_asm.reset_peer(id).await;
            Ok(())
        })
    }

    fn change_logging(
        &mut self,
        params: svc::ChangeLoggingParams,
        mut results: svc::ChangeLoggingResults,
    ) -> ::capnp::capability::Promise<(), ::capnp::Error> {
        let task_asm = self.asm.clone();
        capnp::capability::Promise::from_future(async move {
            let log_state = params.get()?.get_logs()?.to_str()?;
            let log_vec: Vec<&str> = log_state.split_whitespace().collect();
            let mut applied: Vec<String> = Vec::new();
            let mut ignored: Vec<String> = Vec::new();
            for elem in log_vec.iter() {
                let key_val: Vec<&str> = elem.split("=").collect();
                match key_val.len() {
                    2 => {
                        if targets::ALL_TARGETS.contains(&key_val[0])
                            && levels::ALL_LEVELS.contains(&key_val[1].to_uppercase().as_str())
                        {
                            task_asm
                                .logging
                                .lock()
                                .unwrap()
                                .insert(key_val[0].to_string(), key_val[1].to_uppercase());
                            applied.push(elem.to_string());
                        } else {
                            ignored.push(elem.to_string());
                        }
                    }
                    _ => {
                        ignored.push(elem.to_string());
                    }
                }
            }
            logging::reload_filter(&task_asm.reload_handle, &task_asm.logging.lock().unwrap());

            let mut results_builder = results.get().init_result();
            if applied.len() > 0 {
                let _ = results_builder.set_applied(applied.as_slice());
            }
            if ignored.len() > 0 {
                let _ = results_builder.set_ignored(ignored.as_slice());
            }

            Ok(())
        })
    }
}

// This code will eventually be removed and the logic moved into perf_sample above
/// Performs a performance sample on the PH by measuring the queue depths and the
/// packet latencies throughout the system. Requires the duration of the
/// sample as well as the number of samples per second.
async fn perf_sample(_asm: &Assembly, _duration: &str, _rate: &str) -> String {
    // FIXME: There are now a dynamically allocated number of mgmt_processors...
    // this needs to be restructured to account for that fact.
    Default::default()

    /*let send_duration = Duration::new(duration.parse().unwrap(), 0);
    let begin_time = Instant::now();
    let mut send_interval = interval(Duration::new(0, 1000000000 / rate.parse::<u32>().unwrap()));

    let mut mgmt_processor_duration = Histogram::<u64>::new(1).unwrap();
    let mut mgmt_processor_depth = Histogram::<u64>::new(1).unwrap();
    let mut mgmt_processor_batch = Histogram::<u64>::new(1).unwrap();

    send_interval.tick().await;

    // Enqueue test packets at the frequency desired by the user for the
    // desired amount of time
    while begin_time.elapsed().as_secs() < send_duration.as_secs() {
        let in_processor = asm.mgmt_processor.enqueue_test_packet().await;
        record_metrics(
            in_processor,
            &mut mgmt_processor_duration,
            &mut mgmt_processor_depth,
            &mut mgmt_processor_batch,
        );

        // TODO: record metrics from TUN interface and UDP socket

        send_interval.tick().await;
    }

    // Get values at 10, 25, 50, 75, 90 quantiles for each hist as well as the mean
    let mgmt_processor = three_hists_values(
        "Management Processor",
        &mgmt_processor_duration,
        &mgmt_processor_depth,
        &mgmt_processor_batch,
    );

    format!("{mgmt_processor}")*/
}

/// Helper for perf_sample
/// Records the metrics from a single test packet to the trio of histograms
/// tracking the data from the queue that particular test packet was enqueued on
fn record_metrics(
    metrics: Result<TestPacketMetrics, RecvError>,
    hist_dur: &mut Histogram<u64>,
    hist_dep: &mut Histogram<u64>,
    hist_batch: &mut Histogram<u64>,
) {
    let _ = hist_dur.record(
        metrics
            .as_ref()
            .unwrap()
            .in_queue
            .as_nanos()
            .try_into()
            .unwrap(),
    );
    let _ = hist_dep.record(metrics.as_ref().unwrap().queue_depth.try_into().unwrap());
    let _ = hist_batch.record(metrics.as_ref().unwrap().batch_size.try_into().unwrap());
}

/// Helper for perf_sample
/// Gets the values from the trio of histograms for each queue. Returns a string with the
/// data from all three histograms
fn three_hists_values(
    hist_name: &str,
    hist_dur: &Histogram<u64>,
    hist_dep: &Histogram<u64>,
    hist_batch: &Histogram<u64>,
) -> String {
    let mut info = String::new();

    let _ = write!(
        &mut info,
        "{}",
        values_from_hist(
            &format!("{hist_name} Duration"), // TODO could use en enum and a display to get the name
            "ns",
            hist_dur
        )
        .as_str()
    );
    let _ = write!(
        &mut info,
        "{}",
        values_from_hist(&format!("{hist_name} Depth"), " packets", hist_dep).as_str()
    );
    let _ = write!(
        &mut info,
        "{}",
        values_from_hist(&format!("{hist_name} Batch"), " packets", hist_batch).as_str()
    );
    let mean: u64 = (hist_dur.mean() / (1.0 + hist_dep.mean())) as u64;
    let _ = write!(&mut info, "{hist_name} approx packet time: {mean}ns\n\n\n");

    info
}

/// Helper for three_hists_values
/// Gets the data from a single histogram. Requires the histogram and units of
/// measurement to format the data, as well as the histogram itself.
/// Returns string with the data from one historgram.
fn values_from_hist(hist_name: &str, units: &str, hist: &Histogram<u64>) -> String {
    let ten: u64 = hist.value_at_quantile(0.10);
    let twenty_five: u64 = hist.value_at_quantile(0.25);
    let fifty: u64 = hist.value_at_quantile(0.50);
    let seventy_five: u64 = hist.value_at_quantile(0.75);
    let ninety: u64 = hist.value_at_quantile(0.90);
    let mean: f64 = hist.mean();

    let mut values = format!("{} values at - 10th Quantile: {}{}, 25th Quantile: {}{},\n50th Quantile: {}{}, 75th Quantile: {}{}, 90th Quantile: {}{}, Mean: {}{}\n\n", hist_name, ten, units, twenty_five, units, fifty, units, seventy_five, units, ninety, units, mean, units);

    let mut iter = hist.iter_log(1, SQRT_2);

    let mut iter_value = iter.next();
    let mut prev_bucket = 0;

    while iter_value != None {
        let curr_bucket = iter_value.as_ref().unwrap().value_iterated_to();
        let _ = write!(
            &mut values,
            "Bucket: {}-{} | {}\n",
            prev_bucket,
            curr_bucket,
            iter_value.unwrap().count_since_last_iteration()
        );

        prev_bucket = curr_bucket;
        iter_value = iter.next();
    }

    let _ = write!(&mut values, "\n");

    values
}

// Takes in ancillary data, extracts the file descriptor, and creates a file using the
// fd
async fn set_capture_file(asm: &Assembly, ancillary: SocketAncillary<'_>) -> String {
    // Get the ancillary data
    let anc_message = ancillary.into_messages().nth(0).unwrap();
    // Get the SCM rights from the ancillary data
    if let AncillaryData::ScmRights(mut scm_rights) = anc_message.unwrap() {
        // See if there's actually data in the scm_rights, if yes try to open a
        // capture file, otherwise report failure to open file
        match scm_rights.nth(0) {
            Some(fd) => {
                let std_file = std::fs::File::from(fd.try_into_owned().unwrap()); // tokio::fs::File doesn't implement From<OwnedFd>
                let tokio_file = File::from(std_file);
                match asm.capture_worker.open_capture_file(tokio_file).await {
                    Ok(()) => format!("Capture file opened\n"),
                    Err(err) => format!("Error opening Capture file: {}\n", err),
                }
            }
            None => format!("Error opening Capture file: no ancillary data received\n"),
        }
    } else {
        format!("Error opening Capture file: no ancillary data received\n")
    }
}

// Helper for show_link_summary
fn get_link_summary(asm: &Arc<Assembly>, link_id: LinkId) -> String {
    match asm.peer_table.get(link_id) {
        Some(peer) => format!(
            "{} ({:?})",
            peer.substrate_addr,
            peer.link_state_machine.get_state()
        ),
        None => format!("Unconfigured"),
    }
}
