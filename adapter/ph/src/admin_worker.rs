//! Receives commands, either from the cli or from someone directly interfacing
//! with the socket, performs action based on received command
//! To avoid excess parsing, the command must not have spaces

#![allow(unused_imports)]
#![allow(dead_code)]

use crate::link_state::{LinkEvent, LinkState};
use crate::logging;
use crate::logging::{levels, targets};
use crate::prelude::*;
use crate::test_packet::TestPacketMetrics;
use crate::zdp::TerminateReason;
use admin_api::rpc_commands::RpcCommands;
use admin_api::v1 as cli;
use cbpf_rs;
use cli::cmd_line_inter as svc;
use core::future::Future;
use hdrhistogram::Histogram;
use std::f64::consts::SQRT_2;
use std::fmt::Write;
use std::io::Error;
use std::io::IoSliceMut;
use std::net::IpAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot::error::RecvError;
use tokio::task::JoinSet;
use tokio::time::interval;
use tokio_util::compat::*;
use zpr_ext::std::os::unix::net::{AncillaryData, SocketAncillary};
use zpr_ext::tokio::net::*;

pub async fn launch_capnp(
    asm: Arc<Assembly>,
    listener: UnixListener,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let (sock, _addr) = listener.accept().await?;

        let (reader, writer) = sock.into_split();

        #[cfg(not(feature = "capnp-ancillary"))]
        let network = capnp_rpc::twoparty::VatNetwork::new(
            tokio::io::BufReader::new(reader).compat(),
            tokio::io::BufWriter::new(writer).compat_write(),
            capnp_rpc::rpc_twoparty_capnp::Side::Server,
            capnp::message::ReaderOptions::new(),
        );

        //use an FD-passing transport instead of a plain byte stream.
        #[cfg(feature = "capnp-ancillary")]
        let network = capnp_rpc::twoparty::io::VatNetwork::new_with_fds(
            capnp_futures::io::tokio::UnixFdStream::new(reader),
            capnp_futures::io::tokio::UnixFdStream::new(writer),
            1,
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
        Ok(()) => (),
        Err(e) => error!(target: RPC, "RPC System error: {}", e),
    };
}

struct AdminServiceImpl {
    asm: Arc<Assembly>,
}

impl svc::Server for AdminServiceImpl {
    async fn echo(
        self: Rc<Self>,
        _: svc::EchoParams,
        _: svc::EchoResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: RPC, "Echo procedure initiated");

        Ok(())
    }

    async fn reset_counters(
        self: Rc<Self>,
        _: svc::ResetCountersParams,
        _: svc::ResetCountersResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Reset counters procedure initiated");
        for value in self.asm.counters.management.values() {
            value.reset();
        }

        for fastpath in self.asm.counters.fastpaths.lock().unwrap().iter() {
            for value in fastpath.values() {
                value.reset();
            }
        }

        Ok(())
    }

    async fn counters(
        self: Rc<Self>,
        _: svc::CountersParams,
        mut results: svc::CountersResults,
    ) -> Result<(), capnp::Error> {
        debug!(target: RPC, "Counters procedure initiated");
        let mut results_builder = results.get().init_counts();

        let mut counters_builder = results_builder
            .reborrow()
            .init_management()
            .init_counters(self.asm.counters.management.len() as u32);

        for (i, (key, &ref value)) in self.asm.counters.management.iter().enumerate() {
            let mut counter = counters_builder.reborrow().get(i as u32);
            counter.set_name(key.name());
            counter.set_val(value.get_count());
        }

        {
            let fastpaths = self.asm.counters.fastpaths.lock().unwrap();

            // Initialize builder for list of fastpaths
            let mut fastpaths_builder = results_builder
                .reborrow()
                .init_fastpaths(fastpaths.len() as u32);
            for (i, fastpath) in fastpaths.iter().enumerate() {
                // Initialize builder for individual fastpath and set its ID
                let mut fastpath_builder = fastpaths_builder.reborrow().get(i as u32);
                fastpath_builder.set_id(i as u32);

                // Set counters
                let mut counters_builder = fastpath_builder.init_counters(fastpath.len() as u32);
                for (i, (key, &ref value)) in fastpath.iter().enumerate() {
                    let mut counter = counters_builder.reborrow().get(i as u32);
                    counter.set_name(key.name());
                    counter.set_val(value.get_count());
                }
            }
        }

        results_builder.set_uptime_sec(self.asm.get_uptime().as_secs());
        results_builder.set_uptime_subsec_ms(self.asm.get_uptime().subsec_millis());

        Ok(())
    }

    #[cfg(not(feature = "capnp-ancillary"))]
    async fn set_capture_file(
        self: Rc<Self>,
        _: svc::SetCaptureFileParams,
        _: svc::SetCaptureFileResults,
    ) -> Result<(), capnp::Error> {
        Err(capnp::Error::unimplemented(
            "method cmd_line_inter::Server::set_capture_file not implemented".to_string(),
        ))
    }

    /// Opens the capture file from an FD received as ancillary data.
    #[cfg(feature = "capnp-ancillary")]
    async fn set_capture_file(
        self: Rc<Self>,
        params: svc::SetCaptureFileParams,
        mut results: svc::SetCaptureFileResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Set capture file procedure initiated");
        let capture_file = params.get()?.get_capture_file()?;
        let fd = capture_file.client.get_fd().await?;
        let results_builder = results.get().init_result();

        match fd {
            Some(fd) => {
                let owned_fd = fd.try_clone_to_owned().map_err(|e| {
                    capnp::Error::failed(format!("failed to clone capture file fd: {e}"))
                })?;
                let file = File::from(std::fs::File::from(owned_fd));
                match self.asm.capture_worker.open_capture_file(file).await {
                    Ok(()) => {
                        debug!(target: RPC, "Capture file opened");
                        results_builder.init_success().set_none(());
                    }
                    Err(err) => {
                        debug!(target: RPC, "Error opening capture file: {err}");
                        results_builder
                            .init_error()
                            .set_txt(format!("Error opening capture file: {err}").as_str());
                    }
                }
            }
            None => {
                debug!(target: RPC, "Error opening capture file: no file descriptor received");
                results_builder
                    .init_error()
                    .set_txt("Error opening capture file: no file descriptor received");
            }
        }

        Ok(())
    }

    async fn close_capture_file(
        self: Rc<Self>,
        _: svc::CloseCaptureFileParams,
        _: svc::CloseCaptureFileResults,
    ) -> Result<(), capnp::Error> {
        let _ = self.asm.capture_worker.close_capture_file().await;
        self.asm.flow_control.delete_program();

        Ok(())
    }

    async fn flush_capture_file(
        self: Rc<Self>,
        _: svc::FlushCaptureFileParams,
        _: svc::FlushCaptureFileResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Flush capture file procedure initiated");
        let _ = self.asm.capture_worker.flush_capture_file().await;

        Ok(())
    }

    async fn set_capture_program(
        self: Rc<Self>,
        params: svc::SetCaptureProgramParams,
        mut results: svc::SetCaptureProgramResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Set capture program procedure initiated");
        let programs = params.get()?.get_program()?.get_bpf_prog()?;

        let mut insn_vec = Vec::new();

        for program in programs.iter() {
            debug!(
                target: RPC,
                "Capture program values: code: {}, jt: {}, jf: {}, k: {}",
                program.get_code(),
                program.get_jt(),
                program.get_jf(),
                program.get_k()
            );
            let bpf_insn = cbpf_rs::BpfInsn {
                code: program.get_code(),
                jt: program.get_jt(),
                jf: program.get_jf(),
                k: program.get_k(),
            };
            insn_vec.push(bpf_insn);
        }

        let results_builder = results.get().init_result();

        match cbpf_rs::BpfProgram::validate(&insn_vec) {
            Ok(final_program) => {
                self.asm.flow_control.set_program(final_program);
                let mut success_builder = results_builder.init_success();
                success_builder.set_none(());
            }
            _ => {
                let mut error_builder = results_builder.init_error();
                error_builder.set_txt("Invalid program")
            }
        }

        Ok(())
    }

    async fn delete_capture_program(
        self: Rc<Self>,
        _: svc::DeleteCaptureProgramParams,
        _: svc::DeleteCaptureProgramResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Delete capture program procedure initiated");
        self.asm.flow_control.delete_program();
        Ok(())
    }

    async fn perf_sample(
        self: Rc<Self>,
        _: svc::PerfSampleParams,
        mut results: svc::PerfSampleResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Perf sample procedure initiated");
        let mut results_builder = results.get();
        results_builder.set_result("Not currently supported");
        Ok(())
    }

    async fn show_link_summary(
        self: Rc<Self>,
        _: svc::ShowLinkSummaryParams,
        mut results: svc::ShowLinkSummaryResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Show link summary procedure initiated");
        {
            let mut peer_ids = Vec::new();
            self.asm.peer_table.for_each(|(id, peer)| {
                if !peer.is_internal() {
                    peer_ids.push(id.get())
                }
            });

            let mut results_builder = results.get().init_summary(peer_ids.len() as u32);

            for (i, id) in peer_ids.iter().enumerate() {
                results_builder.set(
                    i as u32,
                    format!("  {id}: {}", get_link_summary(&self.asm, *id)),
                );
            }
        }

        Ok(())
    }

    async fn show_link(
        self: Rc<Self>,
        params: svc::ShowLinkParams,
        mut results: svc::ShowLinkResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Show link procedure initiated");
        let id = params.get()?.get_id();
        debug!(target: RPC, "Show {} requested", self.asm.formatted_link_id(id));

        let mut results_builder = results.get();
        let response = match self.asm.peer_table.get(id) {
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
    }

    async fn configure_link(
        self: Rc<Self>,
        _: svc::ConfigureLinkParams,
        _: svc::ConfigureLinkResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Configure link procedure initiated");
        Ok(())
    }

    async fn start_link(
        self: Rc<Self>,
        params: svc::StartLinkParams,
        mut results: svc::StartLinkResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Start link procedure initiated");
        let id = params.get()?.get_id();
        debug!(target: RPC, "Start {} requested", self.asm.formatted_link_id(id));

        let results_builder = results.get().init_result();

        match self.asm.process_link_state_event(id, LinkEvent::Start) {
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
    }

    async fn stop_link(
        self: Rc<Self>,
        params: svc::StopLinkParams,
        mut results: svc::StopLinkResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Stop link procedure initiated");
        let task_asm = self.asm.clone();
        let id = params.get()?.get_id();
        debug!(target: RPC, "Stop {} requested", self.asm.formatted_link_id(id));

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
    }

    async fn reset_link(
        self: Rc<Self>,
        params: svc::ResetLinkParams,
        _: svc::ResetLinkResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Reset link procedure initiated");
        let id = params.get()?.get_id();
        debug!(target: RPC, "Reset {} requested", self.asm.formatted_link_id(id));

        self.asm.reset_peer(id).await;
        Ok(())
    }

    async fn change_logging(
        self: Rc<Self>,
        params: svc::ChangeLoggingParams,
        mut results: svc::ChangeLoggingResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Change logging procedure initiated");
        let task_asm = self.asm.clone();
        let log_state = params.get()?.get_logs()?;
        // let log_vec: Vec<&str> = log_state.split_whitespace().collect();
        let mut applied: Vec<String> = Vec::new();
        let mut ignored: Vec<String> = Vec::new();
        for log in log_state.iter() {
            let target = log.get_level()?.to_str()?;
            let level = log.get_target()?.to_str()?;
            if targets::ALL_TARGETS.contains(&target)
                && levels::ALL_LEVELS.contains(&level.to_uppercase().as_str())
            {
                task_asm
                    .logging
                    .lock()
                    .unwrap()
                    .insert(target.to_string(), level.to_uppercase());
                applied.push(format!("{}={}", target, level));
                debug!(target: RPC, "Logging pair: {target}={level} applied");
            } else {
                ignored.push(format!("{}={}", target, level));
                debug!(target: RPC, "Logging pair: {target}={level} ignored");
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
    }

    async fn get_node_info(
        self: Rc<Self>,
        _: svc::GetNodeInfoParams,
        mut results: svc::GetNodeInfoResults,
    ) -> Result<(), capnp::Error> {
        info!(target: RPC, "Get node info from adapter");
        let task_asm = self.asm.clone();

        let mut results_builder = results.get().init_result();

        if let PhMode::Node = task_asm.ph_mode {
            let resp = format!("Not in adapter mode");
            let mut error_builder = results_builder.reborrow().init_error();
            error_builder.set_txt(resp);
            return Ok(());
        }

        match task_asm.peer_table.get(DOCK_LINK_ID) {
            Some(pt) => {
                let substrate_addr = pt.substrate_addr;
                let success_builder = results_builder.init_success();
                let mut sock_addr_builder = success_builder.init_sock_addr();

                sock_addr_builder.set_port(substrate_addr.port());
                let mut addr_builder = sock_addr_builder.init_addr();

                match substrate_addr.ip() {
                    IpAddr::V4(addr) => {
                        addr_builder.set_v4(&addr.octets());
                    }
                    IpAddr::V6(addr) => {
                        addr_builder.set_v6(&addr.octets());
                    }
                }
            }
            None => {
                let resp = format!("No node found");
                let mut error_builder = results_builder.init_error();
                error_builder.set_txt(resp);
            }
        }

        Ok(())
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

    let mut values = format!(
        "{} values at - 10th Quantile: {}{}, 25th Quantile: {}{},\n50th Quantile: {}{}, 75th Quantile: {}{}, 90th Quantile: {}{}, Mean: {}{}\n\n",
        hist_name,
        ten,
        units,
        twenty_five,
        units,
        fifty,
        units,
        seventy_five,
        units,
        ninety,
        units,
        mean,
        units
    );

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
    info!(target: RPC, "Setting capture file");
    // Get the ancillary data
    let anc_message = ancillary.into_messages().nth(0).unwrap();
    // Get the SCM rights from the ancillary data
    if let AncillaryData::ScmRights(mut scm_rights) = anc_message.unwrap() {
        debug!(target: RPC, "SCM Rights exist");
        // See if there's actually data in the scm_rights, if yes try to open a
        // capture file, otherwise report failure to open file
        match scm_rights.nth(0) {
            Some(fd) => {
                let std_file = std::fs::File::from(fd.try_into_owned().unwrap()); // tokio::fs::File doesn't implement From<OwnedFd>
                let tokio_file = File::from(std_file);
                match asm.capture_worker.open_capture_file(tokio_file).await {
                    Ok(()) => {
                        debug!(target: RPC, "Capture file opened");
                        format!("Capture file opened\n")
                    }
                    Err(err) => {
                        debug!(target: RPC, "Error opening Capture file: {}\n", err);
                        format!("Error opening Capture file: {}\n", err)
                    }
                }
            }
            None => {
                debug!(target: RPC, "Error opening Capture file: no ancillary data received\n");
                format!("Error opening Capture file: no ancillary data received\n")
            }
        }
    } else {
        debug!(target: RPC, "Error opening Capture file: no ancillary data received\n");
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
