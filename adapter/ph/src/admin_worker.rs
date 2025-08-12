//! Receives commands, either from the cli or from someone directly interfacing
//! with the socket, performs action based on received command
//! To avoid excess parsing, the command must not have spaces

#![allow(unused_imports)]
#![allow(dead_code)]

use crate::assembly::Assembly;
use crate::config;
use crate::link_state::{LinkEvent, LinkState};
use crate::logging::targets::RPC;
use crate::test_packet::TestPacketMetrics;
use crate::zdp::TerminateReason;
use cbpf_rs;
use core::future::Future;
use hdrhistogram::Histogram;
use std::f64::consts::SQRT_2;
use std::fmt::Write;
use std::io::Error;
use std::io::IoSliceMut;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot::error::RecvError;
use tokio::task::JoinSet;
use tokio::time::interval;
use tracing::error;
use zpr::rpc_commands::RpcCommands;
use zpr::LinkId;
use zpr_ext::std::os::unix::net::{AncillaryData, SocketAncillary};
use zpr_ext::tokio::net::*;

pub async fn launch(asm: Arc<Assembly>, socket: Arc<UnixListener>) {
    let mut set = JoinSet::<Result<(), Error>>::new();

    // Continuously looks for a connection to the socket, allows for concurrent connections
    loop {
        tokio::select! {
            // Collecting state of completed task ensures that return code doesn't
            // just sit in JoinSet forever
            Some(ret) = set.join_next() =>
                match ret {
                    Ok(Ok(())) => (),
                    Ok(Err(err)) => error!(target: RPC, "Handle Connection Failed: {err}"),
                    Err(err) => error!(target: RPC, "join_next panicked: {err}")
                },
            accepted = socket.accept() =>
                match accepted {
                    Ok((stream, _addr)) => {
                        set.spawn_local(handle_connection(asm.clone(), stream));
                    },
                    Err(_e) => {
                        error!(target: RPC, "Connection failed");
                    }
            }
        }
    }
}

async fn handle_connection(asm: Arc<Assembly>, mut stream: UnixStream) -> std::io::Result<()> {
    let mut str_message = String::new();

    let split_buf = stream.split(); // split stream into read/write streams
    let mut buf_reader = BufReader::new(split_buf.0);
    let mut buf_writer = BufWriter::new(split_buf.1);
    buf_reader.read_line(&mut str_message).await?;

    let last_let = str_message.pop(); // Removes \n from end of string
    if last_let != Some('\n') {
        // close stream then skip the rest of the loop and moves to next iteration
        buf_writer.shutdown().await?;
    } else {
        buf_writer.write("Message Received\n".as_bytes()).await?;

        // Separate command from any other information associated with the command
        let vec_message: Vec<&str> = str_message.split_whitespace().collect();
        match RpcCommands::from_str(vec_message[0]) {
            Ok(RpcCommands::CountersReset) => {
                buf_writer
                    .write_all(counters_reset(&asm).await.as_bytes())
                    .await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            Ok(RpcCommands::Counters) => {
                buf_writer
                    .write_all(counters(&asm).await.as_bytes())
                    .await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            Ok(RpcCommands::Echo) => {
                buf_writer.write_all(echo(&asm).await.as_bytes()).await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            // PERF SAMPLE <DURATION> <FREQUENCY>
            Ok(RpcCommands::PerfSample) => match vec_message.len() {
                3 => {
                    buf_writer
                        .write_all(
                            perf_sample(&asm, vec_message[1], vec_message[2])
                                .await
                                .as_bytes(),
                        )
                        .await?;
                    buf_writer.write_all("OK\n".as_bytes()).await?
                }
                _ => buf_writer.write_all("ERR\n".as_bytes()).await?,
            },
            // SET-CAPTURE-FILE <file_path>
            Ok(RpcCommands::SetCaptureFile) => {
                // Tell debug tool we're ready for the ancillary data
                buf_writer.write_all("SEND ANCILLARY\n".as_bytes()).await?;
                buf_writer.flush().await?;

                // Receive ancillary data
                let mut ancillary_buffer = [0; config::ANCILLARY_BUFFER_SIZE];
                let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);
                let mut buf = [0; 1]; // Must receive data sent with ancillary data
                let bufs = &mut [IoSliceMut::new(&mut buf)][..];
                buf_reader
                    .into_inner()
                    .as_ref()
                    .recv_vectored_with_ancillary(bufs, &mut ancillary)
                    .await?;

                // Set capture file using ancillary data
                buf_writer
                    .write_all(set_capture_file(&asm, ancillary).await.as_bytes())
                    .await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            Ok(RpcCommands::FlushCaptureFile) => {
                buf_writer
                    .write_all(flush_capture_file(&asm).await.as_bytes())
                    .await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            Ok(RpcCommands::CloseCaptureFile) => {
                buf_writer
                    .write_all(close_capture_file(&asm).await.as_bytes())
                    .await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            // SET-CAPTURE-PROGRAM <program>
            Ok(RpcCommands::SetCaptureProgram) => {
                buf_writer
                    .write_all(set_capture_program(&asm, str_message).as_bytes())
                    .await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            Ok(RpcCommands::DeleteCaptureProgram) => {
                buf_writer
                    .write_all(delete_capture_program(&asm).as_bytes())
                    .await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            Ok(RpcCommands::ShowLink) => match vec_message.len() {
                1 => {
                    buf_writer
                        .write_all(show_link_summary(&asm.clone()).as_bytes())
                        .await?;
                    buf_writer.write_all("OK\n".as_bytes()).await?
                }
                2 => match vec_message[1].parse::<u32>() {
                    Ok(link_id) => {
                        buf_writer
                            .write_all(show_link(&asm.clone(), link_id).as_bytes())
                            .await?;
                        buf_writer.write_all("OK\n".as_bytes()).await?
                    }
                    Err(_) => buf_writer.write_all("ERR\n".as_bytes()).await?,
                },
                _ => buf_writer.write_all("ERR\n".as_bytes()).await?,
            },
            Ok(RpcCommands::ConfigureLink) => match vec_message.len() {
                2 => match vec_message[1].parse::<u32>() {
                    Ok(link_id) => {
                        buf_writer
                            .write_all(configure_link(&asm.clone(), link_id).as_bytes())
                            .await?;
                        buf_writer.write_all("OK\n".as_bytes()).await?
                    }
                    Err(_) => buf_writer.write_all("ERR\n".as_bytes()).await?,
                },
                _ => buf_writer.write_all("ERR\n".as_bytes()).await?,
            },
            Ok(RpcCommands::StartLink) => match vec_message.len() {
                2 => match vec_message[1].parse::<u32>() {
                    Ok(link_id) => {
                        buf_writer
                            .write_all(start_link(&asm.clone(), link_id).as_bytes())
                            .await?;
                        buf_writer.write_all("OK\n".as_bytes()).await?
                    }
                    Err(_) => buf_writer.write_all("ERR\n".as_bytes()).await?,
                },
                _ => buf_writer.write_all("ERR\n".as_bytes()).await?,
            },
            Ok(RpcCommands::StopLink) => match vec_message.len() {
                2 => match vec_message[1].parse::<u32>() {
                    Ok(link_id) => {
                        buf_writer
                            .write_all(stop_link(&asm.clone(), link_id).as_bytes())
                            .await?;
                        buf_writer.write_all("OK\n".as_bytes()).await?
                    }
                    Err(_) => buf_writer.write_all("ERR\n".as_bytes()).await?,
                },
                _ => buf_writer.write_all("ERR\n".as_bytes()).await?,
            },
            Ok(RpcCommands::ResetLink) => match vec_message.len() {
                2 => match vec_message[1].parse::<u32>() {
                    Ok(link_id) => {
                        buf_writer
                            .write_all(reset_link(&asm.clone(), link_id).await.as_bytes())
                            .await?;
                        buf_writer.write_all("OK\n".as_bytes()).await?
                    }
                    Err(_) => buf_writer.write_all("ERR\n".as_bytes()).await?,
                },
                _ => buf_writer.write_all("ERR\n".as_bytes()).await?,
            },
            _ => buf_writer.write_all("ERR\n".as_bytes()).await?,
        };

        buf_writer.flush().await?;
        buf_writer.shutdown().await?;
    }

    Ok(())
}

// Management functions for RPC worker, along with helper functions for the
// management funcs

async fn echo(_asm: &Assembly) -> String {
    String::from("echo\n")
}

async fn counters(asm: &Assembly) -> String {
    let mut counts: String = String::new();
    let _ = write!(&mut counts, "Management counts:\n");
    for (key, &ref value) in &asm.counters.management {
        let _ = write!(&mut counts, "{}: {}\n", key, value.get_count());
    }

    for (i, fastpath) in asm.counters.fastpaths.lock().unwrap().iter().enumerate() {
        let _ = write!(&mut counts, "Fastpath #{} counts:\n", i);
        for (key, &ref value) in fastpath {
            let _ = write!(&mut counts, "{}: {}\n", key, value.get_count());
        }
    }

    let _ = write!(&mut counts, "Uptime: {:?}\n", asm.get_uptime());

    counts
}

async fn counters_reset(asm: &Assembly) -> String {
    for value in asm.counters.management.values() {
        value.reset();
    }
    
    for fastpath in asm.counters.fastpaths.lock().unwrap().iter() {
        for value in fastpath.values() {
            value.reset();
        }
    }

    String::from("counters_reset\n")
}

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

async fn flush_capture_file(asm: &Assembly) -> String {
    let _ = asm.capture_worker.flush_capture_file().await;

    String::from("Capture file flushed\n")
}

async fn close_capture_file(asm: &Assembly) -> String {
    let _ = asm.capture_worker.close_capture_file().await;
    asm.flow_control.delete_program();

    String::from("Capture file closed and capture program deleted\n")
}

/// Expects the entire string message sent to RPC worker, including the command
fn set_capture_program(asm: &Assembly, str_message: String) -> String {
    // Removes the command from the beginning of the str
    let (_command, program) = str_message.split_once(' ').unwrap();
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

    let mut return_message = format!("Program: {program} set\n");
    match cbpf_rs::BpfProgram::validate(&insn_vec) {
        Ok(final_program) => asm.flow_control.set_program(final_program),
        _ => return_message = format!("Invalid program received, program not set\n"),
    }

    return_message
}

fn delete_capture_program(asm: &Assembly) -> String {
    asm.flow_control.delete_program();

    String::from("Program deleted\n")
}

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

fn show_link_summary(asm: &Arc<Assembly>) -> String {
    let mut links: String = String::new();
    let _ = write!(&mut links, "Link summary:\n");

    for id in asm.peer_ids.lock().unwrap().clone() {
        let _ = write!(&mut links, "  {id}: {}\n", get_link_summary(asm, id));
    }

    links
}

fn show_link(asm: &Arc<Assembly>, link_id: LinkId) -> String {
    match asm.peer_table.get(link_id) {
        Some(peer) => {
            let lsm = &peer.link_state_machine;

            format!(
                "Link {link_id} info:
  Substrate Address: {}\n{}",
                peer.substrate_addr, lsm,
            )
        }
        None => format!("No such link {link_id}\n"),
    }
}

fn configure_link(_asm: &Arc<Assembly>, _link_id: LinkId) -> String {
    format!("Command currently unsupported\n")
}

fn start_link(asm: &Arc<Assembly>, link_id: LinkId) -> String {
    match asm.process_link_state_event(link_id, LinkEvent::Start) {
        Ok(_) => format!("Link {} started\n", link_id),
        Err(e) => format!("Failed to start link {}: {:?}\n", link_id, e),
    }
}

fn stop_link(asm: &Arc<Assembly>, link_id: LinkId) -> String {
    match asm.process_link_state_event(link_id, LinkEvent::Close(TerminateReason::Other)) {
        Ok(_) => format!("Link {} stopped\n", link_id),
        Err(e) => format!("Failed to stop link {}: {:?}\n", link_id, e),
    }
}

async fn reset_link(asm: &Arc<Assembly>, link_id: LinkId) -> String {
    asm.reset_peer(link_id).await;
    format!("Link {} reset\n", link_id)
}
