//! Receives commands, either from ph-debug tool or from someone directly interfacing
//! with the socket, performs action based on received command
//! To avoid excess parsing, the command must not have spaces

use crate::assembly::Assembly;
use crate::config;
use crate::test_packet::TestPacketMetrics;
use cbpf_rs;
use core::future::Future;
use hdrhistogram::Histogram;
use std::f64::consts::SQRT_2;
use std::fmt::Write;
use std::io::Error;
use std::io::IoSliceMut;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::oneshot::error::RecvError;
use tokio::task::JoinSet;
use tokio::time::interval;
use zpr_ext::std::os::unix::net::{AncillaryData, SocketAncillary};
use zpr_ext::tokio::net::*;

async fn worker(asm: &'static Assembly<'static>, socket: &UnixListener) {
    let mut set = JoinSet::<Result<(), Error>>::new();

    // Continuously looks for a connection to the socket, allows for concurrent connections
    loop {
        tokio::select! {
            // Collecting state of completed task ensures that return code doesn't
            // just sit in JoinSet forever
            Some(ret) = set.join_next() =>
                match ret {
                    Ok(Ok(())) => (),
                    Ok(Err(err)) => eprintln!("Handle Connection Failed: {err}"),
                    Err(err) => eprintln!("join_next panicked: {err}")
                },
            accepted = socket.accept() =>
                match accepted {
                    Ok((stream, _addr)) => {
                        set.spawn(handle_connection(asm, stream));
                    },
                    Err(_e) => {
                        eprintln!("Connection failed");
                    }
            }
        }
    }
}

async fn handle_connection(
    asm: &'static Assembly<'static>,
    mut stream: UnixStream,
) -> std::io::Result<()> {
    eprintln!("Connection received");

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
        match vec_message[0] {
            "COUNTERS-RESET" => {
                buf_writer
                    .write_all(counters_reset(asm).await.as_bytes())
                    .await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            "COUNTERS" => {
                buf_writer.write_all(counters(asm).await.as_bytes()).await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            "ECHO" => {
                buf_writer.write_all(echo(asm).await.as_bytes()).await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            // PERF SAMPLE <DURATION> <FREQUENCY>
            "PERF-SAMPLE" => match vec_message.len() {
                3 => {
                    buf_writer
                        .write_all(
                            perf_sample(asm, vec_message[1], vec_message[2])
                                .await
                                .as_bytes(),
                        )
                        .await?;
                    buf_writer.write_all("OK\n".as_bytes()).await?
                }
                _ => buf_writer.write_all("ERR\n".as_bytes()).await?,
            },
            // SET-CAPTURE-FILE <file_path>
            "SET-CAPTURE-FILE" => {
                // Tell debug tool we're ready for the ancillary data
                buf_writer.write_all("SEND ANCILLARY\n".as_bytes()).await?;
                buf_writer.flush().await?;

                // Receive ancillary data
                let mut ancillary_buffer = [0; config::ANCILLARY_BUFFER_SIZE];
                let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);
                let mut buf = [0; 1]; // Must receive data sent with ancillary data
                let bufs = &mut [IoSliceMut::new(&mut buf)][..];
                unix_stream_recv_vectored_with_ancillary(
                    buf_reader.into_inner().as_ref(),
                    bufs,
                    &mut ancillary,
                )
                .await?;

                // Set capture file using ancillary data
                buf_writer
                    .write_all(set_capture_file(asm, ancillary).await.as_bytes())
                    .await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            "FLUSH-CAPTURE-FILE" => {
                buf_writer
                    .write_all(flush_capture_file(asm).await.as_bytes())
                    .await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            "CLOSE-CAPTURE-FILE" => {
                buf_writer
                    .write_all(close_capture_file(asm).await.as_bytes())
                    .await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            // SET-CAPTURE-PROGRAM <program>
            "SET-CAPTURE-PROGRAM" => {
                buf_writer
                    .write_all(set_capture_program(asm, str_message).as_bytes())
                    .await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            "DELETE-CAPTURE-PROGRAM" => {
                buf_writer
                    .write_all(delete_capture_program(asm).as_bytes())
                    .await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            }
            _ => buf_writer.write_all("ERR\n".as_bytes()).await?,
        };

        buf_writer.flush().await?;
        buf_writer.shutdown().await?;
    }

    Ok(())
}

pub fn launch<'pktbuf, UnixListenerRef: 'pktbuf>(
    asm: &'static Assembly<'static>,
    socket: UnixListenerRef,
) -> impl Future<Output = ()> + Send + 'pktbuf
where
    UnixListenerRef: std::ops::Deref<Target = UnixListener> + Send + Sync,
{
    async move { worker(&*asm, &*socket).await }
}

// Management functions for RPC worker, along with helper functions for the
// management funcs

async fn echo(_asm: &Assembly<'_>) -> String {
    String::from("echo\n")
}

async fn counters(asm: &Assembly<'_>) -> String {
    let mut counts: String = String::new();
    for (key, &ref value) in &asm.counters {
        let _ = write!(&mut counts, "{}: {}\n", key, value.get_count());
    }

    counts
}

async fn counters_reset(asm: &Assembly<'_>) -> String {
    for value in asm.counters.values() {
        value.reset();
    }

    String::from("counters_reset\n")
}

/// Performs a performance sample on the PH by measuring the queue depths and the
/// packet latencies throughout the system. Requires the duration of the
/// sample as well as the number of samples per second.
async fn perf_sample(asm: &Assembly<'_>, duration: &str, rate: &str) -> String {
    let send_duration = Duration::new(duration.parse().unwrap(), 0);
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

    format!("{mgmt_processor}")
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

async fn set_capture_file(asm: &Assembly<'_>, ancillary: SocketAncillary<'_>) -> String {
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

async fn flush_capture_file(asm: &Assembly<'_>) -> String {
    let _ = asm.capture_worker.flush_capture_file().await;

    String::from("Capture file flushed\n")
}

async fn close_capture_file(asm: &Assembly<'_>) -> String {
    let _ = asm.capture_worker.close_capture_file().await;
    asm.flow_control.delete_program();

    String::from("Capture file closed and capture program deleted\n")
}

/// Expects the entire string message sent to RPC worker, including the command
fn set_capture_program(asm: &Assembly<'_>, str_message: String) -> String {
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

fn delete_capture_program(asm: &Assembly<'_>) -> String {
    asm.flow_control.delete_program();

    String::from("Program deleted\n")
}
