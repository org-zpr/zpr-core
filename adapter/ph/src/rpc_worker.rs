use crate::assembly::Assembly;
use core::future::Future;
use hdrhistogram::Histogram;
use std::fmt::Write;
use std::io::Error;
use std::time::{Duration, Instant};
use tokio::io::AsyncBufReadExt;
use tokio::io::AsyncWriteExt;
use tokio::io::BufReader;
use tokio::io::BufWriter;
use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tokio::task::JoinSet;
use tokio::time::interval;

async fn worker(asm: &'static Assembly<'static>, socket: &UnixListener) {
    let mut set = JoinSet::<Result<(), Error>>::new();

    loop {
        tokio::select! {
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
    eprintln!("Connection recieved");
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
        // TODO remove \n from end of message?
        buf_writer.write("Message Received\n".as_bytes()).await?;

        let vec_message: Vec<&str> = str_message.split_whitespace().collect();

        // TODO there must be a more efficient way to send the OK message, is match statement best suited?
        match vec_message[0] {
            // changed to single word to allow for use of split by space, avoids unnecessary
            // parsing when command is not PERF-SAMPLE
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
            "PERF-SAMPLE" => {
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

async fn echo(_asm: &Assembly<'_>) -> String {
    "echo\n".to_string()
}

// TODO not sure if just printing is what we want this function to do
async fn counters(asm: &Assembly<'_>) -> String {
    let mut counts: String = "".to_string();
    for (key, &ref value) in &asm.counters {
        let _ = write!(&mut counts, "{}: {}\n", key, value.get_count());
    }

    counts
}

async fn counters_reset(asm: &Assembly<'_>) -> String {
    for value in asm.counters.values() {
        value.reset();
    }

    "counters_reset\n".to_string()
}

async fn perf_sample(asm: &Assembly<'_>, duration: &str, rate: &str) -> String {
    let send_duration = Duration::new(duration.parse().unwrap(), 0);
    let begin_time = Instant::now();
    let mut send_interval = interval(Duration::new(0, 1000000000 / rate.parse::<u32>().unwrap()));

    let mut inbound_processor_duration = Histogram::<u64>::new(1).unwrap();
    let mut inbound_processor_depth = Histogram::<u64>::new(1).unwrap();
    let mut inbound_send_duration = Histogram::<u64>::new(1).unwrap();
    let mut inbound_send_depth = Histogram::<u64>::new(1).unwrap();
    let mut outbound_processor_duration = Histogram::<u64>::new(1).unwrap();
    let mut outbound_processor_depth = Histogram::<u64>::new(1).unwrap();
    let mut outbound_send_duration = Histogram::<u64>::new(1).unwrap();
    let mut outbound_send_depth = Histogram::<u64>::new(1).unwrap();

    send_interval.tick().await;
    let mut queue_num = 0;
    while begin_time.elapsed().as_secs() < send_duration.as_secs() {
        if queue_num == (asm.inbound_send.fanout()) {
            queue_num = 0;
        }

        let in_processor = asm.inbound_processor.enqueue_test_packet().await;
        let _ = inbound_processor_duration.record(
            in_processor
                .as_ref()
                .unwrap()
                .in_queue
                .as_nanos()
                .try_into()
                .unwrap(),
        );
        let _ = inbound_processor_depth.record(
            in_processor
                .as_ref()
                .unwrap()
                .queue_depth
                .try_into()
                .unwrap(),
        );

        let in_send = asm.inbound_send.enqueue_test_packet(queue_num).await;
        let _ = inbound_send_duration.record(
            in_send
                .as_ref()
                .unwrap()
                .in_queue
                .as_nanos()
                .try_into()
                .unwrap(),
        );
        let _ =
            inbound_send_depth.record(in_send.as_ref().unwrap().queue_depth.try_into().unwrap());

        let out_processor = asm.outbound_processor.enqueue_test_packet().await;
        let _ = outbound_processor_duration.record(
            out_processor
                .as_ref()
                .unwrap()
                .in_queue
                .as_nanos()
                .try_into()
                .unwrap(),
        );
        let _ =
            outbound_processor_depth.record(out_processor.unwrap().queue_depth.try_into().unwrap());

        let out_send = asm.outbound_send.enqueue_test_packet().await;
        let _ = outbound_send_duration.record(
            out_send
                .as_ref()
                .unwrap()
                .in_queue
                .as_nanos()
                .try_into()
                .unwrap(),
        );
        let _ = outbound_send_depth.record(out_send.unwrap().queue_depth.try_into().unwrap());

        send_interval.tick().await;
        queue_num += 1;
    }

    // get values at 10, 25, 50, 75, 90 quantiles for each hist
    let mut info: String = "".to_string();

    // Get info for inbound processor
    let _ = write!(
        &mut info,
        "{}",
        values_from_hist(
            "Inbound Processor Duration",
            "ns",
            inbound_processor_duration.clone()
        )
        .as_str()
    );
    let _ = write!(
        &mut info,
        "{}",
        values_from_hist(
            "Inbound Processor Depth",
            " packets",
            inbound_processor_depth.clone()
        )
        .as_str()
    );
    let inbound_pro_mean: u64 =
        (inbound_processor_duration.mean() / (1.0 + inbound_processor_depth.mean())) as u64;
    let _ = write!(&mut info, "Approx packet time: {inbound_pro_mean}ns\n\n\n");

    // Get info for inbound send
    let _ = write!(
        &mut info,
        "{}",
        values_from_hist("Inbound Send Duration", "ns", inbound_send_duration.clone()).as_str()
    );
    let _ = write!(
        &mut info,
        "{}",
        values_from_hist("Inbound Send Depth", " packets", inbound_send_depth.clone()).as_str()
    );
    let inbound_send_mean: u64 =
        (inbound_send_duration.mean() / (1.0 + inbound_send_depth.mean())) as u64;
    let _ = write!(&mut info, "Approx packet time: {inbound_send_mean}ns\n\n\n");

    // Get info for outbound processor
    let _ = write!(
        &mut info,
        "{}",
        values_from_hist(
            "Outbound Processor Duration",
            "ns",
            outbound_processor_duration.clone()
        )
        .as_str()
    );
    let _ = write!(
        &mut info,
        "{}",
        values_from_hist(
            "Outbound Processor Depth",
            " packets",
            outbound_processor_depth.clone()
        )
        .as_str()
    );
    let outbound_pro_mean: u64 =
        (outbound_processor_duration.mean() / (1.0 + outbound_processor_depth.mean())) as u64;
    let _ = write!(&mut info, "Approx packet time: {outbound_pro_mean}ns\n\n\n");

    // Get info for outbound send
    let _ = write!(
        &mut info,
        "{}",
        values_from_hist(
            "Outbound Send Duration",
            "ns",
            outbound_send_duration.clone()
        )
        .as_str()
    );
    let _ = write!(
        &mut info,
        "{}",
        values_from_hist(
            "Outbound Send Depth",
            " packets",
            outbound_send_depth.clone()
        )
        .as_str()
    );
    let outbound_send_mean: u64 =
        (outbound_send_duration.mean() / (1.0 + outbound_send_depth.mean())) as u64;
    let _ = write!(
        &mut info,
        "Approx packet time: {outbound_send_mean}ns\n\n\n"
    );

    info
}

fn values_from_hist(hist_name: &str, units: &str, hist: Histogram<u64>) -> String {
    let ten: u64 = hist.value_at_quantile(0.10);
    let twenty_five: u64 = hist.value_at_quantile(0.25);
    let fifty: u64 = hist.value_at_quantile(0.50);
    let seventy_five: u64 = hist.value_at_quantile(0.75);
    let ninety: u64 = hist.value_at_quantile(0.90);
    let mean: f64 = hist.mean();

    let mut values: String = "".to_string();

    // Could be easily replaced with other data if need be
    let _ = write!(&mut values, "{} values at - 10th Quantile: {}{}, 25th Quantile: {}{},\n50th Quantile: {}{}, 75th Quantile: {}{}, 90th Quantile: {}{}, Mean: {}{}\n\n", hist_name, ten, units, twenty_five, units, fifty, units, seventy_five, units, ninety, units, mean, units);

    values
}
