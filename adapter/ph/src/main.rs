#![cfg_attr(feature = "ci", deny(warnings))]
use clap::Parser;
use enum_map::{enum_map, EnumMap};
use openssl::ssl;
use openssl::x509::X509;
use std::fs;
use std::fs::File;
use std::io::ErrorKind;
use std::io::Read;
use std::net::SocketAddr;
use std::pin::Pin;
use std::process::ExitCode;
use tokio::net::UdpSocket;
use tokio::net::UnixListener;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_tun::TunBuilder;

#[allow(unused_imports)]
#[macro_use]
extern crate arrayref;

// TODO: make these all non-pub once everything is used
mod assembly;
mod buffer_stack;
mod capture_worker;
mod classifier;
mod config;
mod counter;
mod counters_enum;
mod dtls_worker;
mod ext;
mod flow_control;
mod inbound_processor_worker;
mod inbound_send_worker;
mod options;
mod outbound_processor_worker;
mod outbound_recv_worker;
mod packet;
mod queues;
mod rpc_worker;
mod test_packet;
mod udp_stream;
mod zdp;
use assembly::Assembly;
use buffer_stack::BufferStack;
use capture_worker::CaptureWorker;
use counter::*;
use counters_enum::*;
use flow_control::FlowControl;
use options::PhMode;
use queues::*;

#[derive(Parser)]
#[command(version, about)]
struct CmdLine {
    #[arg(long, default_value_t, value_enum)]
    mode: PhMode,

    #[arg(long)]
    control_path: String,

    #[arg(long)]
    self_addr: SocketAddr,

    #[arg(long)]
    dock_addr: SocketAddr,

    #[arg(long)]
    ca_file: String,

    #[arg(long)]
    certificate_file: String,

    #[arg(long)]
    private_key_file: String,

    #[arg(long)]
    tun_if: Option<String>,
}

fn emit_counts(counts_map: &EnumMap<CounterType, Counter>) {
    for (key, &ref value) in counts_map {
        println!("{}: {}", key, value.get_count());
    }
}

fn main() -> ExitCode {
    let cmd_line = CmdLine::parse();

    let sock_path = cmd_line.control_path;
    let peer_addr = cmd_line.dock_addr;
    let self_addr = cmd_line.self_addr;
    let ca_file = cmd_line.ca_file;
    let cert_file = cmd_line.certificate_file;
    let priv_key_file = cmd_line.private_key_file;

    // TODO: These batch sizes are placeholders for now.  So are the queue
    // sizes below which are all just double the batch size.  Performance
    // testing will inform us the correct values for these, which balance
    // throughput with service time.
    let inbound_recv_batch_size = 8;
    let inbound_processor_batch_size = 16;
    let inbound_send_batch_size = 4;
    let outbound_recv_batch_size = 4;
    let outbound_processor_batch_size = 16;
    let outbound_send_queue_size = 16;
    let outbound_send_batch_size = 8;
    let capture_queue_size = 16;
    let capture_batch_size = 8;
    let tun_queue_count = 1;

    let buf_storage = vec![[0u8; config::PACKET_BUFFER_SIZE]; 256];
    let buffer_stack = BufferStack::new(buf_storage.leak::<'static>());
    let (ip_inq, ip_outq) = mpsc::channel(inbound_processor_batch_size * 2);
    let inbound_processor = InboundProcessor::new(ip_inq);

    let mut is_inqs = Vec::new();
    let mut is_outqs = Vec::new();
    for _ in 0..tun_queue_count {
        let (is_inq, is_outq) = mpsc::channel(inbound_send_batch_size * 2);
        // FIXME: maybe a way to do this with unzip but Rust couldn't infer types
        is_inqs.push(is_inq);
        is_outqs.push(is_outq);
    }
    let inbound_send = InboundSend::new(is_inqs.into_boxed_slice());

    let (op_inq, op_outq) = mpsc::channel(outbound_processor_batch_size * 2);
    let outbound_processor = OutboundProcessor::new(op_inq);

    let (os_inq, os_outq) = mpsc::channel(outbound_send_queue_size);
    let outbound_send = OutboundSend::new(os_inq);

    let (cap_inq, cap_outq) = mpsc::channel(capture_queue_size);
    let capture_queue = Capture::new(cap_inq);
    
    let capture_worker = CaptureWorker::new();
    
    let flow_control = FlowControl::new();

    let counters = enum_map! { _ => Counter::new(), };

    let asm = Box::leak(Box::new(Assembly {
        buffer_stack,
        inbound_processor,
        inbound_send,
        outbound_processor,
        outbound_send,
        capture_queue,
        capture_worker,
        flow_control,
        counters,
    }));

    let mut ssl_context_builder = ssl::SslContext::builder(ssl::SslMethod::dtls()).unwrap();
    ssl_context_builder.set_options(
        ssl::SslOptions::NO_COMPRESSION
            | (ssl::SslOptions::NO_SSL_MASK & !ssl::SslOptions::NO_DTLSV1_2),
    );

    ssl_context_builder.set_ca_file(&ca_file).unwrap();
    ssl_context_builder.set_verify(ssl::SslVerifyMode::PEER);
    ssl_context_builder
        .set_certificate_file(cert_file, ssl::SslFiletype::PEM)
        .unwrap();
    ssl_context_builder
        .set_private_key_file(priv_key_file, ssl::SslFiletype::PEM)
        .unwrap();

    let mut open_ca = File::open(ca_file).unwrap();
    let mut buffer = Vec::new();
    open_ca.read_to_end(&mut buffer).unwrap();
    ssl_context_builder
        .add_client_ca(&X509::from_pem(&buffer).unwrap())
        .unwrap();

    let ssl_context = Box::leak(Box::new(ssl_context_builder.build()));
    // FIXME: "OpenSSL’s default configuration is insecure.  It is highly
    // recommended to use SslConnector rather than Ssl directly, as it
    // manages that configuration."
    let ssl = ssl::Ssl::new(&ssl_context).unwrap();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            // TODO signal handler goes here

            fs::remove_file(&sock_path)
                .or_else(|e| {
                    if e.kind() == ErrorKind::NotFound {
                        Ok(())
                    } else {
                        Err(e)
                    }
                })
                .unwrap();
            let unix_socket = Box::leak(Box::new(UnixListener::bind(sock_path).unwrap())); //TODO not sure if this needs the Box leak wrapper

            let mut js = JoinSet::new();

            // Launches RPC worker program
            js.spawn(rpc_worker::launch(&*asm, &*unix_socket));

            let usr1_stream = Box::leak(Box::new(signal(SignalKind::user_defined1()).unwrap()));
            let term_stream = Box::leak(Box::new(signal(SignalKind::terminate()).unwrap()));

            js.spawn(async {
                loop {
                    tokio::select! {
                        _ = usr1_stream.recv() => emit_counts(&asm.counters),
                        _ = term_stream.recv() => emit_counts(&asm.counters)
                    }
                }
            });

            let tun_devs = TunBuilder::new()
                .name(cmd_line.tun_if.unwrap_or(String::new()).as_str())
                .packet_info(false)
                .try_build_mq(tun_queue_count)
                .expect("unable to open TUN device")
                .leak();

            js.spawn(inbound_processor_worker::launch(
                &inbound_processor_worker::Config {
                    batch_size: inbound_processor_batch_size,
                    mode: cmd_line.mode,
                },
                &*asm,
                ip_outq,
            ));

            for (tun_dev, is_outq) in tun_devs.iter().zip(is_outqs) {
                js.spawn(inbound_send_worker::launch(
                    &inbound_send_worker::Config {
                        batch_size: inbound_send_batch_size,
                    },
                    &*asm,
                    is_outq,
                    tun_dev,
                ));
            }

            for tun_dev in tun_devs.iter() {
                js.spawn(outbound_recv_worker::launch(
                    &outbound_recv_worker::Config {
                        batch_size: outbound_recv_batch_size,
                    },
                    &*asm,
                    tun_dev,
                ));
            }

            js.spawn(outbound_processor_worker::launch(
                &outbound_processor_worker::Config {
                    batch_size: outbound_processor_batch_size,
                },
                &*asm,
                op_outq,
            ));

            js.spawn(rpc_worker::launch(&*asm, &*unix_socket));

            js.spawn(capture_worker::launch(
                &capture_worker::Config {
                    batch_size: capture_batch_size,
                },
                &*asm,
                cap_outq,
            ));
            
            // TODO: initiate the DTLS connection asynchronously; for now, keep this at the end
            eprintln!("Connecting...");
            let socket = Box::leak(Box::new(
                UdpSocket::bind(self_addr)
                    .await
                    .expect("unable to bind to self addr"),
            ));
            socket
                .connect(peer_addr)
                .await
                .expect("unable to connect to peer addr");
            let mut ssl_stream =
                tokio_openssl::SslStream::new(ssl, udp_stream::UdpStream::new(socket)).unwrap();
            match cmd_line.mode {
                PhMode::Client => Pin::new(&mut ssl_stream)
                    .connect()
                    .await
                    .expect("unable to establish DTLS connection"),
                PhMode::Server => Pin::new(&mut ssl_stream)
                    .accept()
                    .await
                    .expect("unable to establish DTLS connection"),
            }
            eprintln!("Connected!");

            js.spawn(dtls_worker::launch(
                &dtls_worker::Config {
                    inbound_batch_size: inbound_recv_batch_size,
                    outbound_batch_size: outbound_send_batch_size,
                },
                &*asm,
                ssl_stream,
                os_outq,
            ));

            while let Some(res) = js.join_next().await {
                res.unwrap();
            }
        });

    ExitCode::SUCCESS
}
