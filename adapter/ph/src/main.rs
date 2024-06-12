use std::fs;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::pin::Pin;
use std::process::ExitCode;
use openssl::ssl;
use tokio::io;
use tokio::io::unix::AsyncFd;
use tokio::net::UdpSocket;
use tokio::net::UnixListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::signal::unix::{signal, SignalKind};

#[macro_use]
extern crate arrayref;

// TODO: make these all non-pub once everything is used
pub mod ext;
mod config;
pub mod buffer_stack;
mod packet;
mod queues;
mod assembly;
mod counter;
mod udp_stream;
mod dtls_worker;
mod inbound_processor_worker;
mod inbound_send_worker;
mod outbound_recv_worker;
mod outbound_processor_worker;
mod rpc_worker;

use buffer_stack::BufferStack;
use queues::*;
use counter::*;
use assembly::Assembly;


fn is_std_fd(rfd: RawFd) -> bool {
    rfd == std::io::stdin().as_raw_fd() ||
    rfd == std::io::stdout().as_raw_fd() ||
    rfd == std::io::stderr().as_raw_fd()
}

fn is_fd_open<T: AsRawFd>(fd: T) -> bool {
    nix::fcntl::fcntl(fd.as_raw_fd(), nix::fcntl::FcntlArg::F_GETFD).is_ok()
}

fn set_fd_nonblocking<T: AsRawFd>(fd: T) -> io::Result<()> {
    let rfd = fd.as_raw_fd();
    let flags = nix::fcntl::fcntl(rfd, nix::fcntl::FcntlArg::F_GETFL)?;
    let flags_nb = nix::fcntl::OFlag::from_bits_retain(flags) | nix::fcntl::OFlag::O_NONBLOCK;
    nix::fcntl::fcntl(rfd, nix::fcntl::FcntlArg::F_SETFL(flags_nb))?;
    Ok(())
}

fn emit_counts(counts_arr:&[Counter]) {
    let num_packets = counts_arr[0].get_count();
    let num_dropped = counts_arr[1].get_count();
    eprintln!("packets recieved: {num_packets}");
    eprintln!("packets dropped: {num_dropped}");
}

fn main() -> ExitCode {
    let mut args = std::env::args();

    let execname = args.next().unwrap();

    if args.len() < 4 {
        eprintln!("Usage: {execname} <socket path> <self addr:port> <peer addr:port> <TUN fd> [<TUN fd>...]");
        return ExitCode::FAILURE;
    }

    let Ok(sock_path) = args.next().unwrap().parse::<String>()
    else {
        eprintln!("Socket path parse failure");
        return ExitCode::FAILURE;
    };

    let Ok(self_addr) = args.next().unwrap().parse::<SocketAddr>()
    else {
        eprintln!("Address parse failure");
        return ExitCode::FAILURE;
    };

    let Ok(peer_addr) = args.next().unwrap().parse::<SocketAddr>()
    else {
        eprintln!("Address parse failure");
        return ExitCode::FAILURE;
    };

    let mut tun_fds = Vec::new();
    for arg in args {
        let Ok(rfd) = arg.parse::<RawFd>()
        else {
            eprintln!("FD parse failure");
            return ExitCode::FAILURE;
        };
        if is_std_fd(rfd) {
            eprintln!("refusing to use std FD");
            return ExitCode::FAILURE;
        }
        if !is_fd_open(rfd) {
            eprintln!("FD is not open");
            return ExitCode::FAILURE;
        }
        set_fd_nonblocking(rfd).expect("unable to set FD nonblocking");
        tun_fds.push(unsafe { BorrowedFd::borrow_raw(rfd) });
    }

    // TODO: These batch sizes are placeholders for now.  So are the queue
    // sizes below which are all just double the batch size.  Performance
    // testing will inform us the correct values for these, which balance
    // throughput with service time.
    let inbound_processor_batch_size = 16;
    let inbound_send_batch_size = 4;
    let outbound_recv_batch_size = 4;
    let outbound_processor_batch_size = 16;
    let outbound_send_queue_size = 16;

    let buf_storage = vec![[0u8; config::PACKET_BUFFER_SIZE]; 256];
    let buffer_stack = BufferStack::new(buf_storage.leak::<'static>());

    let (ip_inq, ip_outq) = mpsc::channel(inbound_processor_batch_size * 2);
    let inbound_processor = InboundProcessor::new(ip_inq);

    let mut is_inqs = Vec::new();
    let mut is_outqs = Vec::new();
    for _ in 0..tun_fds.len() {
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

    let counters = [Counter::new(), Counter::new()];

    let asm = Box::leak(Box::new(Assembly{
            buffer_stack, inbound_processor, inbound_send,
            outbound_processor, outbound_send, counters
        }));

    let mut ssl_context_builder = ssl::SslContext::builder(ssl::SslMethod::dtls()).unwrap();
    ssl_context_builder.set_options(
        ssl::SslOptions::NO_COMPRESSION |
        (ssl::SslOptions::NO_SSL_MASK & !ssl::SslOptions::NO_DTLSV1_2));
    // TODO: set CA cert, client key, & enable verification here
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
            
            fs::remove_file(&sock_path).or_else(|e| if e.kind() == ErrorKind::NotFound { Ok(()) } else { Err(e) }).unwrap();
            let unix_socket =  Box::leak(Box::new(UnixListener::bind(sock_path).unwrap())); //TODO not sure if this needs the Box leak wrapper

            let async_tun_fds = tun_fds.into_iter().map(|tun_fd| AsyncFd::new(tun_fd).unwrap()).collect::<Vec<_>>().leak();

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

            js.spawn(inbound_processor_worker::launch(
                    &inbound_processor_worker::Config{ batch_size: inbound_processor_batch_size },
                    &*asm, ip_outq));

            for (async_tun_fd, is_outq) in async_tun_fds.iter().zip(is_outqs) {
                js.spawn(inbound_send_worker::launch(
                    &inbound_send_worker::Config{ batch_size: inbound_send_batch_size },
                    &*asm, is_outq, &*async_tun_fd));
            }

            for async_tun_fd in async_tun_fds.iter() {
                js.spawn(outbound_recv_worker::launch(
                    &outbound_recv_worker::Config{ batch_size: outbound_recv_batch_size },
                    &*asm, &*async_tun_fd));
            }

            js.spawn(outbound_processor_worker::launch(
                    &outbound_processor_worker::Config{ batch_size: outbound_processor_batch_size },
                    &*asm, op_outq));

            js.spawn(rpc_worker::launch(&*asm, &*unix_socket));

            // TODO: initiate the DTLS connection asynchronously; for now, keep this at the end
            let socket = Box::leak(Box::new(UdpSocket::bind(self_addr).await.expect("unable to bind to self addr")));
            socket.connect(peer_addr).await.expect("unable to connect to peer addr");
            let mut ssl_stream = tokio_openssl::SslStream::new(ssl, udp_stream::UdpStream::new(socket)).unwrap();
            Pin::new(&mut ssl_stream).connect().await.expect("unable to establish DTLS connection");

            js.spawn(dtls_worker::launch(&*asm, ssl_stream, os_outq));

            while let Some(res) = js.join_next().await {
                res.unwrap();
            }
        });

    ExitCode::SUCCESS
}
