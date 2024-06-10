use std::net::SocketAddr;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::process::ExitCode;
use tokio::io;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

// TODO: make these all non-pub once everything is used
pub mod ext;
mod config;
pub mod buffer_stack;
mod packet;
mod queues;
mod assembly;
mod inbound_recv_worker;
mod counter;
mod inbound_processor_worker;

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

fn main() -> ExitCode {
    let mut args = std::env::args();

    let execname = args.next().unwrap();

    if args.len() < 3 {
        eprintln!("Usage: {execname} <self addr:port> <peer addr:port> <TUN fd> [<TUN fd>...]");
        return ExitCode::FAILURE;
    }

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
    let inbound_recv_batch_size = 16;
    let inbound_processor_batch_size = 16;
    let inbound_send_batch_size = 4;
    let outbound_recv_batch_size = 4;
    let outbound_processor_batch_size = 16;
    let outbound_send_batch_size = 16;

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

    let (os_inq, os_outq) = mpsc::channel(outbound_send_batch_size * 2);
    let outbound_send = OutboundSend::new(os_inq);

    let counters = [Counter::new(), Counter::new()];

    let asm = Box::leak(Box::new(Assembly{
            buffer_stack, inbound_processor, inbound_send,
            outbound_processor, outbound_send, counters
        }));

    // TODO signal handler goes here


    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let socket = Box::leak(Box::new(UdpSocket::bind(self_addr).await.expect("unable to bind to self addr")));
            socket.connect(peer_addr).await.expect("unable to connect to peer addr");

            let mut js = JoinSet::new();

            js.spawn(inbound_recv_worker::launch(
                    &inbound_recv_worker::Config{ batch_size: inbound_recv_batch_size },
                    &*asm, &*socket));

            js.spawn(inbound_processor_worker::launch(
                    &inbound_processor_worker::Config{ batch_size: inbound_processor_batch_size },
                    &*asm, ip_outq));

            while let Some(res) = js.join_next().await {
                res.unwrap();
            }
        });

    ExitCode::SUCCESS
}
