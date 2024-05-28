use std::net::SocketAddr;
use std::os::fd::{AsRawFd, BorrowedFd, RawFd};
use std::process::ExitCode;
use tokio::io;

// TODO: make these all non-pub once everything is used
mod config;
pub mod buffer_stack;

use buffer_stack::BufferStack;


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

    let buf_storage = vec![[0u8; config::PACKET_BUFFER_SIZE]; 256];
    let buffer_stack = BufferStack::new(buf_storage.leak::<'static>());

    ExitCode::SUCCESS
}
