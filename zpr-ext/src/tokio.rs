pub mod net {
    use nix::sys::socket;
    use std::io;
    use tokio::net::UdpSocket;

    pub trait UdpSocketExt {
        fn mtu(&self) -> io::Result<u32>;
    }

    impl UdpSocketExt for UdpSocket {
        fn mtu(&self) -> io::Result<u32> {
            match socket::getsockopt(self, socket::sockopt::IpMtu) {
                Ok(mtu) => Ok(mtu as u32),
                Err(errno) => Err(io::Error::from(errno)),
            }
        }
    }
}
