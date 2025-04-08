use std::net::IpAddr;
use std::os::unix::io::{RawFd, AsRawFd};
use std::mem;
use nix::{ioctl_readwrite, ioctl_write_ptr};

use thiserror::Error;

use crate::zprtun::DEFAULT_TUN_MTU;

use libc::{
    self, IFNAMSIZ, PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL, AF_SYSTEM, AF_SYS_CONTROL, AF_INET,
    UTUN_OPT_IFNAME, c_uint, c_char, socklen_t, sockaddr, c_void,
};

pub const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";



ioctl_readwrite!(ctliocginfo, b'N', 3, ctl_info); // Convert kernel controller name to kernel controller ID


#[repr(C)]
#[derive(Copy, Clone)]
pub struct ctl_info {
    pub ctl_id: c_uint, // kernel controller ID (filled in on return)
    pub ctl_name: [c_char; 96], // kernel controller name
}


#[derive(Debug, Error)]
pub enum TunError {
    #[error("TUN device name is too long")]
    NameTooLong,
    #[error("TUN device name is invalid (expect 'utun<N>')")]
    InvalidName,
    #[error("Failed to parse TUN interface name: {0}")]
    ParseError(#[from] std::num::ParseIntError),
    #[error("I/O Error: {0}")]
    IOError(#[from] std::io::Error),
}

/// TUN device on macOS.
pub struct Tun {
    tun_fd: RawFd,
    ctl_fd: RawFd,
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.tun_fd
    }
}

impl Tun {
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn create(config: &Builder) -> Result<Self, TunError> {
        let mtu = config.mtu.unwrap_or(DEFAULT_TUN_MTU);

        // The id is one plus the number after the "utun" prefix.
        // If we pass the kernel id=0 it will assign the next available id.
        let id = if let Some(tun_name) = config.name.as_ref() {
            if tun_name.len() > IFNAMSIZ {
                return Err(TunError::NameTooLong);
            }
            if !tun_name.starts_with("utun") {
                return Err(TunError::InvalidName);
            }
            tun_name[4..].parse::<u32>()? + 1_u32
        } else {
            0_u32
        };

        unsafe {
            let fd = libc::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
            let mut info = ctl_info {
                ctl_id: 0,
                ctl_name: {
                    let mut buffer = [0; 96];
                    for (i, o) in UTUN_CONTROL_NAME.as_bytes().iter().zip(buffer.iter_mut()) {
                        *o = *i as _;
                    }
                    buffer
                },
            };

            // Obtain a ctl_id for utun controller
            if let Err(err) = ctliocginfo(fd, &mut info as *mut _ as *mut _) {
                return Err(std::io::Error::from(err).into());
            }

            let addr = libc::sockaddr_ctl {
                sc_id: info.ctl_id,
                sc_len: mem::size_of::<libc::sockaddr_ctl>() as _,
                sc_family: AF_SYSTEM as _,
                ss_sysaddr: AF_SYS_CONTROL as _,
                sc_unit: id as c_uint,
                sc_reserved: [0; 5],
            };

            // Pretty sure this 'connect' call will create the TUN device
            let address = &addr as *const libc::sockaddr_ctl as *const sockaddr;
            if libc::connect(fd, address, mem::size_of_val(&addr) as socklen_t) < 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            let mut tun_name = [0u8; 64];
            let mut name_len: socklen_t = 64;

            let optval = &mut tun_name as *mut _ as *mut c_void;
            let optlen = &mut name_len as *mut socklen_t;
            if libc::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, optval, optlen) < 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            let ctl = libc::socket(AF_INET, SOCK_DGRAM, 0);


        }



        Ok(Tun {})
    }
}



#[derive(Default)]
pub struct Builder {
    name: Option<String>,
    mtu: Option<u16>,
    address: Option<IpAddr>,
    // flags: Option<i32>,
    // queue_count: usize,
}


impl Builder {
    pub fn set_tun_name(&mut self, name: &str) -> &mut Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_mtu(&mut self, mtu: u16) -> &mut Self {
        self.mtu = Some(mtu);
        self
    }

    pub fn set_address(&mut self, addr: IpAddr) -> &mut Self {
        self.address = Some(addr);
        self
    }
}