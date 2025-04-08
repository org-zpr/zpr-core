use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::io::{RawFd, AsRawFd};
use std::mem;
use std::ptr;
use std::ffi::CStr;
use nix::{ioctl_readwrite, ioctl_write_ptr};

use thiserror::Error;

use crate::zprtun::DEFAULT_TUN_MTU;

use libc::{
    self, IFNAMSIZ, PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL, AF_SYSTEM, AF_SYS_CONTROL, AF_INET,
    UTUN_OPT_IFNAME, c_uint, c_char, socklen_t, sockaddr, c_void, ifreq,
    sockaddr_in, sockaddr_in6,
};

/// Special macOS controller name for creating tun devices. (see net/if_utun.h)
pub const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";

/// Size of the ifr_ifru union in the ifreq struct. (see net/if.h)
const OVERWRITE_SIZE: usize = std::mem::size_of::<libc::__c_anonymous_ifr_ifru>();


ioctl_readwrite!(ctliocginfo, b'N', 3, ctl_info); // Convert kernel controller name to kernel controller ID
ioctl_write_ptr!(siocsifaddr, b'i', 12, ifreq); // set ifnet address (XXX is this IPv4 only?)
// ioctl_write_ptr!(siocsifaddr_in6, b'i', 12, in6_ifreq); // set ifnet address (ipv6)
ioctl_write_ptr!(siocsifmtu, b'i', 52, ifreq); // set ifnet MTU


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
    name: String,
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

        let mut tundev = unsafe {
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

            // Now query for the name of the TUN device
            let mut tun_name = [0u8; 64];
            let mut name_len: socklen_t = 64;
            let optval = &mut tun_name as *mut _ as *mut c_void;
            let optlen = &mut name_len as *mut socklen_t;
            if libc::getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, optval, optlen) < 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            let tun_name_str: String = CStr::from_ptr(tun_name.as_ptr() as *const c_char)
                .to_string_lossy()
                .into();


            let ctl = libc::socket(AF_INET, SOCK_DGRAM, 0);

            Tun {
                tun_fd: fd,
                ctl_fd: ctl,
                name: tun_name_str,
            }
        };

        if config.address.is_some() {
            tundev.set_address(config.address.unwrap())?;
        }
        tundev.set_mtu(mtu)?;

        Ok(tundev)
    }

    /// Prepare a new request for kernel control socket.
    unsafe fn request(&self) -> Result<libc::ifreq, TunError> {
        let mut req: libc::ifreq = unsafe { mem::zeroed() };
        unsafe {
            ptr::copy_nonoverlapping(
                self.name.as_ptr() as *const c_char,
                req.ifr_name.as_mut_ptr(),
                self.name.len(),
            )
        };
        Ok(req)
    }

    fn set_address(&mut self, addr: IpAddr) -> Result<(), TunError> {
        match addr {
            IpAddr::V4(ipv4) => self.set_address_ipv4(ipv4),
            IpAddr::V6(ipv6) => self.set_address_ipv6(ipv6),
        }
    }

    fn set_address_ipv4(&mut self, value: Ipv4Addr) -> Result<(), TunError> {
        unsafe {
            let mut req = self.request()?;
            ipv4addr_to_sockaddr(value, 0, &mut req.ifr_ifru.ifru_addr, OVERWRITE_SIZE);
            if let Err(err) = siocsifaddr(self.ctl_fd, &req) {
                return Err(std::io::Error::from(err).into());
            }
            // TODO: Update routing?
            Ok(())
        }
    }

    fn set_address_ipv6(&mut self, value: Ipv6Addr) -> Result<(), TunError> {
        unsafe {
            let mut req = self.request()?;
            ipv6addr_to_sockaddr(value, 0, &mut req.ifr_ifru.ifru_addr, OVERWRITE_SIZE);
            if let Err(err) = siocsifaddr(self.ctl_fd, &req) {
                return Err(std::io::Error::from(err).into());
            }
            // TODO: Update routing?
            Ok(())
        }
    }


    fn set_mtu(&mut self, value: u16) -> Result<(), TunError> {
        unsafe {
            let mut req = self.request()?;
            req.ifr_ifru.ifru_mtu = value as i32;
            if let Err(err) = siocsifmtu(self.ctl_fd, &req) {
                return Err(std::io::Error::from(err).into());
            }
            Ok(())
        }
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
    /// Tun name is optional. If provided must be of format "utun<N>" where N is a number.
    #[allow(dead_code)]
    pub fn with_tun_name(&mut self, name: &str) -> &mut Self {
        self.name = Some(name.into());
        self
    }

    #[allow(dead_code)]
    pub fn with_mtu(&mut self, mtu: u16) -> &mut Self {
        self.mtu = Some(mtu);
        self
    }

    #[allow(dead_code)]
    pub fn with_address(&mut self, addr: IpAddr) -> &mut Self {
        self.address = Some(addr);
        self
    }
}



/// Fill the `addr` with the address particulars. `size` is the size of the
/// sockaddr structure to be filled (used as our upper bound for the copy).
pub unsafe fn ipv4addr_to_sockaddr (
    src_addr: Ipv4Addr,
    src_port: u16,
    addr: &mut libc::sockaddr,
    size: usize,
)
{
    let mut s_addr: sockaddr_in = unsafe { std::mem::zeroed() };
    s_addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    s_addr.sin_family = libc::AF_INET as libc::sa_family_t;
    s_addr.sin_addr.s_addr = u32::from_ne_bytes(src_addr.octets());
    s_addr.sin_port = src_port.to_be();

    unsafe {
        std::ptr::copy_nonoverlapping(
            &s_addr as *const _ as *const libc::c_void,
            addr as *mut _ as *mut libc::c_void,
            size.min(std::mem::size_of::<sockaddr_in>()));
    };
}

pub unsafe fn ipv6addr_to_sockaddr (
    src_addr: Ipv6Addr,
    src_port: u16,
    addr: &mut libc::sockaddr,
    size: usize,
)
{
    let mut s_addr: sockaddr_in6 = unsafe { std::mem::zeroed() };
    s_addr.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
    s_addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    s_addr.sin6_port = src_port.to_be();
    s_addr.sin6_flowinfo = 0;
    s_addr.sin6_addr.s6_addr = src_addr.octets();
    s_addr.sin6_scope_id = 0;
    unsafe {
        std::ptr::copy_nonoverlapping(
            &s_addr as *const _ as *const libc::c_void,
            addr as *mut _ as *mut libc::c_void,
            size.min(std::mem::size_of::<sockaddr_in6>()));
    };
}



