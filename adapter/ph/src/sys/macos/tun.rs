use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::{ioctl_readwrite, ioctl_write_ptr};
use std::ffi::CStr;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsFd;
use std::os::unix::io::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;

use thiserror::Error;
use tracing::*;

use crate::logging::targets::NET_OS;
use crate::zprtun::{DEFAULT_TUN_MTU, ZPRNET_PREFIX_LEN};

use libc::{
    self, c_char, c_int, c_uint, c_void, ctl_info, ifreq, sockaddr, sockaddr_in, sockaddr_in6,
    socklen_t, AF_INET, AF_INET6, AF_SYSTEM, AF_SYS_CONTROL, IFNAMSIZ, PF_SYSTEM, SOCK_DGRAM,
    SYSPROTO_CONTROL, UTUN_OPT_IFNAME,
};

// Not in libc. Copied from netinet6/in6_var.h
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct in6_aliasreq {
    pub ifra_name: [c_char; IFNAMSIZ],
    pub ifra_addr: sockaddr_in6,
    pub ifra_dstaddr: sockaddr_in6,
    pub ifra_prefixmask: sockaddr_in6,
    pub ifra_flags: c_int,
    pub ifra_lifetime: libc::in6_addrlifetime,
}

// Not in libc. Copied from netinet6/nd6.h
const ND6_INFINITE_LIFETIME: c_uint = 0xffffffff;
const IPV6_MMTU: u16 = 1280; // Minimum MTU for IPv6
const IPV4_MMTU: u16 = 576; // Minimum MTU for IPv4

/// Special macOS controller name for creating tun devices. (see net/if_utun.h)
pub const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";

/// Size of the ifr_ifru union in the ifreq struct. (see net/if.h)
const OVERWRITE_SIZE_IP4: usize = std::mem::size_of::<libc::__c_anonymous_ifr_ifru>();

ioctl_readwrite!(ctliocginfo, b'N', 3, ctl_info); // Convert kernel controller name to kernel controller ID
ioctl_write_ptr!(siocsifaddr, b'i', 12, ifreq); // set ifnet address (is this IPv4 only?)
ioctl_write_ptr!(siocaifaddr_in6, b'i', 26, in6_aliasreq); // set ifnet address (ipv6)
ioctl_write_ptr!(siocsifmtu, b'i', 52, ifreq); // set ifnet MTU

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

    #[error("Invalid prefix length (0-128)")]
    InvalidPrefixLen,

    #[error("Invalid MTU size (must be >= 1280 for IPv6)")]
    InvalidIpv6Mtu,

    #[error("Invalid MTU size (must be >= 576 for IPv4)")]
    InvalidIpv4Mtu,
}

/// Basic TUN device on macOS.
pub struct Tun {
    tun_fd: OwnedFd,
    ctl_fd: OwnedFd,
    name: String,
}

// This is the way ZPR accesses the tun device.
impl AsFd for Tun {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.tun_fd.as_fd()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum IPV {
    V4,
    V6,
}

impl From<IpAddr> for IPV {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => IPV::V4,
            IpAddr::V6(_) => IPV::V6,
        }
    }
}

impl Tun {
    /// Create a build to aid in configuring the tun.
    pub fn builder(ipv: IPV) -> Builder {
        Builder::new(ipv)
    }

    /// Create and configure the TUN device.
    pub fn create(config: &Builder) -> Result<Self, TunError> {
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
            let fd = OwnedFd::from_raw_fd(libc::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL));
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
            if let Err(err) = ctliocginfo(fd.as_raw_fd(), &mut info as *mut _ as *mut _) {
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

            // This 'connect' call will request creation of the TUN device
            let address = &addr as *const libc::sockaddr_ctl as *const sockaddr;
            if libc::connect(
                fd.as_raw_fd(),
                address,
                mem::size_of_val(&addr) as socklen_t,
            ) < 0
            {
                return Err(std::io::Error::last_os_error().into());
            }

            // Now query for the name of the TUN device
            let mut tun_name = [0u8; 64];
            let mut name_len: socklen_t = 64;
            let optval = &mut tun_name as *mut _ as *mut c_void;
            let optlen = &mut name_len as *mut socklen_t;
            if libc::getsockopt(
                fd.as_raw_fd(),
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                optval,
                optlen,
            ) < 0
            {
                return Err(std::io::Error::last_os_error().into());
            }

            let tun_name_str: String = CStr::from_ptr(tun_name.as_ptr() as *const c_char)
                .to_string_lossy()
                .into();

            let ctl_sock;
            if config.is_ipv6() {
                ctl_sock = libc::socket(AF_INET6, SOCK_DGRAM, 0);
            } else {
                ctl_sock = libc::socket(AF_INET, SOCK_DGRAM, 0);
            }
            if ctl_sock < 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            Tun {
                tun_fd: fd,
                ctl_fd: OwnedFd::from_raw_fd(ctl_sock),
                name: tun_name_str,
            }
        };
        info!(target: NET_OS, "TUN device created: {}", tundev.name);

        tundev.configure(config)?;

        // TODO: Set interface UP? Not required? Seems like kernel sets it to UP already.

        Ok(tundev)
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    // Post create configuration based on the builder.
    fn configure(&mut self, config: &Builder) -> Result<(), TunError> {
        // Set to non-blocking
        if let Err(err) = Tun::set_raw_fd_nonblocking(self.tun_fd.as_raw_fd()) {
            return Err(TunError::IOError(std::io::Error::from(err)));
        }

        let mtu: Option<u16>;
        if let Some(addr) = config.address {
            let prefix_len = config.prefix_len.unwrap_or(ZPRNET_PREFIX_LEN);
            if prefix_len > 128 {
                return Err(TunError::InvalidPrefixLen);
            }
            self.set_address(addr, prefix_len)?;

            // If address is specified, always also set MTU
            mtu = Some(config.mtu.unwrap_or(DEFAULT_TUN_MTU));
        } else {
            // Address not specied, only set MTU if it (MTU) is specified.
            mtu = config.mtu;
        }
        if let Some(mtu) = mtu {
            if config.is_ipv6() && mtu < IPV6_MMTU {
                return Err(TunError::InvalidIpv6Mtu);
            }
            if !config.is_ipv6() && mtu < IPV4_MMTU {
                return Err(TunError::InvalidIpv4Mtu);
            }
            self.set_mtu(mtu)?;
        }
        Ok(())
    }

    /// Prepare a new `ifreq` request for kernel control socket.  Fills in the name field.
    unsafe fn request_v4(&self) -> Result<libc::ifreq, TunError> {
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

    /// Set the address of the TUN device.  `prefix_len` is the prefix length for IPv6 and is ignored for IPv4.
    pub fn set_address(&mut self, addr: IpAddr, prefix_len: usize) -> Result<(), TunError> {
        match addr {
            IpAddr::V4(ipv4) => self.set_address_ipv4(ipv4),
            IpAddr::V6(ipv6) => self.set_address_ipv6(ipv6, prefix_len),
        }
    }

    fn set_address_ipv4(&mut self, value: Ipv4Addr) -> Result<(), TunError> {
        unsafe {
            let mut req = self.request_v4()?;
            ipv4addr_to_sockaddr(value, 0, &mut req.ifr_ifru.ifru_addr, OVERWRITE_SIZE_IP4);
            if let Err(err) = siocsifaddr(self.ctl_fd.as_raw_fd(), &req) {
                return Err(std::io::Error::from(err).into());
            }
            // TODO: Update routing?
            Ok(())
        }
    }

    fn set_address_ipv6(&mut self, value: Ipv6Addr, prefix_len: usize) -> Result<(), TunError> {
        let mut req: in6_aliasreq = unsafe { mem::zeroed() };
        unsafe {
            ptr::copy_nonoverlapping(
                self.name.as_ptr() as *const c_char,
                req.ifra_name.as_mut_ptr(),
                self.name.len(),
            );

            ipv6addr_to_sockaddr(value, 0, &mut req.ifra_addr, mem::size_of::<sockaddr_in6>());

            req.ifra_prefixmask.sin6_family = AF_INET6 as libc::sa_family_t;
            req.ifra_prefixmask.sin6_len = mem::size_of::<sockaddr_in6>() as u8;

            let mut pfx_mask: u128 = 0;
            for i in 0..prefix_len {
                pfx_mask |= 1 << (127 - i);
            }
            req.ifra_prefixmask.sin6_addr.s6_addr = pfx_mask.to_be_bytes();

            req.ifra_lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME;
            req.ifra_lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME;

            if let Err(err) = siocaifaddr_in6(self.ctl_fd.as_raw_fd(), &req) {
                return Err(std::io::Error::from(err).into());
            }
            // TODO: Update routing?
            Ok(())
        }
    }

    pub fn set_mtu(&mut self, value: u16) -> Result<(), TunError> {
        unsafe {
            let mut req = self.request_v4()?;
            req.ifr_ifru.ifru_mtu = value as i32;
            if let Err(err) = siocsifmtu(self.ctl_fd.as_raw_fd(), &req) {
                return Err(std::io::Error::from(err).into());
            }
            Ok(())
        }
    }

    fn set_raw_fd_nonblocking(fd: RawFd) -> nix::Result<()> {
        // Get the current file status flags
        let flags = fcntl(fd, FcntlArg::F_GETFL)?;

        // Add the O_NONBLOCK flag to the existing flags
        let mut new_flags = OFlag::from_bits_truncate(flags);
        new_flags.insert(OFlag::O_NONBLOCK);

        // Set the new flags
        fcntl(fd, FcntlArg::F_SETFL(new_flags))?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Builder {
    name: Option<String>,
    mtu: Option<u16>,
    prefix_len: Option<usize>,
    address: Option<IpAddr>,
    ipv: IPV,
}

impl Builder {
    /// Create a new builder, which is used to configure the TUN device.
    /// You must choose either IPv4 or IPv6.
    fn new(ipv: IPV) -> Builder {
        Builder {
            name: None,
            mtu: None,
            prefix_len: None,
            address: None,
            ipv,
        }
    }

    pub fn is_ipv6(&self) -> bool {
        self.ipv == IPV::V6
    }

    /// Set the address of the TUN device.  If you set this in the builder then
    /// the address will be assigned when you create the TUN device.
    #[allow(dead_code)]
    pub fn with_address(&mut self, addr: IpAddr) -> &mut Self {
        if addr.is_ipv4() && self.is_ipv6() {
            panic!("Cannot set IPv4 address on IPv6 TUN device");
        }
        if addr.is_ipv6() && !self.is_ipv6() {
            panic!("Cannot set IPv6 address on IPv4 TUN device");
        }
        self.address = Some(addr);
        self
    }

    /// Tun name is optional. If provided must be of format "utun<N>" where N is a number.
    #[allow(dead_code)]
    pub fn with_tun_name(&mut self, name: &str) -> &mut Self {
        self.name = Some(name.into());
        self
    }

    /// Will use a default setting if not supplied.
    #[allow(dead_code)]
    pub fn with_mtu(&mut self, mtu: u16) -> &mut Self {
        self.mtu = Some(mtu);
        self
    }

    /// Set IPv6 prefix len (0<=prefix_len<=128). Will use a default setting is not supplied.
    #[allow(dead_code)]
    pub fn with_prefix_len(&mut self, prefix_len: usize) -> &mut Self {
        self.prefix_len = Some(prefix_len);
        self
    }
}

/// Fill the `addr` with the address particulars. `size` is the size of the
/// sockaddr structure to be filled (used as our upper bound for the copy).
pub unsafe fn ipv4addr_to_sockaddr(
    src_addr: Ipv4Addr,
    src_port: u16,
    addr: &mut libc::sockaddr,
    size: usize,
) {
    let mut s_addr: sockaddr_in = unsafe { std::mem::zeroed() };
    s_addr.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    s_addr.sin_family = libc::AF_INET as libc::sa_family_t;
    s_addr.sin_addr.s_addr = u32::from_ne_bytes(src_addr.octets());
    s_addr.sin_port = src_port.to_be();

    unsafe {
        std::ptr::copy_nonoverlapping(
            &s_addr as *const _ as *const libc::c_void,
            addr as *mut _ as *mut libc::c_void,
            size.min(std::mem::size_of::<sockaddr_in>()),
        );
    };
}

/// Fill the `addr` with the address particulars. `size` is the size of the
/// sockaddr structure to be filled (used as our upper bound for the copy).
pub unsafe fn ipv6addr_to_sockaddr(
    src_addr: Ipv6Addr,
    src_port: u16,
    addr: &mut libc::sockaddr_in6,
    size: usize,
) {
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
            size.min(std::mem::size_of::<sockaddr_in6>()),
        );
    };
}
