use crate::sys::TunPi;
use libc::{AF_INET, AF_INET6};

// TODO: I have not confirmed that the packet info FLAGS field is the same as linux.
// Assuming it is for now.
const TUN_PKT_STRIP: u16 = 0x0001;

// 16 bit versions of the libc constants.
const PI_AF_INET: u16 = AF_INET as u16;
const PI_AF_INET6: u16 = AF_INET6 as u16;

// The TunPi uses the linux flavor of packet info; the "proto" field is the ethertype.
const TUN_PI_ETH_P_IP: u16 = 0x0800;
const TUN_PI_ETH_P_IPV6: u16 = 0x86dd;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TunPiImpl {
    flags: u16,
    proto: [u8; 2],
}

impl From<TunPiImpl> for TunPi {
    fn from(pi: TunPiImpl) -> TunPi {
        TunPi {
            strip: pi.flags & TUN_PKT_STRIP != 0,
            proto: {
                let plat_pi = u16::from_be_bytes(pi.proto);
                if plat_pi == PI_AF_INET {
                    TUN_PI_ETH_P_IP
                } else if plat_pi == PI_AF_INET6 {
                    TUN_PI_ETH_P_IPV6
                } else {
                    // Choosing not to barf here and just let the next layer sort it out.
                    plat_pi
                }
            },
        }
    }
}

impl From<TunPi> for TunPiImpl {
    fn from(pi: TunPi) -> TunPiImpl {
        TunPiImpl {
            flags: 0,
            proto: if pi.proto == TUN_PI_ETH_P_IP {
                PI_AF_INET.to_be_bytes()
            } else if pi.proto == TUN_PI_ETH_P_IPV6 {
                PI_AF_INET6.to_be_bytes()
            } else {
                panic!("PI write expects IPv4 or IPv6 packet");
            },
        }
    }
}
