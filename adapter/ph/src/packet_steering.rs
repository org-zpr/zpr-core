//! OS-level control of steering packets into sockets.

use std::net::UdpSocket;
use zpr::packet_info::ZPI_ENCRYPTED_HEADER_FLAG;

#[allow(dead_code)]
pub enum SteeringMethod {
    OsDefault,
    PacketHash,
    ZdpStreamId,
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
mod os_impl {
    use super::*;
    use std::io;

    pub fn set_steering(
        _sock: &UdpSocket,
        _num_queues: usize,
        method: SteeringMethod,
    ) -> std::io::Result<()> {
        match method {
            SteeringMethod::OsDefault => Ok(()),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "packet steering not supported on this OS",
            )),
        }
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
mod os_impl {
    use super::*;
    use crate::zdp;
    use cbpf_rs::bpf_code::*;
    use libc::sock_filter as sf;
    use std::io;
    use std::mem::{offset_of, size_of};
    use zpr_ext::std::net::UdpSocketExt;

    pub fn set_steering(
        sock: &UdpSocket,
        num_queues: usize,
        method: SteeringMethod,
    ) -> io::Result<()> {
        match method {
            SteeringMethod::OsDefault | SteeringMethod::PacketHash => {
                sock.attach_reuse_port_cbpf(&[
                    // Default on Linux is hash-based.

                    // As far as I can tell there's no way to "unattach" a filter,
                    // but setting a filter which always returns an out-of-bounds index
                    // is sufficient.

                    // [0] return huge value to force fallback to hash-based steering
                    sf {
                        code: RET | K,
                        jt: 0,
                        jf: 0,
                        k: u32::MAX,
                    },
                ])
            }

            SteeringMethod::ZdpStreamId => sock.attach_reuse_port_cbpf(&[
                // TODO/FIXME: Ideally we want to select the queue by the _sum_ of the
                // hash and stream ID, thus avoiding clumping due to correlated stream IDs between
                // links.  That requires eBPF though, since the hash value is only present for
                // eBPF programs (see <https://github.com/torvalds/linux/blob/master/net/core/sock_reuseport.c#L595-L598>).
                // (`[SKF_AD_RXHASH]` just reads as 0!)

                // [0] load ZPI (upper 8 bits) and packet type (lower 8 bits)
                sf {
                    code: LD | H | ABS,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                // [1] if packet is encrypted, or packet is non-flow, fall back to hash
                sf {
                    code: JMP | JSET | K,
                    jt: 5,
                    jf: 0,
                    k: ((ZPI_ENCRYPTED_HEADER_FLAG as u32) << 8)
                        | zdp::ZDP_PACKET_TYPE_NON_FLOW_FLAG as u32,
                },
                // [2] load stream ID, assuming this is a transit packet (no MgmtHeader)
                sf {
                    code: LD | W | ABS,
                    jt: 0,
                    jf: 0,
                    k: (size_of::<zdp::ZdpZpiHeader>()
                        + size_of::<zdp::ZdpBaseHeader>()
                        + offset_of!(zdp::ZdpPerFlowHeader, stream_id))
                        as u32,
                },
                // [3] if this is in fact a transit packet, we're good, else...
                sf {
                    code: JMP | JEQ | K,
                    jt: 1,
                    jf: 0,
                    k: zdp::ZdpPacketType::TransitPacket.0 as u32,
                },
                // [4] this is a mgmt packet, reload stream ID from the correct location (after MgmtHeader)
                sf {
                    code: LD | W | ABS,
                    jt: 0,
                    jf: 0,
                    k: (size_of::<zdp::ZdpZpiHeader>()
                        + size_of::<zdp::ZdpBaseHeader>()
                        + size_of::<zdp::ZdpMgmtHeader>()
                        + offset_of!(zdp::ZdpPerFlowHeader, stream_id))
                        as u32,
                },
                // [5] modulo # of queues
                sf {
                    code: ALU | MOD | K,
                    jt: 0,
                    jf: 0,
                    k: num_queues as u32,
                },
                // [6] return as selected queue #
                sf {
                    code: RET | A,
                    jt: 0,
                    jf: 0,
                    k: 0,
                },
                // [7] return huge value to force fallback to hash-based steering
                sf {
                    code: RET | K,
                    jt: 0,
                    jf: 0,
                    k: u32::MAX,
                },
            ]),
        }
    }
}

pub use os_impl::*;
