use bytes::buf;
use crate::sys::TunPi;

const TUN_PKT_STRIP: u16 = 0x0001;

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
            proto: u16::from_be_bytes(pi.proto),
        }
    }
}

impl From<TunPi> for TunPiImpl {
    fn from(pi: TunPi) -> TunPiImpl {
        TunPiImpl {
            flags: 0,
            proto: pi.proto.to_be_bytes(),
        }
    }
}

