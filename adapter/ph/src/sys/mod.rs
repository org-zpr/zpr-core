#[cfg(target_os = "linux")]
pub(crate) mod linux;
#[cfg(target_os = "linux")]
pub use self::linux::TunPi;
#[cfg(target_os = "linux")]
pub use self::linux::ZprTun;

#[cfg(target_os = "macos")]
pub(crate) mod macos;
#[cfg(target_os = "macos")]
pub use self::macos::TunPiImpl;
#[cfg(target_os = "macos")]
pub use self::macos::ZprTun;


pub(crate) mod posix;
pub use self::posix::notify;

use bytes::buf;

/// per-packet packet info
#[derive(Clone, Copy)]
pub struct TunPi {
    // the inbound packet was truncated (ignored outbound)
    pub strip: bool,
    /// Ethertype of packet
    pub proto: u16,
}

// The TunPi uses the linux flavor of packet info; the "proto" field is the ethertype.
pub const TUN_PI_ETH_P_IP: u16 = 0x0800;
pub const TUN_PI_ETH_P_IPV6: u16 = 0x86dd;

impl TunPi {
    /// The size of a per-packet packet info structure.
    pub const PI_SIZE: usize = std::mem::size_of::<TunPiImpl>();

    /// Read per-packet packet info from a `Buf`.
    pub fn read_pi<B: buf::Buf>(buf: &mut B) -> TunPi {
        let mut os_pi = std::mem::MaybeUninit::<TunPiImpl>::uninit();
        let slice = os_pi.as_mut_ptr();
        buf.copy_to_slice(unsafe {
            /* SAFETY: we immediately initialize */
            std::slice::from_raw_parts_mut(slice as *mut u8, TunPi::PI_SIZE)
        });
        unsafe {
            /* SAFETY: was just initialized */
            os_pi.assume_init()
        }
        .into()
    }

    /// Write per-packet packet info into a `BufMut`.
    pub fn write_pi<B: buf::BufMut>(buf: &mut B, pi: TunPi) {
        let os_pi: TunPiImpl = pi.into();
        buf.put(unsafe {
            /* SAFETY: we are reading exactly the structure */
            std::slice::from_raw_parts((&os_pi as *const _) as *const u8, TunPi::PI_SIZE)
        });
    }
}
