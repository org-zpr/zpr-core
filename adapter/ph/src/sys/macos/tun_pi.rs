use bytes::buf;

/// per-packet packet info
#[derive(Clone, Copy)]
pub struct TunPi {
    /// True if the inbound packet was truncated (ignored outbound)
    pub strip: bool,
    /// Ethertype of packet
    pub proto: u16,
}

impl TunPi {
    /// The size of a per-packet packet info structure.
    /// On macos this is `0`.
    ///
    /// TODO: Needs more exploration. The rust-tun code documents that there is PI
    /// on macos, but our tests reading into buffers do not see it.
    pub const PI_SIZE: usize = 0;

    /// Since macos does not provide packet info, we just return a
    /// [TunPi] here with `strip = false` and `proto = 0`.
    pub fn read_pi<B: buf::Buf>(_buf: &mut B) -> TunPi {
        TunPi {
            strip: false,
            proto: 0,
        }
    }

    /// Write per-packet packet info into a `BufMut`.
    /// Since macos does not support packet info this does nothing.
    pub fn write_pi<B: buf::BufMut>(_buf: &mut B, _pi: TunPi) {}
}
