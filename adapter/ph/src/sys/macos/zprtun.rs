use crate::zprtun::ZPRTunError;
use bytes::buf;
use tun::AsyncDevice;
use zpr_ext::std::mem::slice_assume_init_mut;

pub struct ZprTun(tun::AsyncDevice);

impl From<AsyncDevice> for ZprTun {
    fn from(tun_device: AsyncDevice) -> Self {
        ZprTun(tun_device)
    }
}

impl From<tun::Error> for ZPRTunError {
    fn from(e: tun::Error) -> Self {
        ZPRTunError::PlatformError(e.to_string())
    }
}

impl ZprTun {
    /// Create a new TUN device.
    /// If `ifname` is `None`, the kernel will automatically assign a name.
    /// On macOS if the name is specificed, it must be of the form `utun[0-9]+`.
    pub fn new_mq(
        ifname: Option<String>,
        concurrency: usize,
    ) -> std::result::Result<Vec<Self>, ZPRTunError> {
        let mut config = tun::Configuration::default();
        if let Some(name) = ifname {
            config = config.tun_name(&name).to_owned();
        }
        if concurrency <= 0 || concurrency > 1 {
            return Err(ZPRTunError::PlatformError(String::from(
                "on macos concurrency (queues) must be 1",
            )));
        }

        let dev = tun::create_as_async(&config)?;

        Ok(vec![ZprTun::from(dev)])
    }

    pub async fn recv_buf<B: buf::BufMut>(&self, buf: &mut B) -> std::io::Result<usize> {
        let uninit_slice = buf.chunk_mut();
        // SAFETY: we are only writing to this uninitialized slice
        let slice = unsafe { slice_assume_init_mut(uninit_slice.as_uninit_slice_mut()) };
        let size = self.0.recv(slice).await?;
        // SAFETY: we've now initialized this much of the slice
        unsafe {
            buf.advance_mut(size);
        }
        Ok(size)
    }

    pub fn try_send(&self, _buf: &[u8]) -> std::io::Result<usize> {
        let idev = &*(self.0);
        idev.send(_buf)
    }

    /// A NOP on mac.
    pub fn set_carrier(&self, _carrier: bool) -> std::io::Result<()> {
        Ok(())
    }
}
