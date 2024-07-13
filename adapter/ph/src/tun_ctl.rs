use crate::ext::tokio_tun::TunExt;
use std::io::Result;
use tokio_tun::Tun;

pub struct TunCtl<'a> {
    tun: &'a Tun,
}

impl<'a> TunCtl<'a> {
    pub fn new(tun: &'a Tun) -> Self {
        Self { tun }
    }

    pub fn set_carrier(&self, carrier: bool) -> Result<()> {
        self.tun.set_carrier(carrier)
    }
}
