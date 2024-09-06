use crate::packet::Packet;
use crate::zdp;
use std::sync::{Arc, Mutex};
use tokio::sync::{oneshot::Sender, Semaphore};

pub struct SyncReqState<'pktbuf> {
    inner_req: Mutex<SyncReqInnerState<'pktbuf>>,
    pub semaphore: Arc<Semaphore>,
}

struct SyncReqInnerState<'pktbuf> {
    reply_channel: Option<Sender<(Packet<'pktbuf>, zdp::ZdpPacketType)>>,
}

impl<'pktbuf> SyncReqState<'pktbuf> {
    pub fn new() -> Self {
        Self {
            inner_req: SyncReqInnerState {
                reply_channel: None,
            }
            .into(),
            semaphore: Arc::new(Semaphore::new(1)),
        }
    }
    pub fn get_sender(&self) -> Option<Sender<(Packet<'pktbuf>, zdp::ZdpPacketType)>> {
        self.inner_req.lock().unwrap().reply_channel.take()
    }

    pub fn set_sender(&self, sender: Option<Sender<(Packet<'pktbuf>, zdp::ZdpPacketType)>>) {
        let mut inner_req = self.inner_req.lock().unwrap();
        inner_req.reply_channel = sender;
    }
}

pub enum SyncReqError {
    LinkClosed,
    ProtocolError,
    Timeout,
}

impl std::fmt::Display for SyncReqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str(match self {
            Self::LinkClosed => "link closed",
            Self::ProtocolError => "protocol error",
            Self::Timeout => "timeout",
        })
    }
}
