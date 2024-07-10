use crate::assembly::Assembly;
use crate::CapPacket;
use core::future::Future;
use libc::timeval;
use pcap::{Capture, Dead, Error, Linktype, Packet, PacketHeader, Savefile};
use std::mem::drop;
use std::time::{Duration, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::sync::Mutex;
pub const USER0: i32 = 147;
use std::path::Path;

pub struct CaptureWorker {
    inner_cap: Mutex<InnerCap>,
}

struct InnerCap {
    capture: Capture<Dead>,
    savefile: Option<Savefile>,
}

#[allow(dead_code)]
impl CaptureWorker {
    pub fn new() -> Self {
        Self {
            inner_cap: InnerCap {
                capture: pcap::Capture::dead(pcap::Linktype(USER0)).unwrap(), // not sure what Linktype this should be
                savefile: None,
            }
            .into(),
        }
    }
    pub async fn open_capture_file(&self, path: &Path) {
        self.inner_cap.lock().await.savefile =
            Some(self.inner_cap.lock().await.capture.savefile(path).unwrap())
    }

    pub async fn flush_capture_file(&self) -> Result<(), Error> {
        self.inner_cap
            .lock()
            .await
            .savefile
            .as_mut()
            .unwrap()
            .flush()
    }

    pub async fn destroy_capture_file(&self) {
        self.inner_cap.lock().await.savefile = None;
    }
}
#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize,
}

#[allow(dead_code)]
async fn worker<'pktbuf>(
    config: &Config,
    asm: &Assembly<'pktbuf>,
    queue: &mut mpsc::Receiver<CapPacket<'pktbuf>>,
    path: String,
) {
    let mut messages = Vec::new();
    let mut savefile_exists = false;

    if asm.capture_worker.inner_cap.lock().await.savefile.is_some() {
        asm.capture_worker.open_capture_file(path).await;
        savefile_exists = true;
    }

    while let _count @ 1.. = queue.recv_many(&mut messages, config.batch_size).await {
        for cap_pack in &messages {
            if savefile_exists {
                savefile_write(
                    cap_pack,
                    asm.capture_worker
                        .inner_cap
                        .lock()
                        .await
                        .savefile
                        .as_mut()
                        .unwrap(),
                )
            }
        }
        asm.buffer_stack
            .put_buffers(messages.drain(..).map(|cap_pack| cap_pack.packet.destroy()));
    }
}

#[allow(dead_code)]
pub fn launch<'pktbuf, AsmRef: 'pktbuf>(
    config: &Config,
    asm: AsmRef,
    mut queue: mpsc::Receiver<CapPacket<'pktbuf>>,
    path: String,
) -> impl Future<Output = ()> + Send + 'pktbuf
where
    AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &mut queue, path).await }
}

#[allow(dead_code)]
fn savefile_write(cap_pack: &CapPacket, savefile: &mut Savefile) {
    let creation_time: Duration = cap_pack.timestamp.duration_since(UNIX_EPOCH).unwrap();
    let ts: timeval = timeval {
        tv_sec: creation_time.as_secs() as i64,
        tv_usec: creation_time.subsec_micros() as i64,
    };

    let header: PacketHeader = PacketHeader {
        ts,
        caplen: cap_pack.packet.body().len() as u32, // not sure if this is the right value, perhaps should be cap_pack.packet.metadata().len
        len: cap_pack.packet.body().len() as u32,
    };

    let packet: Packet = Packet {
        header: &header,
        data: cap_pack.packet.body(),
    };

    savefile.write(&packet);
}
