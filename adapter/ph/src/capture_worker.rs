use crate::assembly::Assembly;
use crate::pcap_writer::*;
use crate::queues::CapPacket;
use core::future::Future;
use std::io;
use tokio::fs::File;
use tokio::sync::{mpsc, Mutex};
use tracing::error;

pub struct CaptureWorker {
    inner_cap: Mutex<InnerCap>,
}

struct InnerCap {
    savefile: Option<PcapWriter<File>>,
}

impl CaptureWorker {
    pub fn new() -> Self {
        Self {
            inner_cap: InnerCap { savefile: None }.into(),
        }
    }

    pub async fn open_capture_file(&self, file: File) -> Result<(), io::Error> {
        let mut inner_cap = self.inner_cap.lock().await;
        inner_cap.savefile = Some(PcapWriter::open(file, linktype::USER0).await?);
        Ok(())
    }

    pub async fn flush_capture_file(&self) -> Result<(), io::Error> {
        let savefile = &mut self.inner_cap.lock().await.savefile;
        match savefile {
            Some(ref mut savefile) => savefile.flush().await,
            None => Ok(()),
        }
    }

    pub async fn close_capture_file(&self) -> Result<(), io::Error> {
        match self.inner_cap.lock().await.savefile.take() {
            Some(savefile) => {
                savefile.close().await?;
            }
            None => (),
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn query_savefile(&self) -> bool {
        self.inner_cap.lock().await.savefile.is_some()
    }
}

#[derive(Copy, Clone)]
pub struct Config {
    pub batch_size: usize,
}

async fn worker<'pktbuf>(
    config: &Config,
    asm: &Assembly<'pktbuf>,
    queue: &mut mpsc::Receiver<CapPacket<'pktbuf>>,
) {
    let mut messages = Vec::new();

    // Batch accepts values from capture queue and writes them to the savefile
    while let _count @ 1.. = queue.recv_many(&mut messages, config.batch_size).await {
        let mut inner_cap = asm.capture_worker.inner_cap.lock().await;
        match &mut inner_cap.savefile {
            Some(ref mut savefile) => match savefile_write_batch(savefile, messages.iter()).await {
                Ok(()) => (),
                Err(err) => {
                    error!("Error writing to capture file, ending capture: {}", err);
                    match inner_cap.savefile.take().unwrap().close().await {
                        Ok(_file) => (),
                        Err(err) => error!("Error closing capture file: {}", err),
                    }
                }
            },
            None => (),
        }
        asm.buffer_stack
            .put_buffers(messages.drain(..).map(|cap_pack| cap_pack.packet.destroy()));
    }
}

pub fn launch<'pktbuf, AsmRef: 'pktbuf>(
    config: &Config,
    asm: AsmRef,
    mut queue: mpsc::Receiver<CapPacket<'pktbuf>>,
) -> impl Future<Output = ()> + Send + 'pktbuf
where
    AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
{
    let cfg = *config;
    async move { worker(&cfg, &*asm, &mut queue).await }
}

async fn savefile_write_batch<'a, 'b: 'a>(
    savefile: &'a mut PcapWriter<File>,
    cap_packs: impl IntoIterator<Item = &'a CapPacket<'b>>,
) -> io::Result<()> {
    for cap_pack in cap_packs.into_iter() {
        savefile_write(savefile, cap_pack).await?;
    }

    Ok(())
}

async fn savefile_write(
    savefile: &mut PcapWriter<File>,
    cap_pack: &CapPacket<'_>,
) -> io::Result<()> {
    let packet = PcapPacket {
        timestamp: cap_pack.timestamp,
        orig_len: cap_pack.orig_len,
        data: cap_pack.packet.body(),
    };

    savefile.write(&packet).await
}
