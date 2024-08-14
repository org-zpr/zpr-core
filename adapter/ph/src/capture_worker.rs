use crate::assembly::Assembly;
use crate::pcap_writer::*;
use crate::queues::CapPacket;
use core::future::Future;
use std::io;
use tokio::fs::File;
use tokio::sync::{mpsc, Mutex};

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
        let sf = &mut self.inner_cap.lock().await.savefile;
        match sf {
            Some(ref mut sf) => sf.flush().await,
            None => Ok(()),
        }
    }

    pub async fn close_capture_file(&self) -> Result<(), io::Error> {
        match self.inner_cap.lock().await.savefile.take() {
            Some(writer) => {
                writer.close().await?;
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
        let mut locked_mutex = asm.capture_worker.inner_cap.lock().await;
        match &mut locked_mutex.savefile {
            Some(s_file) => {
                for cap_pack in &messages {
                    savefile_write(cap_pack, s_file).await;
                }
            }
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

async fn savefile_write(cap_pack: &CapPacket<'_>, savefile: &mut PcapWriter<File>) {
    let packet = PcapPacket {
        timestamp: cap_pack.timestamp,
        orig_len: cap_pack.orig_len,
        data: cap_pack.packet.body(),
    };

    // FIXME: handle write errors (maybe close the capture file?)
    savefile.write(&packet).await.unwrap();
}
