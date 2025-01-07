use crate::assembly::Assembly;
use crate::logging::targets::CAPTURE;
use crate::pcap_writer::*;
use crate::queues::CapPacket;
use std::io;
use std::sync::Arc;
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
        let mut savefile = PcapWriter::open(file, linktype::USER0).await?;
        savefile.flush().await?;
        inner_cap.savefile = Some(savefile);
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

pub async fn launch(config: Config, asm: Arc<Assembly>, mut queue: mpsc::Receiver<CapPacket>) {
    let mut messages = Vec::new();

    // Batch accepts values from capture queue and writes them to the savefile
    while let _count @ 1.. = queue.recv_many(&mut messages, config.batch_size).await {
        let mut state = asm.capture_worker.inner_cap.lock().await;

        match &mut state.savefile {
            Some(ref mut savefile) => {
                // Write the packets out.  If the queue is empty, force a flush
                // to make sure these packets get written out in timely fashion.
                match savefile_write_batch(savefile, messages.iter(), queue.is_empty()).await {
                    Ok(()) => (),

                    Err(err) => {
                        error!(target: CAPTURE, "Error writing to capture file, ending capture: {}", err);
                        match state.savefile.take().unwrap().close().await {
                            Ok(_file) => (),
                            Err(err) => {
                                error!(target: CAPTURE, "Error closing capture file: {}", err)
                            }
                        }
                    }
                }
            }

            None => (),
        }

        asm.buffer_stack.put_buffers(
            messages
                .drain(..)
                .map(|cap_pack| cap_pack.packet.destroy().try_into().unwrap()),
        );
    }
}

async fn savefile_write_batch<'a>(
    savefile: &'a mut PcapWriter<File>,
    cap_packs: impl IntoIterator<Item = &'a CapPacket>,
    force_flush: bool,
) -> io::Result<()> {
    for cap_pack in cap_packs.into_iter() {
        savefile_write(savefile, cap_pack).await?;
    }

    // Note, we don't actually care _when_ the flush completes, just that
    // we've kicked it off...  (akin to sync_file_range(SYNC_FILE_RANGE_WRITE))
    // but tokio provides no way to express this without launching a separate task.
    if force_flush {
        savefile.flush().await?;
    }

    Ok(())
}

async fn savefile_write(savefile: &mut PcapWriter<File>, cap_pack: &CapPacket) -> io::Result<()> {
    let packet = PcapPacket {
        timestamp: cap_pack.timestamp,
        orig_len: cap_pack.orig_len,
        data: cap_pack.packet.body(),
    };

    savefile.write(&packet).await
}
