use crate::logging::targets::CAPTURE;
use crate::pcap_writer::*;
use crate::prelude::*;
use std::io;
use tokio::fs::File;
use tokio::net::UnixDatagram;
use tokio::sync::Mutex;

pub struct CaptureWorker {
    inner: Mutex<Inner>,
}

struct Inner {
    savefile: Option<PcapWriter<File>>,
}

impl CaptureWorker {
    pub fn new() -> Self {
        Self {
            inner: Inner { savefile: None }.into(),
        }
    }

    pub async fn open_capture_file(&self, file: File) -> Result<(), io::Error> {
        let mut inner = self.inner.lock().await;
        let mut savefile = PcapWriter::open(file, linktype::USER0).await?;
        savefile.flush().await?;
        inner.savefile = Some(savefile);
        Ok(())
    }

    pub async fn flush_capture_file(&self) -> Result<(), io::Error> {
        let savefile = &mut self.inner.lock().await.savefile;
        match savefile.as_mut() {
            Some(savefile) => savefile.flush().await,
            None => Ok(()),
        }
    }

    pub async fn close_capture_file(&self) -> Result<(), io::Error> {
        match self.inner.lock().await.savefile.take() {
            Some(savefile) => {
                savefile.close().await?;
            }
            None => (),
        }
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn query_savefile(&self) -> bool {
        self.inner.lock().await.savefile.is_some()
    }
}

#[derive(Copy, Clone)]
pub struct Config {
    #[allow(dead_code)]
    pub batch_size: usize,
}

pub async fn launch(_config: Config, asm: Arc<Assembly>, queue: UnixDatagram) {
    let mut buf = [0u8; config::PACKET_BUFFER_SIZE];

    // TODO: batch processing (only take lock once per batch)
    while let Ok(size) = queue.recv(&mut buf).await {
        let mut state = asm.capture_worker.inner.lock().await;

        if let Some(savefile) = state.savefile.as_mut() {
            // Write the packets out.  If the queue is empty, force a flush
            // to make sure these packets get written out in timely fashion.
            // TODO: use poll to determine queue emptiness
            match savefile_write_batch(savefile, &[&buf[..size]], true).await {
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
    }
}

async fn savefile_write_batch<'a>(
    savefile: &'a mut PcapWriter<File>,
    packets: &[&[u8]],
    force_flush: bool,
) -> io::Result<()> {
    for packet in packets {
        savefile.write_raw(packet).await?;
    }

    // Note, we don't actually care _when_ the flush completes, just that
    // we've kicked it off...  (akin to sync_file_range(SYNC_FILE_RANGE_WRITE))
    // but tokio provides no way to express this without launching a separate task.
    if force_flush {
        savefile.flush().await?;
    }

    Ok(())
}
