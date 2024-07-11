use pcap;
use tokio::sync::Mutex;
pub const USER0: i32 = 147;
use std::path::Path;

pub struct CaptureWorker {
    inner_cap: Mutex<InnerCap>,
}

struct InnerCap {
    capture: pcap::Capture<pcap::Dead>,
    savefile: Option<pcap::Savefile>,
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
        let mut inner_cap = self.inner_cap.lock().await;
        inner_cap.savefile = Some(inner_cap.capture.savefile(path).unwrap());
    }

    pub async fn flush_capture_file(&self) -> Result<(), pcap::Error> {
        let sf = &mut self.inner_cap.lock().await.savefile;
        match sf {
            Some(ref mut sf) => sf.flush(),
            None => Ok(()),
        }
    }

    pub async fn destroy_capture_file(&self) {
        self.inner_cap.lock().await.savefile = None;
    }
}
