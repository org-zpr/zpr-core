use pcap;
use std::mem::drop;
use tokio::sync::Mutex;

#[allow(dead_code)]
pub struct CaptureWorker {
    inner_cap: Mutex<InnerCap>,
}

#[allow(dead_code)]
struct InnerCap {
    capture: pcap::Capture<pcap::Dead>,
    savefile: Option<pcap::Savefile>,
}

#[allow(dead_code)]
impl CaptureWorker {
    pub fn new() -> Self {
        Self {
            inner_cap: InnerCap {
                capture: pcap::Capture::dead(pcap::Linktype(0)).unwrap(), // not sure what Linktype this should be
                savefile: None,
            }
            .into(),
        }
    }
    pub fn open_capture_file(&mut self, path: String) {
        self.inner_cap.get_mut().savefile =
            Some(self.inner_cap.get_mut().capture.savefile(path).unwrap())
    }

    pub fn flush_savefile(&mut self) -> Result<(), pcap::Error> {
        // self.savefile.get_mut().as_mut().unwrap().flush()
        self.inner_cap.get_mut().savefile.as_mut().unwrap().flush()
    }

    // Have to use .into_inner() here to get ownership of the savefile in order to drop it,
    // can't use get_mut() because calling drop() on a non-owned value does nothing.
    // Means can't use entire CaptureWorker struct after calling this function.
    pub fn destroy_savefile(self) {
        // drop(self.savefile);
        drop(self.inner_cap.into_inner().savefile)
    }
}
