use pcap;
use tokio::sync::Mutex;
use std::mem::drop;

pub struct CaptureWorker {
    capture: pcap::Capture<pcap::Dead>,
    savefile: Mutex<Option<pcap::Savefile>>,
}

impl CaptureWorker {

    pub fn open_capture_file(&mut self, path: String) {
        self.savefile = Mutex::new(Some(self.capture.savefile(path).unwrap()));
    }

    pub fn flush_savefile(&mut self) -> Result<(), pcap::Error> {
        self.savefile.get_mut().as_mut().unwrap().flush()
    }

    pub fn destroy_savefile(self) {
        drop(self.savefile);
    }
}