use std::time::{Duration, Instant};
use tokio::sync::oneshot::{Sender, Receiver, channel};

// #[derive(Copy)]
pub struct TestPacket {
    time: Instant,
    sender: Sender<TestPacketMetrics>,
}

pub struct TestPacketMetrics {
    pub in_queue: Duration,
    pub queue_depth: usize,
}

impl TestPacket {
    pub fn create() -> (TestPacket, Receiver<TestPacketMetrics>) {
        let (sender, receiver) = channel();
        let time = Instant::now();
        let t_pkt = TestPacket { time, sender };

        (t_pkt, receiver)
    }

    pub fn acknowledge(self, queue_depth: usize) {
        let in_queue = self.time - Instant::now();

        let test_metrics = TestPacketMetrics { in_queue, queue_depth };

        let _ = self.sender.send(test_metrics);
    }

}