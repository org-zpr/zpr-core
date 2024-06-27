use std::time::{Duration, Instant};
use tokio::sync::oneshot::{Sender, Receiver, channel};

#[derive(Debug)]
pub struct TestPacket {
    time: Instant,
    sender: Sender<TestPacketMetrics>,
}

#[derive(Debug)]
pub struct TestPacketMetrics {
    pub in_queue: Duration,
    pub queue_depth: usize,
}

impl TestPacket {
    pub fn create() -> (TestPacket, Receiver<TestPacketMetrics>) {
        let (sender, receiver) = channel::<TestPacketMetrics>();
        let time = Instant::now();
        let t_pkt = TestPacket { time, sender };

        (t_pkt, receiver)
    }

    pub fn acknowledge(self, queue_depth: usize) {
        let curr_time = Instant::now();
        let in_queue = curr_time.duration_since(self.time);
        
        let test_metrics = TestPacketMetrics { in_queue, queue_depth };

        let _ = self.sender.send(test_metrics);
    }

}