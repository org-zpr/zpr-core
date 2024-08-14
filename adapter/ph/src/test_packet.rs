use std::time::{Duration, Instant};
use tokio::sync::oneshot::{channel, Receiver, Sender};

#[derive(Debug)]
pub struct TestPacket {
    time: Instant,
    sender: Sender<TestPacketMetrics>,
}

#[derive(Debug)]
pub struct TestPacketMetrics {
    pub in_queue: Duration,
    pub queue_depth: usize,
    pub batch_size: usize,
}

impl TestPacket {
    /// Creates a TestPacket as well as the receiver corresponding to the sender
    /// stored in the TestPacket. Returns both the TestPacket and the Receiver
    pub fn create() -> (TestPacket, Receiver<TestPacketMetrics>) {
        let (sender, receiver) = channel::<TestPacketMetrics>();
        let time = Instant::now();
        let t_pkt = TestPacket { time, sender };

        (t_pkt, receiver)
    }

    /// Sends metrics of the TestPacket to the associated reciever
    pub fn acknowledge(self, queue_depth: usize, batch_size: usize) {
        let curr_time = Instant::now();
        let in_queue = curr_time.duration_since(self.time);

        let test_metrics = TestPacketMetrics {
            in_queue,
            queue_depth,
            batch_size,
        };

        let _ = self.sender.send(test_metrics);
    }
}
