use std::sync::atomic::{AtomicBool, Ordering};

pub struct FlowControl {
    copy_inbound_to_capture: AtomicBool,
    copy_outbound_to_capture: AtomicBool,
}

#[allow(dead_code)]
impl FlowControl {
    pub(crate) fn new() -> Self {
        Self {
            copy_inbound_to_capture: AtomicBool::new(false),
            copy_outbound_to_capture: AtomicBool::new(false),
        }
    }

    pub fn set_inbound(&self, val: bool) {
        self.copy_inbound_to_capture.store(val, Ordering::Relaxed);
    }

    pub fn get_inbound(&self) -> bool {
        self.copy_inbound_to_capture.load(Ordering::Relaxed)
    }

    pub fn set_outbound(&self, val: bool) {
        self.copy_outbound_to_capture.store(val, Ordering::Relaxed);
    }

    pub fn get_outbound(&self) -> bool {
        self.copy_outbound_to_capture.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_fc() {
        let fc = FlowControl::new();
        assert_eq!(fc.get_inbound(), false);
        assert_eq!(fc.get_outbound(), false);
    }

    #[test]
    fn test_new_fc_reverse() {
        let fc = FlowControl::new();
        assert_eq!(fc.get_inbound(), false);
        fc.set_outbound(true);
        assert_eq!(fc.get_outbound(), true);
    }

    #[test]
    fn test_store_fc() {
        let fc = FlowControl::new();
        assert_eq!(fc.get_inbound(), false);
        assert_eq!(fc.get_outbound(), false);

        fc.set_inbound(false);
        assert_eq!(fc.get_inbound(), false);
        assert_eq!(fc.get_outbound(), false);

        fc.set_inbound(true);
        assert_eq!(fc.get_inbound(), true);
        assert_eq!(fc.get_outbound(), false);
    }

    #[test]
    fn test_same_fc() {
        let fc = FlowControl::new();
        assert_eq!(fc.get_inbound(), false);
        assert_eq!(fc.get_outbound(), false);

        fc.set_inbound(true);
        fc.set_outbound(false);
        assert_eq!(fc.get_inbound(), true);
        assert_eq!(fc.get_outbound(), false);
    }
}
