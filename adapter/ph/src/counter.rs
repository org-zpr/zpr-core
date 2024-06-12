use std::sync::atomic::{AtomicU64, Ordering};

// Implement counter type used in the Assembly struct

pub struct Counter {
    number: AtomicU64
}

#[allow(dead_code)]
impl Counter {
    pub(crate) fn new() -> Self {
        Self { number: AtomicU64::new(0) }
    }

    pub(crate) fn reset(&self) {
        self.number.store(0, Ordering::Relaxed); // TODO ordering type
    }

    pub(crate) fn set(&self, value: u64) {
        self.number.store(value, Ordering::Relaxed); // TODO ordering type
    }

    pub(crate) fn increment(&self) {
        self.number.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn decrement(&self) {
        self.number.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn increase_by(&self, amount: u64) {
        self.number.fetch_add(amount, Ordering::Relaxed);
    }

    pub(crate) fn decrease_by(&self, amount: u64) {
        self.number.fetch_sub(amount, Ordering::Relaxed);
    }

    pub(crate) fn get_count(&self) -> u64 {
        self.number.load(Ordering::Relaxed) // TODO look for more elegant way to get value
                                                    // all the Atomic methods (that I could find) that get type are either
                                                    // mutable or "consume" the atomic value, which the compiler
                                                    // gets mad at
    }

    pub(crate) fn print(&self) {
        let count = self.number.load(Ordering::Relaxed);
        println!("count: {count}") //TODO change message and is println necessary? 
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_get_count() {
        let mut counter = Counter::new();
        assert_eq!(counter.get_count(), 0);
    }

    #[test]
    fn test_set() {
        let mut counter = Counter::new();
        counter.set(10);
        assert_eq!(counter.get_count(), 10);
    }

    #[test]
    fn test_increment() {
        let mut counter = Counter::new();
        counter.set(10);
        counter.increment();
        assert_eq!(counter.get_count(), 11);
        counter.increment();
        assert_eq!(counter.get_count(), 12);
    }

    #[test]
    fn test_decrement() {
        let mut counter = Counter::new();
        counter.set(10);
        counter.decrement();
        assert_eq!(counter.get_count(), 9);
        counter.decrement();
        assert_eq!(counter.get_count(), 8);
    }

    #[test]
    fn test_reset() {
        let mut counter = Counter::new();
        counter.set(7543);
        assert_eq!(counter.get_count(), 7543);
        counter.reset();
        assert_eq!(counter.get_count(), 0);
    }

    #[test]
    fn test_increase() {
        let mut counter = Counter::new();
        assert_eq!(counter.get_count(), 0);
        counter.increase_by(653546);
        assert_eq!(counter.get_count(), 653546);
    }

    #[test]
    fn test_decrease() {
        let mut counter = Counter::new();
        counter.set(975467);
        assert_eq!(counter.get_count(), 975467);
        counter.decrease_by(4543);
        assert_eq!(counter.get_count(), 970924);

    }

}