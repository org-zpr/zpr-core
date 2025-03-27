pub mod scalar {
    //! Types in this module are "single-threaded atomics".
    //!
    //! Like other cell types, they provide dynamic enforcement of Rust's
    //! ownership rules, within a single thread.
    //!
    //! Unlike other cell types, they are limited to fixed operations on
    //! integral types, but have practically no overhead.
    //!
    //! Like atomic types, they provide mutable access via a shared reference.
    //!
    //! Unlike atomic types, they are not `Sync`, but have less overhead and
    //! a simpler API.

    use std::cell::RefCell;
    use std::marker::PhantomData;
    use std::sync::atomic::*;

    pub struct UsizeCell(AtomicUsize, PhantomData<RefCell<usize>>);

    impl UsizeCell {
        pub const fn new(val: usize) -> Self {
            Self(AtomicUsize::new(val), PhantomData)
        }

        pub const fn into_inner(self) -> usize {
            self.0.into_inner()
        }

        pub fn load(&self) -> usize {
            self.0.load(Ordering::Relaxed)
        }

        pub fn store(&self, val: usize) {
            self.0.store(val, Ordering::Relaxed)
        }

        pub fn fetch_add(&self, val: usize) -> usize {
            let old = self.load();
            self.store(old.wrapping_add(val));
            old
        }

        pub fn fetch_sub(&self, val: usize) -> usize {
            let old = self.load();
            self.store(old.wrapping_sub(val));
            old
        }

        pub fn fetch_add_nowrap(&self, val: usize) -> usize {
            let old = self.load();
            self.store(old + val);
            old
        }

        pub fn fetch_sub_nowrap(&self, val: usize) -> usize {
            let old = self.load();
            self.store(old - val);
            old
        }
    }
}
