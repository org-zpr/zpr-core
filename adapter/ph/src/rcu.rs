#![allow(dead_code)]
//! Wrapper for RCU-"ish" functionality (<https://en.wikipedia.org/wiki/Read-copy-update>)
//!
//! This API is deliberately minimal, to restrict via what functionality
//! we couple ourselves to a given RCU-like implementation.
//!
//! The capability expected of an RCU implementation, beyond what the API
//! directly implies, is as follows.  Writes need not be efficient, but must
//! not block reads, but should eventually complete even under contention.
//! Reads must be very efficient and not contend with each other.
//! Garbage collection should be performed by the writer, not the reader.
//!
//! Multiple implementations are provided, since it's not clear which is
//! best yet.  A couple simple std-only implementations are also provided,
//! which do not meet the above performance requirements, but are useful
//! for testing.  The active implementation is selected by a feature flag.

#![allow(dead_code)]

#[cfg(all(
    feature = "rcu-rwlock",
    feature = "rcu-mutex-arc",
    feature = "rcu-crossbeam-epoch",
    feature = "rcu-aarc"
))]
compile_error!("exactly one rcu-* feature must be selected");

#[cfg(not(any(
    feature = "rcu-rwlock",
    feature = "rcu-mutex-arc",
    feature = "rcu-crossbeam-epoch",
    feature = "rcu-aarc"
)))]
compile_error!("exactly one rcu-* feature must be selected");

#[cfg(feature = "rcu-rwlock")]
mod rcu_impl {
    use std::sync::RwLock;

    /// An RCU-protected box.
    pub struct RcuBox<T>(RwLock<T>);

    impl<T> RcuBox<T> {
        /// Create a new box containing the given value.
        pub fn new(value: T) -> Self {
            Self(RwLock::new(value))
        }

        /// Provide protected read access to the latest version of the
        /// boxed value to the given function, whose result is returned.
        pub fn inspect<U>(&self, f: impl FnOnce(&T) -> U) -> U {
            f(&*self.0.read().unwrap())
        }

        /// Replace the boxed value with a new value.  The old value
        /// will be destructed once all readers have completed.
        pub fn write(&self, new_value: T) {
            let mut lock = self.0.write().unwrap();
            let old = std::mem::replace(&mut *lock, new_value);
            std::mem::drop(lock);
            std::mem::drop(old);
        }
    }
}

#[cfg(feature = "rcu-mutex-arc")]
mod rcu_impl {
    use std::sync::{Arc, Mutex};

    pub struct RcuBox<T>(Mutex<Arc<T>>);

    impl<T> RcuBox<T> {
        pub fn new(value: T) -> Self {
            Self(Mutex::new(Arc::new(value)))
        }

        pub fn inspect<U>(&self, f: impl FnOnce(&T) -> U) -> U {
            let lock = self.0.lock().unwrap();
            let arc = lock.clone();
            std::mem::drop(lock);
            f(&*arc)
        }

        pub fn write(&self, new_value: T) {
            let mut lock = self.0.lock().unwrap();
            let old = std::mem::replace(&mut *lock, Arc::new(new_value));
            std::mem::drop(lock);
            std::mem::drop(old);
        }
    }
}

#[cfg(feature = "rcu-crossbeam-epoch")]
mod rcu_impl {
    use crossbeam_epoch as epoch;
    use std::sync::atomic::Ordering;

    pub struct RcuBox<T>(epoch::Atomic<T>);

    impl<T> RcuBox<T> {
        pub fn new(value: T) -> Self {
            Self(epoch::Atomic::new(value))
        }

        pub fn inspect<U>(&self, f: impl FnOnce(&T) -> U) -> U {
            let guard = epoch::pin();
            let ptr = self.0.load(Ordering::Acquire, &guard);
            // SAFETY: we only allow readers to access "live" values
            let ref_ = unsafe { ptr.deref() };
            f(ref_)
        }

        pub fn write(&self, new_value: T) {
            let guard = epoch::pin();
            let old_value = self
                .0
                .swap(epoch::Owned::from(new_value), Ordering::AcqRel, &guard);
            // SAFETY: `old_value` is now unreachable
            unsafe {
                guard.defer_destroy(old_value);
            }
        }
    }
}

#[cfg(feature = "rcu-aarc")]
mod rcu_impl {
    pub struct RcuBox<T: 'static>(aarc::AtomicArc<T>);

    impl<T> RcuBox<T> {
        pub fn new(value: T) -> Self {
            Self(aarc::AtomicArc::new(Some(value)))
        }

        pub fn inspect<U>(&self, f: impl FnOnce(&T) -> U) -> U {
            f(&*self.0.load::<aarc::Snapshot<_>>().unwrap())
        }

        pub fn write(&self, new_value: T) {
            // NOTE: it's not clear from aarc docs in which threads GC is allowed;
            // if in `load()` threads, this would be a deal-breaker
            self.0.store(Some(&std::sync::Arc::new(new_value)))
        }
    }
}

// NOTE: left-right looked promising, but `ReadHandle` is not `Sync`,
// so we'd have to create a thread-local variable for each `RcuBox`,
// which just becomes a ton of overhead.

// NOTE: haphazard also looked promising, but requires that
// the pointed-to data is `Sync`, which is basically a nonstarter.

// NOTE: urcu looked promising, but didn't compile.

pub use rcu_impl::*;

impl<T: Clone> RcuBox<T> {
    /// Clone the value in the box.
    pub fn clone_inner(&self) -> T {
        self.inspect(|item| item.clone())
    }
}

impl<T: Copy> RcuBox<T> {
    /// Read a copy of the value in the box.
    pub fn read(&self) -> T {
        self.inspect(|item| *item)
    }
}

impl<T: Default> Default for RcuBox<T> {
    /// Creates a new box containing the boxed value type's default value.
    fn default() -> Self {
        Self::new(Default::default())
    }
}

impl<T> From<T> for RcuBox<T> {
    /// Creates a new box from the given value.  Same as `RcuBox::new()`.
    fn from(value: T) -> Self {
        Self::new(value)
    }
}
