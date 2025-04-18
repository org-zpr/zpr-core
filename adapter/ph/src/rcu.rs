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

#[cfg(any(feature = "rcu-rwlock", doc))]
mod rcu_impl {
    use std::sync::{RwLock, RwLockReadGuard};

    /// An RCU-protected box.
    pub struct RcuBox<T>(RwLock<T>);

    /// A protected reference to the item in an RCU-protected box.
    pub struct RcuGuard<'a, T>(RwLockReadGuard<'a, T>);

    impl<T> std::ops::Deref for RcuGuard<'_, T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            self.0.deref()
        }
    }

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

        /// Get a protected reference to the latest version of the boxed value.
        pub fn get(&self) -> RcuGuard<'_, T> {
            RcuGuard(self.0.read().unwrap())
        }

        /// Replace the boxed value with a new value.  The old value
        /// will be destructed once all readers have completed.
        pub fn write(&self, new_value: T) {
            let mut lock = self.0.write().unwrap();
            let old = std::mem::replace(&mut *lock, new_value);
            std::mem::drop(lock);
            std::mem::drop(old);
        }

        /// Replace the boxed value with a new value, which
        /// may be derived from the old value.  Calls to `update()`
        /// are totally ordered.  That is, behaves as `self.write(self.inspect(f))`
        /// but without the possibility of a lost update.
        ///
        /// If the update function returns `None`, no update is made, and an
        /// error is returned.  Otherwise, this method succeeds.
        ///
        /// Note also that unlike `inspect()`, `f` may be called repeatedly.
        pub fn update(&self, f: impl Fn(&T) -> Option<T>) -> Result<(), ()> {
            let mut lock = self.0.write().unwrap();
            let Some(new_value) = f(&*lock) else {
                return Err(());
            };
            let old = std::mem::replace(&mut *lock, new_value);
            std::mem::drop(lock);
            std::mem::drop(old);
            Ok(())
        }
    }
}

#[cfg(all(feature = "rcu-mutex-arc", not(doc)))]
mod rcu_impl {
    use std::sync::{Arc, Mutex};

    pub struct RcuBox<T>(Mutex<Arc<T>>);

    pub struct RcuGuard<'a, T> {
        phantom: std::marker::PhantomData<&'a T>,
        arc: Arc<T>,
    }

    impl<T> std::ops::Deref for RcuGuard<'_, T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            self.arc.deref()
        }
    }

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

        pub fn get(&self) -> RcuGuard<'_, T> {
            let lock = self.0.lock().unwrap();
            RcuGuard {
                phantom: std::marker::PhantomData,
                arc: lock.clone(),
            }
        }

        pub fn write(&self, new_value: T) {
            let mut lock = self.0.lock().unwrap();
            let old = std::mem::replace(&mut *lock, Arc::new(new_value));
            std::mem::drop(lock);
            std::mem::drop(old);
        }

        pub fn update(&self, f: impl Fn(&T) -> Option<T>) -> Result<(), ()> {
            let mut lock = self.0.lock().unwrap();
            let Some(new_value) = f(&*lock) else {
                return Err(());
            };
            let old = std::mem::replace(&mut *lock, Arc::new(new_value));
            std::mem::drop(lock);
            std::mem::drop(old);
            Ok(())
        }
    }
}

#[cfg(all(feature = "rcu-crossbeam-epoch", not(doc)))]
mod rcu_impl {
    use crossbeam_epoch as epoch;
    use std::sync::atomic::Ordering;

    pub struct RcuBox<T>(epoch::Atomic<T>);

    pub struct RcuGuard<'a, T> {
        guard: epoch::Guard,
        atomic: &'a epoch::Atomic<T>,
    }

    impl<T> std::ops::Deref for RcuGuard<'_, T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            let ptr = self.atomic.load(Ordering::Acquire, &self.guard);
            // SAFETY: we only allow readers to access "live" values
            unsafe { ptr.deref() }
        }
    }

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

        pub fn get(&self) -> RcuGuard<'_, T> {
            RcuGuard {
                guard: epoch::pin(),
                atomic: &self.0,
            }
        }

        pub fn write(&self, new_value: T) {
            let guard = epoch::pin();
            let old_value = self
                .0
                .swap(epoch::Owned::new(new_value), Ordering::AcqRel, &guard);
            // SAFETY: `old_value` is now unreachable
            unsafe {
                guard.defer_destroy(old_value);
            }
        }

        pub fn update(&self, f: impl Fn(&T) -> Option<T>) -> Result<(), ()> {
            let guard = epoch::pin();
            let Ok(old_value) =
                self.0
                    .fetch_update(Ordering::AcqRel, Ordering::Acquire, &guard, |ptr| {
                        f(unsafe { ptr.deref() }).map(|x| epoch::Owned::new(x).into_shared(&guard))
                    })
            else {
                return Err(());
            };
            // SAFETY: `old_value` is now unreachable
            unsafe {
                guard.defer_destroy(old_value);
            }
            Ok(())
        }
    }
}

// NOTE: `rcu-aarc` doesn't actually compile because of the requirement that
// the contained type has static lifetime.  However -- I think we *could* work
// with this constraint in most cases if we change type annotations
// in some places, so I'm keeping it around for now.
#[cfg(all(feature = "rcu-aarc", not(doc)))]
mod rcu_impl {
    use std::sync::Mutex;

    pub struct RcuBox<T: 'static>(aarc::AtomicArc<T>, Mutex<()>);

    pub struct RcuGuard<'a, T> {
        phantom: std::marker::PhantomData<&'a T>,
        snapshot: aarc::Snapshot<T>,
    }

    impl<T> std::ops::Deref for RcuGuard<'_, T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            self.snapshot.deref()
        }
    }

    impl<T> RcuBox<T> {
        pub fn new(value: T) -> Self {
            Self(aarc::AtomicArc::new(Some(value)), Mutex::new(()))
        }

        pub fn inspect<U>(&self, f: impl FnOnce(&T) -> U) -> U {
            f(&*self.0.load::<aarc::Snapshot<_>>().unwrap())
        }

        pub fn get(&self) -> RcuGuard<'_, T> {
            RcuGuard {
                phantom: std::marker::PhantomData,
                snapshot: self.0.load::<aarc::Snapshot<_>>().unwrap(),
            }
        }

        pub fn write(&self, new_value: T) {
            // NOTE: it's not clear from aarc docs in which threads GC is allowed;
            // if in `load()` threads, this would be a deal-breaker
            self.0.store(Some(&std::sync::Arc::new(new_value)))
        }

        pub fn update(&self, f: impl Fn(&T) -> Option<T>) -> Result<(), ()> {
            let guard = self.1.lock().unwrap();
            let Some(new_value) = self.inspect(f) else {
                return Err(());
            };
            self.write(new_value);
            Ok(())
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

/// `RcuGuard` for an `Option` value known to be `Some`.
pub struct RcuOptionGuard<'a, T>(RcuGuard<'a, Option<T>>);

impl<T> std::ops::Deref for RcuOptionGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: this can only be constructed via methods
        // which validate that the guarded value is `Some`
        unsafe { self.0.as_ref().unwrap_unchecked() }
    }
}

impl<'a, T> From<RcuGuard<'a, Option<T>>> for Option<RcuOptionGuard<'a, T>> {
    fn from(guard: RcuGuard<'a, Option<T>>) -> Self {
        if guard.is_none() {
            None
        } else {
            Some(RcuOptionGuard(guard))
        }
    }
}

impl<'a, T> TryFrom<RcuGuard<'a, Option<T>>> for RcuOptionGuard<'a, T> {
    type Error = ();

    fn try_from(guard: RcuGuard<'a, Option<T>>) -> Result<Self, Self::Error> {
        if guard.is_none() {
            Err(())
        } else {
            Ok(RcuOptionGuard(guard))
        }
    }
}

/// `RcuGuard` for an `RcuCslab` entry known to be present.
pub struct RcuCslabEntryGuard<'a, T> {
    guard: RcuGuard<'a, cslab::RcuCslabReader<T>>,
    key: usize,
}

impl<T> std::ops::Deref for RcuCslabEntryGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: we've validated already (in `get_guarded`) that the key
        // was at one point visible to this reader
        unsafe { self.guard.get_unchecked(self.key) }
    }
}

impl<T> RcuBox<cslab::RcuCslabReader<T>> {
    /// Like `RcuCslabReader::get()`, but for an `RcuCslabReader` living in
    /// an `RcuBox` (as it ought to).  Hoists the `Option` outside of the guard
    /// for efficiency/ease of use.
    pub fn get_guarded(&self, key: usize) -> Option<RcuCslabEntryGuard<'_, T>> {
        let guard = self.get();
        if guard.contains_key(key) {
            Some(RcuCslabEntryGuard { guard, key })
        } else {
            None
        }
    }
}
