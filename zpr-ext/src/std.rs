pub mod mem {
    use std::mem::ManuallyDrop;
    use std::ops::{Deref, DerefMut, Drop};

    /// Backport of the nightly-only experimental API.
    pub unsafe fn slice_assume_init_mut<T>(slice: &mut [std::mem::MaybeUninit<T>]) -> &mut [T] {
        unsafe { &mut *(slice as *mut _ as *mut [T]) }
    }

    struct DropGuardImplInner<T, F: FnOnce(T)> {
        item: T,
        destructor: F,
    }

    struct DropGuardImpl<T, F: FnOnce(T)>(ManuallyDrop<DropGuardImplInner<T, F>>);

    impl<T, F: FnOnce(T)> Deref for DropGuardImpl<T, F> {
        type Target = T;

        fn deref(&self) -> &T {
            &self.0.deref().item
        }
    }

    impl<T, F: FnOnce(T)> DerefMut for DropGuardImpl<T, F> {
        fn deref_mut(&mut self) -> &mut T {
            &mut self.0.deref_mut().item
        }
    }

    impl<T, F: FnOnce(T)> Drop for DropGuardImpl<T, F> {
        fn drop(&mut self) {
            // SAFETY: we are calling this in the drop handler, and
            // do not ourselves reuse `inner`
            let inner = unsafe { ManuallyDrop::take(&mut self.0) };
            (inner.destructor)(inner.item);
        }
    }

    #[allow(drop_bounds)]
    pub trait DropGuard<T>: Deref<Target = T> + DerefMut<Target = T> + Drop {
        //! A `DropGuard` is a wrapper for a value which calls a specified
        //! destructor on the value when the guard is dropped.  This is
        //! useful for specifying a "temporary" destructor, e.g.  across a
        //! cancellation point.

        /// Destroy the wrapper and return the wrapped value.  The destructor
        /// will no longer be called.
        fn into_inner(self) -> T;

        /// Convert the wrapped value into another type, using `into_fn`.
        /// The new value will be converted back to the original type using
        /// `from_fn` in order to be destructed.
        fn map<U, IntoFn: FnOnce(T) -> U, FromFn: FnOnce(U) -> T>(
            self,
            into_fn: IntoFn,
            from_fn: FromFn,
        ) -> impl DropGuard<U>;
    }

    impl<T, F: FnOnce(T)> DropGuard<T> for DropGuardImpl<T, F> {
        fn into_inner(mut self) -> T {
            // SAFETY: we are consuming `self`, and forget it immediately after
            let inner = unsafe { ManuallyDrop::take(&mut self.0) };
            std::mem::forget(self);
            inner.item
        }

        fn map<U, IntoFn: FnOnce(T) -> U, FromFn: FnOnce(U) -> T>(
            mut self,
            into_fn: IntoFn,
            from_fn: FromFn,
        ) -> impl DropGuard<U> {
            // SAFETY: we are consuming `self`, and forget it immediately after
            let inner = unsafe { ManuallyDrop::take(&mut self.0) };
            std::mem::forget(self);
            let inner_item = inner.item;
            let inner_destructor = inner.destructor;
            drop_guard(into_fn(inner_item), |outer| {
                inner_destructor(from_fn(outer))
            })
        }
    }

    /// Construct a `DropGuard`, wrapping the specified item, with the specified destructor.
    pub fn drop_guard<T, F: FnOnce(T)>(item: T, destructor: F) -> impl DropGuard<T> {
        DropGuardImpl(ManuallyDrop::new(DropGuardImplInner { item, destructor }))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::cell::RefCell;

        #[test]
        fn drop_guard_drop_test() {
            let dropped = RefCell::new(false);
            {
                let _guard = drop_guard(123, |x| {
                    assert_eq!(x, 123);
                    *dropped.borrow_mut() = true
                });
                assert!(!*dropped.borrow());
            }
            assert!(dropped.take());
        }

        #[test]
        fn drop_guard_into_inner_test() {
            let mut dropped = false;
            {
                let guard = drop_guard(123, |_| dropped = true);
                assert_eq!(guard.into_inner(), 123);
            }
            assert!(!dropped);
        }

        #[test]
        fn drop_guard_deref_test() {
            let mut guard = drop_guard(123, |_| ());
            assert_eq!(*guard, 123);
            *guard = 456;
            assert_eq!(*guard, 456);
        }

        #[test]
        fn drop_guard_map_test() {
            let dropped = RefCell::new(false);
            {
                let guard_outer = drop_guard(123, |x| {
                    assert_eq!(x, 123);
                    *dropped.borrow_mut() = true
                });
                let guard_inner = guard_outer.map(|x| x + 333, |x| x - 333);
                assert!(!*dropped.borrow());
                assert_eq!(*guard_inner, 456);
            }
            assert!(dropped.take());
        }
    }
}

pub mod vec {
    pub trait VecExt<T> {
        fn recycle<U>(self) -> Vec<U>;
    }

    impl<T> VecExt<T> for Vec<T> {
        /// Recycle the underlying storage pool of a vector, while ending
        /// the lifetimes of everything contained in it.  Example usage:
        ///   let mut outer_vec = Vec::new();
        ///   loop {
        ///     // invariant: outer_vec is empty
        ///     let mut inner_vec = outer_vec;
        ///     // ... use inner_vec ...
        ///     outer_vec = inner_vec.recycle();
        ///   }
        /// See <https://github.com/rust-lang/rfcs/pull/2802#issuecomment-871512348>
        /// Also available here: <https://docs.rs/vec-utils/0.3.0/src/vec_utils/vec.rs.html#234>
        /// and here: <https://docs.rs/recycle_vec/1.0.4/src/recycle_vec/lib.rs.html#88>
        fn recycle<U>(mut self) -> Vec<U> {
            self.clear();
            self.into_iter().map(|_| unreachable!()).collect()
        }
    }
}
