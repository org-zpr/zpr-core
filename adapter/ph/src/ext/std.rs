#![allow(dead_code)]

pub mod mem {
    use std::ops::{Deref, DerefMut, Drop};

    pub unsafe fn slice_assume_init_mut<T>(slice: &mut [std::mem::MaybeUninit<T>]) -> &mut [T] {
        unsafe { &mut *(slice as *mut _ as *mut [T]) }
    }

    struct DropGuardImplInner<T, F: FnOnce(T)> {
        item: T,
        destructor: F,
    }

    // TODO: switch to ManuallyDrop
    struct DropGuardImpl<T, F: FnOnce(T)>(Option<DropGuardImplInner<T, F>>);

    impl<T, F: FnOnce(T)> Deref for DropGuardImpl<T, F> {
        type Target = T;

        fn deref(&self) -> &T {
            &self.0.as_ref().unwrap().item
        }
    }

    impl<T, F: FnOnce(T)> DerefMut for DropGuardImpl<T, F> {
        fn deref_mut(&mut self) -> &mut T {
            &mut self.0.as_mut().unwrap().item
        }
    }

    impl<T, F: FnOnce(T)> Drop for DropGuardImpl<T, F> {
        fn drop(&mut self) {
            let inner = self.0.take().unwrap();
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
            let item = self.0.take().unwrap().item;
            std::mem::forget(self);
            item
        }

        fn map<U, IntoFn: FnOnce(T) -> U, FromFn: FnOnce(U) -> T>(
            mut self,
            into_fn: IntoFn,
            from_fn: FromFn,
        ) -> impl DropGuard<U> {
            let inner = self.0.take().unwrap();
            let inner_item = inner.item;
            let inner_destructor = inner.destructor;
            std::mem::forget(self);
            drop_guard(into_fn(inner_item), |outer| {
                inner_destructor(from_fn(outer))
            })
        }
    }

    /// Construct a `DropGuard`, wrapping the specified item, with the specified destructor.
    pub fn drop_guard<T, F: FnOnce(T)>(item: T, destructor: F) -> impl DropGuard<T> {
        DropGuardImpl(Some(DropGuardImplInner { item, destructor }))
    }
}

pub mod vec {
    pub trait VecExt<T> {
        fn recycle<U>(self) -> Vec<U>;
    }

    impl<T> VecExt<T> for Vec<T> {
        // Recycle the underlying storage pool of a vector, while ending
        // the lifetimes of everything contained in it.  Example usage:
        //   let mut outer_vec = Vec::new();
        //   loop {
        //     // invariant: outer_vec is empty
        //     let mut inner_vec = outer_vec;
        //     // ... use inner_vec ...
        //     outer_vec = inner_vec.recycle();
        //   }
        // See <https://github.com/rust-lang/rfcs/pull/2802#issuecomment-871512348>
        // Also available here: <https://docs.rs/vec-utils/0.3.0/src/vec_utils/vec.rs.html#234>
        // and here: <https://docs.rs/recycle_vec/1.0.4/src/recycle_vec/lib.rs.html#88>
        fn recycle<U>(mut self) -> Vec<U> {
            self.clear();
            self.into_iter().map(|_| unreachable!()).collect()
        }
    }
}
