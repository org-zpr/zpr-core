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
