use std::num::NonZero;

// Rust gets very confused by NonZero generices,
// so we have to write this one out manually.

pub trait NonZeroExt {
    type Inner;

    fn unwrap_or_zero(self) -> Self::Inner;
}

macro_rules! impl_non_zero_ext {
    ($t:ty) => {
        impl NonZeroExt for Option<NonZero<$t>> {
            type Inner = $t;

            fn unwrap_or_zero(self) -> Self::Inner {
                // transmute from Option<Self::NonZero<T>> to T where T: ZeroablePrimitive is sound
                unsafe { std::mem::transmute(self) }
            }
        }
    };
}

impl_non_zero_ext!(i8);
impl_non_zero_ext!(i16);
impl_non_zero_ext!(i32);
impl_non_zero_ext!(i64);
impl_non_zero_ext!(i128);
impl_non_zero_ext!(isize);
impl_non_zero_ext!(u8);
impl_non_zero_ext!(u16);
impl_non_zero_ext!(u32);
impl_non_zero_ext!(u64);
impl_non_zero_ext!(u128);
impl_non_zero_ext!(usize);
