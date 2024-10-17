pub mod error {
    use std::marker::PhantomData;

    /// NOTE: zerocopy currently provides no way to construct a
    /// SizeError, so we must return an opaque error type.
    #[non_exhaustive]
    pub struct SizeError<Src, Dst: ?Sized>(PhantomData<zerocopy::error::SizeError<Src, Dst>>);

    impl<Src, Dst: ?Sized> SizeError<Src, Dst> {
        #[allow(dead_code)]
        pub(super) fn new() -> Self {
            Self(PhantomData)
        }
    }

    impl<Src, Dst: ?Sized> std::fmt::Debug for SizeError<Src, Dst> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "SizeError")
        }
    }
}

pub use error::*;

#[cfg(feature = "bytes")]
mod zerocopy_bytes {
    use crate::bytes::BufExt;
    use bytes::{Buf, BufMut};
    use std::mem::MaybeUninit;
    use zerocopy::*;

    pub trait IntoBytesExt {
        /// Like `write_to()`, but writes to a `BufMut`.
        fn write_to_buf<B: BufMut>(
            &self,
            buf: &mut B,
        ) -> Result<(), super::SizeError<&Self, &mut B>>
        where
            Self: Immutable;
    }

    pub trait FromBytesExt {
        /// Get a write-only buffer to modify this value.
        fn as_uninit_bytes_mut(&mut self) -> &mut [MaybeUninit<u8>];

        /// Like `read_from_prefix()`, but reads from a `Buf`.
        fn read_from_buf<B: Buf>(buf: &mut B) -> Result<Self, super::SizeError<&mut B, Self>>
        where
            Self: Sized;
    }

    impl<T: IntoBytes> IntoBytesExt for T {
        fn write_to_buf<B: BufMut>(
            &self,
            buf: &mut B,
        ) -> Result<(), super::SizeError<&Self, &mut B>>
        where
            Self: Immutable,
        {
            let bytes = self.as_bytes();
            if buf.remaining_mut() < bytes.len() {
                Err(super::SizeError::new())
            } else {
                buf.put(bytes);
                Ok(())
            }
        }
    }

    impl<T: FromBytes> FromBytesExt for T {
        fn as_uninit_bytes_mut(&mut self) -> &mut [MaybeUninit<u8>] {
            // SAFETY: we are forming the slice as the correct size;
            // MaybeUninit<u8> is always safe to cast to, and
            // T can read anything that's written to it
            unsafe {
                std::slice::from_raw_parts_mut(
                    self as *mut _ as *mut MaybeUninit<u8>,
                    std::mem::size_of::<T>(),
                )
            }
        }

        fn read_from_buf<B: Buf>(buf: &mut B) -> Result<Self, super::SizeError<&mut B, Self>>
        where
            Self: Sized,
        {
            if buf.remaining() < std::mem::size_of::<Self>() {
                Err(super::SizeError::new())
            } else {
                let mut ret = T::new_zeroed();
                buf.copy_to_maybe_uninit_slice_mut(ret.as_uninit_bytes_mut());
                Ok(ret)
            }
        }
    }
}

#[cfg(feature = "bytes")]
pub use zerocopy_bytes::*;
