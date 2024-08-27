#[cfg(feature = "bytes")]
mod zerocopy_bytes {
    use bytes::{Buf, BufMut};
    use std::mem::MaybeUninit;
    use zerocopy::*;

    pub trait AsBytesExt {
        /// Like `write_to()`, but writes to a `BufMut`.
        fn write_to_buf(&self, buf: &mut impl BufMut) -> Option<()>;
    }

    pub trait FromBytesExt {
        /// Get a write-only buffer to modify this value.
        fn as_bytes_mut(&mut self) -> &mut [MaybeUninit<u8>];

        /// Like `read_from_prefix()`, but reads from a `Buf`.
        fn read_from_buf(buf: &mut impl Buf) -> Option<Self>
        where
            Self: Sized;
    }

    impl<T: AsBytes> AsBytesExt for T {
        fn write_to_buf(&self, buf: &mut impl BufMut) -> Option<()> {
            let bytes = self.as_bytes();
            if buf.remaining_mut() < bytes.len() {
                None
            } else {
                buf.put(bytes);
                Some(())
            }
        }
    }

    impl<T: FromBytes> FromBytesExt for T {
        fn as_bytes_mut(&mut self) -> &mut [MaybeUninit<u8>] {
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

        fn read_from_buf(buf: &mut impl Buf) -> Option<Self>
        where
            Self: Sized,
        {
            if buf.remaining() < std::mem::size_of::<Self>() {
                None
            } else {
                let mut ret = T::new_zeroed();
                // SAFETY: we are immediately writing to all bytes
                buf.copy_to_slice(unsafe {
                    crate::std::mem::slice_assume_init_mut(ret.as_bytes_mut())
                });
                Some(ret)
            }
        }
    }
}

#[cfg(feature = "bytes")]
pub use zerocopy_bytes::*;
