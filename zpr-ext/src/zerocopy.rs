#[cfg(feature = "bytes")]
mod zerocopy_bytes {
    use bytes::{Buf, BufMut};
    use zerocopy::*;

    pub trait AsBytesExt {
        /// Like `write_to()`, but writes to a `BufMut`.
        fn write_to_buf(&self, buf: &mut impl BufMut) -> Option<()>;
    }

    pub trait FromBytesExt {
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
        fn read_from_buf(buf: &mut impl Buf) -> Option<Self>
        where
            Self: Sized,
        {
            if buf.remaining() < std::mem::size_of::<Self>() {
                None
            } else {
                Self::read_from(buf.copy_to_bytes(std::mem::size_of::<Self>()).as_ref())
            }
        }
    }
}

#[cfg(feature = "bytes")]
pub use zerocopy_bytes::*;
