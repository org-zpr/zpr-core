use bytes::Buf;
use std::mem::MaybeUninit;

pub trait BufExt {
    /// Like `copy_to_slice()`, but safely fills in a `MaybeUninit` slice.
    fn copy_to_maybe_uninit_slice_mut<'a, 'b>(&'a mut self, dst: &'b mut [MaybeUninit<u8>]) -> &'b mut [u8];
}

impl<T: Buf> BufExt for T {
    fn copy_to_maybe_uninit_slice_mut<'a, 'b>(&'a mut self, dst: &'b mut [MaybeUninit<u8>]) -> &'b mut [u8] {
        // SAFETY: we are immediately writing to all bytes
        let slice = unsafe { crate::std::mem::slice_assume_init_mut(dst) };
        self.copy_to_slice(slice);
        slice
    }
}
