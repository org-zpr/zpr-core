/// Backport of the nightly-only experimental API.
pub unsafe fn slice_assume_init_mut<T>(slice: &mut [std::mem::MaybeUninit<T>]) -> &mut [T] {
    unsafe { &mut *(slice as *mut _ as *mut [T]) }
}
