//! An RCU-friendly concurrent slab

#[cfg(loom)]
use loom::alloc::{self, Layout};
#[cfg(not(loom))]
use std::alloc::{self, Layout};
//#[cfg(not(loom))]
use std::cell::UnsafeCell;
//#[cfg(loom)]
//use loom::cell::UnsafeCell;
#[cfg(loom)]
use loom::sync;
use std::mem::ManuallyDrop;
#[cfg(not(loom))]
use std::sync;
use sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex, MutexGuard,
};

// DESIGN NOTES
//
// The slab itself is a traditional freelist design: an allocated
// entry simply contains the item stored at that location; a free
// entry simply contains a pointer to the next free slot.  The only
// addition to this structure is a bitmap we use to allow querying for
// whether an item is present in a given slot.
//
// The complexity of the remainder of the design springs from the goal
// to allow readers to operate concurrently with a writer, while
// maintaining near-zero-cost lookups for readers.
//
// There are only three core operations on an active slab: insert [I],
// remove [R], and get [G] (which notably returns a reference, not a copy).
// A slab may also of course be dropped [D] at the end of its lifetime.
//
// Dropping is enforced by the Rust runtime to only occur once all
// references to the slab have disappeared.  Therefore it can only
// execute exclusively of any other operation.
//
// Since writers can be "slow", we assume a single writer (enforced
// by requiring a mut reference).  Therefore, insert [I] and remove [R]
// execute exclusive of each other.
//
// Get [G] however, may execute concurrently with any other operation.
// Notably, we provide a method `reader()` to obtain a "reader" handle
// which allows performing get [G] operations concurrently with insert [I]
// and remove [R].
//
// Therefore, the concurrency stories we must consider are [I] with [G],
// and [R] with [G].
//
// Insert [I] with get [G] is straightforward.  We require that [I] first
// store the item itself in the slab, _then_ mark the item as present in the
// bitmap.  [G] must likewise first check the bitmap _before_ attempting to
// read an item.  The cross-thread ordering is enforced by a release-acquire
// operation pair on the bitmap element:
//
//          WRITER             |        READER
//                             |
//   store item [Ii]           |
//        ↓                    |
//   store flag [Ib] (release) |
//                             ⇘
//                             | (acquire) load flag [Gb]
//                             |               ↓
//                             |           load item [Gi]
//
// (as marked in the source code).
//
// The complex case is remove [R] with get [G].  The key issue is that a
// writer may wish to remove an item from the slab while a reader is still
// accessing it.  One approach to prevent this would be to have the reader,
// while accessing the item, recheck the flag before any operation which
// would be potentially unsafe in the case that corrupt data had been read.
// This however is intrusive for complex items and suffers from the A/B/A
// problem.
//
// So instead, we follow a model informed by the read-copy-update (RCU)
// family of algorithms.  Remove [R] is split into two phases:
// `mark_removed()`, and `finalize_remove()`.  Both must be performed in
// sequence to remove any item.  Marking may be performed at any time.
// Finalizing however, may only be performed after synchronizing with the
// reader(s) to ensure that no accesses to that item are outstanding.  This
// corresponds directly with the notion of RCU synchronization, in which a
// "cleanup" operation can be scheduled to run after all active read-side
// critical sections have completed.
//
// `mark_removed()` then, simply clears the item's mark in the bitmap.  Get
// [G] operations may safely race this.  They will safely return either the
// item (which has not yet actually been deleted from slab storage), or a
// not found indication.  The writer then must signal the reader(s) that it
// is waiting for all outstanding read-side critical sections to complete
// (this would be e.g.  an RCU update operation).  This signal is
// effectively a release-acquire pair, after which all readers will
// henceforth read the item's bitmap mark clear (and return not found).
//
// The reader(s) then must signal the writer when their outstanding
// read-side critical sections have completed (this would be e.g.  an RCU
// synchronization callback).  This signal again is effectively a
// release-acquire pair.  It's now known to the writer that no reader
// remains accessing the marked item.  `finalize_remove()` may then be
// called, and the item is actually deleted, and the slot returned to the
// slab's freelist.
//
// This complex ordering is illustrated as follows:
//
//        WRITER            |       READER
//                          |
//     store flag [Rb]      |    load flag [Gb]  }
//          ↓               |         ↓          } any number; safely races writer
//     RCU update (release) |   ?load item [Gi]  }
//                          ⇘      |
//                          | (acquire) RCU update
//                          |      ↓  ↓  |
//                          | (release) RCU callback
//                          ⇙            ↓
//   RCU callback (acquire) |    load flag [Gb]  } now reads as clear
//          ↓               |
//    delete item [Ri]      |
//
// Of course, it's critical for writers to correctly track the visibility of
// remove [R] operations to readers.  The `Cslab` data structure does not
// provide this.  Instead, the `RcuCslab` data structure builds upon `Cslab`
// to provide this functionality.  It is described below.

union Entry<T> {
    next_free: isize, // offset to next empty; neighbor is 0 so zero-alloced array is initialized
    item: ManuallyDrop<T>,
}

type CslabTable<T> = [UnsafeCell<Entry<T>>];
type CslabBitmap = [AtomicUsize];

// `CslabStorage` "glues together" the table and bitmap allocations into one.
// This allows us to write a `Drop` implementation which uses both of them.
struct CslabStorage<T> {
    size: usize,
    ptr: *mut u8,
    bitmap_offset: usize,
    phantom: std::marker::PhantomData<T>,
}

impl<T> CslabStorage<T> {
    fn table_layout(n: usize) -> Layout {
        Layout::array::<<usize as std::slice::SliceIndex<CslabTable<T>>>::Output>(n).unwrap()
    }

    fn bitmap_layout(n: usize) -> Layout {
        Layout::array::<<usize as std::slice::SliceIndex<CslabBitmap>>::Output>(
            (n + usize::BITS as usize - 1) / usize::BITS as usize,
        )
        .unwrap()
    }

    fn storage_layout(n: usize) -> (Layout, usize) {
        Self::table_layout(n)
            .extend(Self::bitmap_layout(n))
            .unwrap()
    }

    pub fn with_fixed_capacity(size: usize) -> Self {
        assert!(size > 0);

        let (layout, bitmap_offset) = Self::storage_layout(size);

        // SAFETY: layout is not 0-sized
        let ptr = unsafe { alloc::alloc_zeroed(layout) };

        #[cfg(loom)]
        {
            let bitmap: &mut [std::mem::MaybeUninit<AtomicUsize>] = unsafe {
                std::slice::from_raw_parts_mut(
                    ptr.add(bitmap_offset).cast(),
                    (size + usize::BITS as usize - 1) / usize::BITS as usize,
                )
            };
            for bme in bitmap {
                bme.write(AtomicUsize::new(0));
            }
        }

        Self {
            size,
            ptr,
            bitmap_offset,
            phantom: std::marker::PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.size
    }

    pub fn table(&self) -> &CslabTable<T> {
        // SAFETY: we've correctly allocated memory
        unsafe { std::slice::from_raw_parts(self.ptr.cast(), self.size) }
    }

    pub fn bitmap(&self) -> &CslabBitmap {
        // SAFETY: we've correctly allocated memory
        unsafe {
            std::slice::from_raw_parts(
                self.ptr.add(self.bitmap_offset).cast(),
                (self.size + usize::BITS as usize - 1) / usize::BITS as usize,
            )
        }
    }

    pub fn parts_mut(&mut self) -> (&mut CslabTable<T>, &mut CslabBitmap) {
        // SAFETY: we've correctly allocated memory
        (
            unsafe { std::slice::from_raw_parts_mut(self.ptr.cast(), self.size) },
            unsafe {
                std::slice::from_raw_parts_mut(
                    self.ptr.add(self.bitmap_offset).cast(),
                    (self.size + usize::BITS as usize - 1) / usize::BITS as usize,
                )
            },
        )
    }
}

impl<T> Drop for CslabStorage<T> {
    fn drop(&mut self) {
        // FIXME: this is inefficient for very large tables
        // NOTE: we can (a) use bitscanning, and (b) keep a count of how many values remaining

        let size = self.size;
        let (table, bitmap) = self.parts_mut();

        for (i, bme) in bitmap.iter().enumerate() {
            let x = bme.load(Ordering::Relaxed);
            for j in 0..usize::BITS as usize {
                let idx = (i * usize::BITS as usize) + j;
                if idx >= size {
                    break;
                }
                if (x >> j) & 1 != 0 {
                    // SAFETY: we know an element is present from the bit being set
                    // and our requirement that `finalize_remove()` be called
                    // for every `mark_removed()`
                    unsafe { ManuallyDrop::drop(&mut (*table[idx].get()).item) }
                }
            }
        }

        let (layout, _) = Self::storage_layout(self.size);
        // SAFETY: we are dropping; no-one else has a pointer to this
        unsafe {
            alloc::dealloc(self.ptr, layout);
        }
    }
}

// SAFETY: `CslabStorage` is explicitly designed to be accessed between threads
unsafe impl<T> Send for CslabStorage<T> {}
unsafe impl<T> Sync for CslabStorage<T> {}

fn get_impl<T>(storage: &CslabStorage<T>, idx: usize) -> Option<&T> {
    if contains_key_impl(storage, idx) {
        // load item
        // SAFETY: the bitmap has told us there is an item
        Some(unsafe { get_unchecked_impl(storage, idx) })
    } else {
        None
    }
}

// note: this method performs an acquire operation on the bitmap,
// so is safe for establishing synchronization
fn contains_key_impl<T>(storage: &CslabStorage<T>, idx: usize) -> bool {
    if idx >= storage.len() {
        return false;
    }

    // check flag
    (storage.bitmap()[idx / usize::BITS as usize].load(Ordering::Acquire) /* [Gb] */
        >> (idx % usize::BITS as usize))
        & 1
        != 0
}

// SAFETY: this method requires that we've already confirmed an item is present.
// (It's OK if the item is pending removal.  But it must not actually be removed yet.)
unsafe fn get_unchecked_impl<T>(storage: &CslabStorage<T>, idx: usize) -> &T {
    unsafe { &(*storage.table()[idx].get()).item } /* [Gi] */
}

/// Cloneable read-only handle to a `Cslab`.
pub struct CslabReader<T>(Arc<CslabStorage<T>>);

impl<T> CslabReader<T> {
    /// Lookup an item by its index in the slab.
    ///
    /// If no item is present at the given index, or the index is out of
    /// range, returns `None`.
    ///
    /// Unlike `Cslab::get()`, until removal finalization has been
    /// synchronized, it is possible for this method to return items which
    /// have been marked for removal by the writer thread.  (The item
    /// returned is however still valid.)
    pub fn get(&self, idx: usize) -> Option<&T> {
        get_impl(&*self.0, idx)
    }

    /// Like `get()`, but simply returns whether an item is present or not.
    pub fn contains_key(&self, idx: usize) -> bool {
        contains_key_impl(&*self.0, idx)
    }

    /// Gets an item known not to have been finalized.  (I.e., the item must be
    /// present or pending removal.)
    ///
    /// # Safety
    ///
    /// A previous call to `get()` or `contains_key()` has indicated
    /// that an item is present at this index, and `finalize_remove()`
    /// has not been called on this index in the interim.
    pub unsafe fn get_unchecked(&self, idx: usize) -> &T {
        get_unchecked_impl(&*self.0, idx)
    }
}

impl<T> Clone for CslabReader<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

/// A concurrent slab.
pub struct Cslab<T> {
    // Index of the first item in the freelist.
    first_free: usize, // >= capacity indicates empty freelist
    // Number of elements in use.  Used only to report back to callees.
    in_use: usize,
    // Number of elements allocated.  Used only to report back to callees.
    allocated: usize,
    // Shared pointer to table & bitmap storage.
    storage: Arc<CslabStorage<T>>,
}

impl<T> Cslab<T> {
    /// Create a new slab with the given capacity.
    ///
    /// All slab indices will be an integer less than the specified capacity.
    ///
    /// NOTE: Slabs cannot be resized.
    pub fn with_fixed_capacity(capacity: usize) -> Self {
        Self {
            first_free: 0,
            in_use: 0,
            allocated: 0,
            storage: Arc::new(CslabStorage::with_fixed_capacity(capacity)),
        }
    }

    /// Returns the total capacity of the slab.
    pub fn capacity(&self) -> usize {
        self.storage.len()
    }

    /// Returns the number of elements present in the slab.
    pub fn len(&self) -> usize {
        self.in_use
    }

    /// Returns the number of slots allocated in the slab.
    ///
    /// This is always >= the number of elements present (`.len()`).
    /// The difference indicates how many elements have been marked for
    /// removal but not yet finalized.
    ///
    /// The difference between this and the capacity indicates
    /// how many more elements may be added.
    pub fn allocated(&self) -> usize {
        self.allocated
    }

    /// Lookup an item by its index in the slab.  If no item is present at
    /// the given index, or the index is out of range, returns `None`.
    ///
    /// Unlike `CslabReader::get()`, it is _not_ possible for this method to
    /// return items which have been marked for removal.
    pub fn get(&self, idx: usize) -> Option<&T> {
        get_impl(&*self.storage, idx)
    }

    /// Return a clonable read-only handle to the slab.
    ///
    /// This handle may be used to perform read accesses concurrently with
    /// write accesses through the slab directly.
    pub fn reader(&self) -> CslabReader<T> {
        CslabReader(self.storage.clone())
    }

    /// Allocate a slot in the slab and insert the given item into it.
    ///
    /// The allocated index will be returned.
    ///
    /// If there is no space remaining, an error is returned.
    pub fn insert(&mut self, item: T) -> Result<usize, ()> {
        let idx = self.first_free;

        if idx >= self.storage.table().len() {
            return Err(());
        }

        // update freelist
        // SAFETY: any index in the freelist has no item
        self.first_free =
            (idx as isize + 1 + unsafe { (*self.storage.table()[idx].get()).next_free }) as usize;

        // store item
        // SAFETY: any index in the freelist has no item
        unsafe { (*self.storage.table()[idx].get()).item = ManuallyDrop::new(item) } /* [Ii] */;

        // mark in bitmap
        let mask = self.storage.bitmap()[idx / usize::BITS as usize].load(Ordering::Relaxed);
        debug_assert!((mask >> (idx % usize::BITS as usize)) & 1 == 0);
        self.storage.bitmap()[idx / usize::BITS as usize].store(
            mask | (1 << (idx % usize::BITS as usize)),
            Ordering::Release,
        ) /* [Ib] */;

        self.in_use += 1;
        self.allocated += 1;

        Ok(idx)
    }

    /// Returns the index which will be used for the next allocation.
    pub fn vacant_key(&self) -> Result<usize, ()> {
        let idx = self.first_free;

        if idx >= self.storage.table().len() {
            return Err(());
        }

        Ok(idx)
    }

    /// Try to reserve a slot for inserting an item.
    ///
    /// This way, an item which needs to refer to its own index can be inserted.
    pub fn vacant_entry(&mut self) -> Result<VacantEntry<'_, T>, ()> {
        if self.first_free >= self.storage.table().len() {
            return Err(());
        }

        Ok(VacantEntry(self))
    }

    /// Mark an element to be removed.
    ///
    /// Panics if there is no element present at the given index.
    ///
    /// The indexed slot will appear empty to any readers who have performed
    /// a release-acquire synchronization with this thread.
    ///
    /// # Safety
    ///
    /// The item must eventually be removed with `finalize_remove()`.
    /// (Else, double-frees will occur on drop.)
    pub unsafe fn mark_removed(&mut self, idx: usize) {
        let mask = self.storage.bitmap()[idx / usize::BITS as usize].load(Ordering::Relaxed);

        // confirm we're deleting something that's present
        // (this is really a requirement of `finalize_remove()`
        assert!((mask >> (idx % usize::BITS as usize)) & 1 == 1);

        // mark the item as free (but don't actually free it)
        self.storage.bitmap()[idx / usize::BITS as usize].store(
            mask & !(1 << (idx % usize::BITS as usize)),
            Ordering::Relaxed,
        ) /* [Rb] */;

        self.in_use -= 1;
    }

    /// Actually free an index which has been marked free with `mark_removed()`.
    ///
    /// Returns the removed item.
    ///
    /// # Safety
    ///
    /// `mark_removed()` must first have been called.  (It is an undetectable
    /// error to call this on an already-freed item.)
    ///
    /// It must be known that there will be no further reads of this index.
    /// This can be guaranteed after calling `mark_removed()` by notifying
    /// all readers of this update via a release-acquire synchronization,
    /// then waiting for all readers to acknowledge this notification, again
    /// with release-acquire synchronization.
    pub unsafe fn finalize_remove(&mut self, idx: usize) -> T {
        // confirm item is not visible
        let mask = self.storage.bitmap()[idx / usize::BITS as usize].load(Ordering::Relaxed);
        assert!((mask >> (idx % usize::BITS as usize)) & 1 == 0);

        // drop item
        // SAFETY: we know only we can access this item from our safety requirement
        let entry = &mut *self.storage.table()[idx].get();
        // SAFETY: we know there is an item from our safety requirement
        let item = unsafe { ManuallyDrop::take(&mut entry.item) } /* [Ri] */;

        // add entry to front of freelist
        // SAFETY: we have removed the item
        entry.next_free = self.first_free as isize - idx as isize;
        self.first_free = idx;

        self.allocated -= 1;

        item
    }
}

pub struct VacantEntry<'a, T>(&'a mut Cslab<T>);

impl<T> VacantEntry<'_, T> {
    /// Returns the index which will be used by calling `insert()`
    /// on this `VacantEntry`.
    pub fn key(&self) -> usize {
        self.0.first_free
    }

    /// Inserts an item at the index returned by `key()`.
    pub fn insert(self, item: T) -> usize {
        // because `self` holds a mut reference to the `Cslab`
        // which could only have come from `vacant_entry()`,
        // we're guaranteed (a) that there is an entry free,
        // and (b) that it hasn't changed since the creation
        // of `self`
        self.0.insert(item).unwrap()
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    #[test]
    fn basic_test() {
        let mut slab = Cslab::with_fixed_capacity(4);
        assert_eq!(slab.capacity(), 4);
        let i = slab.insert(123).unwrap();
        let j = slab.insert(456).unwrap();
        assert_eq!(slab.capacity(), 4);
        assert_eq!(slab.len(), 2);
        assert_eq!(slab.allocated(), 2);
        assert_eq!(*slab.get(i).unwrap(), 123);
        assert_eq!(*slab.get(j).unwrap(), 456);
        assert_eq!(slab.get(j + 1), None);
        assert_eq!(slab.get(slab.capacity()), None);
        assert_eq!(slab.get(usize::MAX), None);
    }

    #[test]
    fn at_capacity_test() {
        let mut slab = Cslab::with_fixed_capacity(4);
        assert_eq!(slab.capacity(), 4);
        slab.insert(123).unwrap();
        slab.insert(456).unwrap();
        slab.insert(234).unwrap();
        slab.insert(567).unwrap();
        slab.insert(345).unwrap_err();
        assert_eq!(slab.len(), 4);
        assert_eq!(slab.allocated(), 4);
    }

    #[test]
    fn removal_test() {
        let mut slab = Cslab::with_fixed_capacity(4);
        let i = slab.insert(123).unwrap();
        let j = slab.insert(456).unwrap();
        unsafe {
            slab.mark_removed(i);
        }
        assert_eq!(slab.get(i), None);
        assert_eq!(*slab.get(j).unwrap(), 456);
        assert_ne!(slab.insert(234).unwrap(), i);
        assert_ne!(slab.insert(567).unwrap(), i);
        slab.insert(345).unwrap_err();
        assert_eq!(unsafe { slab.finalize_remove(i) }, 123);
        let ii = slab.insert(345).unwrap();
        assert_eq!(ii, i);
        assert_eq!(*slab.get(ii).unwrap(), 345);
    }

    #[test]
    fn reader_test() {
        let mut slab = Cslab::with_fixed_capacity(4);
        assert_eq!(slab.capacity(), 4);
        let i = slab.insert(123).unwrap();
        let reader = slab.reader();
        let j = slab.insert(456).unwrap();
        let clone = reader.clone();
        assert_eq!(*reader.get(i).unwrap(), 123);
        assert_eq!(*reader.get(j).unwrap(), 456);
        assert_eq!(*clone.get(i).unwrap(), 123);
        assert_eq!(*clone.get(j).unwrap(), 456);
    }

    struct OnDrop<'a>(&'a dyn Fn());
    impl Drop for OnDrop<'_> {
        fn drop(&mut self) {
            self.0();
        }
    }

    #[test]
    fn removal_drop_test() {
        let mut slab = Cslab::with_fixed_capacity(4);
        let dropped = std::cell::Cell::new(false);
        let dropper = || assert!(!dropped.replace(true));
        let i = slab.insert(OnDrop(&dropper)).unwrap();
        unsafe {
            slab.mark_removed(i);
        }
        assert!(!dropped.get());
        let item = unsafe { slab.finalize_remove(i) };
        assert!(!dropped.get());
        std::mem::drop(item);
        assert!(dropped.get());
        std::mem::drop(slab);
    }

    #[test]
    fn container_drop_test() {
        let mut slab = Cslab::with_fixed_capacity(4);
        let i_dropped = std::cell::Cell::new(false);
        let j_dropped = std::cell::Cell::new(false);
        let i_dropper = || assert!(!i_dropped.replace(true));
        let j_dropper = || assert!(!j_dropped.replace(true));
        let i = slab.insert(OnDrop(&i_dropper)).unwrap();
        slab.insert(OnDrop(&j_dropper)).unwrap();
        unsafe {
            slab.mark_removed(i);
            slab.finalize_remove(i);
        }
        assert!(i_dropped.get());
        std::mem::drop(slab);
        assert!(j_dropped.get());
    }
}

#[cfg(all(test, loom))]
mod loom_tests {
    // NOTE: `loom` (and the similar `shuttle`) is VERY limited for testing
    // atomic interactions.  Notably, they assume that atomic operations
    // occur _in the order they are issued_, which means they don't test
    // _any_ reorderings in a single-writer/single-reader interaction.

    use super::*;
    use loom::{model, thread};

    #[test]
    fn concurrent_insert_get_test() {
        model(|| {
            let mut slab = Cslab::with_fixed_capacity(4);

            let reader = slab.reader();
            thread::spawn(move || match reader.get(0) {
                Some(&x) => assert_eq!(x, 123),
                None => (),
            });

            slab.insert(123).unwrap();
        });
    }

    #[test]
    fn concurrent_remove_get_test() {
        model(|| {
            let mut slab = Cslab::with_fixed_capacity(4);

            let idx = slab.insert(123).unwrap();

            let reader = slab.reader();
            let t1 = thread::spawn(move || match reader.get(idx) {
                Some(&x) => assert_eq!(x, 123),
                None => (),
            });

            unsafe {
                slab.mark_removed(idx);
            }

            t1.join().unwrap();

            let reader = slab.reader();
            thread::spawn(move || {
                assert_eq!(reader.get(idx), None);
            });

            unsafe {
                slab.finalize_remove(idx);
            }
        });
    }
}

// FURTHER DESIGN NOTES
//
// Above, we left unsolved the problem of tracking items marked for removal,
// so that we finalize removal of the correct items at the correct time.
// This is the role of `RcuCslab` -- so named as it is a
// read-copy-update/RCU-friendly structure.
//
// The design of `RcuCslab` is as follows.  The `RcuCslab` structure is the
// "writer" interface.  It provides fully synchronized read-write access to
// the slab.  Reader handles may be cloned from this.  Each reader handle is
// associated (n-to-1) with a "generation" -- reads performed in a given
// generation definitively cannot see items removed prior to the creation of
// the generation.  Generations are totally ordered.  New generations are
// created explicitly by calling `.schedule_finalization()` on the writer.
// Removals are finalized when the generation in which they were removed
// becomes unreferenced.
//
// Specifically, item removal proceeds as follows.  The writer may at any
// time mark an item to be removed with the `.mark_removed()` method.  (The
// item will then immediately appear as removed to the writer, to any
// readers of future generations, and eventually, to the readers of current
// and previous generations.) Beside marking the item removed,
// `.mark_removed()` also adds the item's index to a finalization list
// associated with the current generation.
//
// The writer should then call `.schedule_finalization()`.  This creates a
// new current generation, dropping the writer's reference to the previous
// current generation.  A reference to the new generation is returned, and
// should be communicated to all readers.  Once all references to the
// previous generation are dropped, finalization will occur: the list of
// marked items in the previous generation is walked; each is finalized and
// dropped.  This finalization occurs in the context of the last dropper,
// which is either the writer (if no other references existed), or, for RCU,
// the RCU finalization thread.  Note that this synchronization and
// guarantee of finalization fulfills the safety requirements on the removal
// methods of `Cslab`.
//
// In order to maintain consistency when there are multiple outstanding
// generations, each noncurrent generation retains a reference to its
// successor.  Generations are thus finalized in strict creation order.

// NOTE: it is unsafe to allow arbitrary `CslabReader`s to be cloned
// from an `RcuCslab`!  Our internal safety guarantees rely on
// accesses being performed _only_ through the `RcuCslab`.

struct RcuCslabGenInner<T> {
    // list of indexes whose removal we can finalize once this generation
    // is dropped (since all future active generations will have read the removal mark)
    pending_removes: Vec<usize>,

    // a reference count used to prevent newer generations from
    // being collected before older generations
    next_gen: Option<Arc<RcuCslabGen<T>>>,
}

struct RcuCslabGen<T> {
    // a reference to the writer, used to perform removal finalization
    writer: Arc<Mutex<Cslab<T>>>,

    // the actual generation info, protected by a mutex
    inner: Mutex<RcuCslabGenInner<T>>,
}

impl<T> Drop for RcuCslabGen<T> {
    fn drop(&mut self) {
        let pending_drops: Box<[_]> = {
            let mut writer = self.writer.lock().unwrap();
            // SAFETY: all items in pending_removes have been marked
            // SAFETY: being RCU-dropped means we have synchronized with the writer
            self.inner
                .get_mut()
                .unwrap()
                .pending_removes
                .iter()
                .map(|&idx| unsafe { writer.finalize_remove(idx) })
                .collect()
        };

        // drop items outside the mutex to prevent deadlocks
        std::mem::drop(pending_drops);
    }
}

/// Read handle for an `RcuCslab`.
///
/// These handles are what should be communicated through an RCU structure
/// to the readers.
///
/// Items marked for removal are only actually removed once all reader
/// handles which could have seen the items present have been dropped.
///
/// Read handles may be cloned for convenience.  Cloned handles share the
/// same generation.
pub struct RcuCslabReader<T> {
    // unsynchronized read access to the slab
    reader: CslabReader<T>,

    // a reference to the generation we were created in; we don't actually
    // use the value, but keeping this reference is necessary to prevent
    // finalization of the generation
    gen: Arc<RcuCslabGen<T>>,
}

impl<T> RcuCslabReader<T> {
    /// Lookup an item by its index in the slab.
    ///
    /// If no item is present at the given index, or the index is out of
    /// range, returns `None`.
    ///
    /// Unlike `RcuCslab::get()`, until removal finalization has been
    /// synchronized, it is possible for this method to return items which
    /// have been marked for removal by the writer thread.  (The item
    /// returned is however still valid.)
    ///
    /// Note that, it is possible for this method to return `None`
    /// even if it previously returned `Some`!  The only guarantee
    /// this method gives is that the reference returned remains valid
    /// for the lifetime of the reader.
    pub fn get(&self, idx: usize) -> Option<&T> {
        self.reader.get(idx)
    }

    /// Like `get()`, but simply returns whether an item is present or not.
    pub fn contains_key(&self, idx: usize) -> bool {
        self.reader.contains_key(idx)
    }

    /// Gets an item known not to have been finalized.  (I.e., the item must be
    /// present or pending removal.)
    ///
    /// # Safety
    ///
    /// A previous call to `get()` or `contains_key()` has indicated
    /// that an item is present at this index.
    pub unsafe fn get_unchecked(&self, idx: usize) -> &T {
        // SAFETY: the caller has ensured an item was once present here,
        // and we are holding a reference to the current generation
        // which prevents any removal of this item from being finalized
        unsafe { self.reader.get_unchecked(idx) }
    }
}

impl<T> Clone for RcuCslabReader<T> {
    fn clone(&self) -> Self {
        Self {
            reader: self.reader.clone(),
            gen: self.gen.clone(),
        }
    }
}

/// An RCU-friendly concurrent slab.
///
/// Example usage, using a mutex instead of RCU:
///
/// ```
/// use cslab::RcuCslab;
/// use std::sync::{Arc, Mutex};
///
/// let mut slab = RcuCslab::with_fixed_capacity(10);
/// let reader_box = Arc::new(Mutex::new(slab.reader()));
///
/// let reader_reader_box = reader_box.clone();
/// std::thread::spawn(move ||
///   //
///   // READER
///   //
///
///   for idx in 0..10 {
///     let reader = reader_reader_box.lock().unwrap().clone();
///      match reader.get(idx) {
///        Some(value) => (),
///        None => (),
///      }
///   }
/// );
///
/// //
/// // WRITER
/// //
///
/// // insert an item
/// let idx_a = slab.insert(123).unwrap();
/// // simple way to remove a single item
/// *reader_box.lock().unwrap() = slab.remove(idx_a);
///
/// // insert several items
/// let idx_b = slab.insert(456).unwrap();
/// let idx_c = slab.insert(789).unwrap();
/// // more efficient way to remove several items at once
/// slab.mark_removed(idx_b);
/// slab.mark_removed(idx_c);
/// *reader_box.lock().unwrap() = slab.schedule_finalization();
/// ```
pub struct RcuCslab<T> {
    // unsynchronized access to capacity
    capacity: usize,

    // main reference to the writer
    writer: Arc<Mutex<Cslab<T>>>,

    // an unsynchronized reader we can clone cheaply
    reader: CslabReader<T>,

    // reference to the current generation of readers
    cur_gen: Arc<RcuCslabGen<T>>,
}

impl<T> RcuCslab<T> {
    /// Create a new slab with the given capacity.
    ///
    /// All slab indices will be an integer less than the specified capacity.
    ///
    /// NOTE: Slabs cannot be resized.
    pub fn with_fixed_capacity(capacity: usize) -> Self {
        let cslab = Cslab::with_fixed_capacity(capacity);
        let reader = cslab.reader();
        let writer = Arc::new(Mutex::new(cslab));
        let cur_gen = Arc::new(RcuCslabGen {
            writer: writer.clone(),
            inner: Mutex::new(RcuCslabGenInner {
                pending_removes: Vec::new(),
                next_gen: None,
            }),
        });

        Self {
            capacity,
            writer,
            reader,
            cur_gen,
        }
    }

    /// Returns the total capacity of the slab.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the number of elements present in the slab.
    pub fn len(&self) -> usize {
        self.writer.lock().unwrap().len()
    }

    /// Returns the number of slots allocated in the slab.
    ///
    /// This is always >= the number of elements present (`.len()`).
    /// The difference indicates how many elements have been marked for
    /// removal but not yet finalized.
    ///
    /// The difference between this and the capacity indicates
    /// how many more elements may be added.
    pub fn allocated(&self) -> usize {
        self.writer.lock().unwrap().allocated()
    }

    /// Lookup an item by its index in the slab.  If no item is present at
    /// the given index, or the index is out of range, returns `None`.
    ///
    /// Unlike `RcuCslabReader::get()`, it is _not_ possible for this method to
    /// return items which have been marked for removal.
    pub fn get(&self, idx: usize) -> Option<&T> {
        self.reader.get(idx)
    }

    /// Return a clonable read-only handle to the slab, associated with the
    /// current generation.
    ///
    /// This handle may be used to perform read accesses concurrently with
    /// write accesses through the slab directly.
    ///
    /// Calling this method is equivalent to cloning a reader of the current
    /// generation.
    pub fn reader(&self) -> RcuCslabReader<T> {
        RcuCslabReader {
            reader: self.reader.clone(),
            gen: self.cur_gen.clone(),
        }
    }

    // NOTE/CAUTION: because the writer is fully synchronized, we _could_
    // make `insert()` and `remove()` `&` instead of `&mut` here.  But that
    // would require us to make `get()` take the writer mutex (since it
    // performs reads not protected by a generation), which seems excessive.

    /// Allocate a slot in the slab and insert the given item into it.
    ///
    /// The allocated index will be returned.
    ///
    /// If there is no space remaining, an error is returned.
    pub fn insert(&mut self, item: T) -> Result<usize, ()> {
        self.writer.lock().unwrap().insert(item)
    }

    /// Returns the index which will be used for the next allocation.
    pub fn vacant_key(&self) -> Result<usize, ()> {
        self.writer.lock().unwrap().vacant_key()
    }

    /// Try to reserve a slot for inserting an item.
    ///
    /// This way, an item which needs to refer to its own index can be inserted.
    pub fn vacant_entry(&mut self) -> Result<VacantRcuEntry<'_, T>, ()> {
        // NOTE: we can't just wrap `VacantEntry` here, because we'd
        // need to return the mutex guard *and* the `VacantEntry`, which
        // Rust doesn't allow.
        let guard = self.writer.lock().unwrap();

        if matches!(guard.vacant_key(), Err(_)) {
            return Err(());
        }

        Ok(VacantRcuEntry(guard))
    }

    /// Mark an element to be removed.
    ///
    /// Panics if there is no element present at the given index.
    ///
    /// The indexed slot will deterministically appear empty to all readers
    /// of future generations, and _may_ appear empty to readers of the
    /// current or previous generations.
    pub fn mark_removed(&mut self, idx: usize) {
        // NOTE: order here doesn't matter; no-one will do anything with
        // `pending_removes` until `collect()` (which is mut) releases the references
        // to `cur_gen`
        // SAFETY: we eventually call `finalize_remove()` on drop
        unsafe {
            self.writer.lock().unwrap().mark_removed(idx);
        }
        self.cur_gen.inner.lock().unwrap().pending_removes.push(idx);
    }

    /// Schedule removal finalization of the current generation, and create
    /// a new generation.
    ///
    /// Returns a read handle associated with the new generation.
    /// (Same as will be returned by any calls to `.reader()`
    /// after return from this method.)
    ///
    /// Removal finalization will occur once all read handles of the
    /// previous current generation, and all older previous generations,
    /// are no longer referenced, in the context of the drop of the
    /// last such reference.  (Or, if there are no such remaining references,
    /// finalization will occur immediately during this method call.)
    pub fn schedule_finalization(&mut self) -> RcuCslabReader<T> {
        let next_gen = Arc::new(RcuCslabGen {
            writer: self.writer.clone(),
            inner: Mutex::new(RcuCslabGenInner {
                pending_removes: Vec::new(),
                next_gen: None,
            }),
        });

        {
            let mut cur_gen_inner = self.cur_gen.inner.lock().unwrap();
            debug_assert!(cur_gen_inner.next_gen.is_none());
            cur_gen_inner.next_gen = Some(next_gen.clone());
        }

        // Replace the previous generation with the current generation.
        // Note that if no other references remain to the previous generation,
        // the finalization will be performed immedaitely here.
        // Hence we are careful not to hold any locks.
        self.cur_gen = next_gen;

        self.reader()
    }

    /// A convenience method for marking and scheduling finalization of a single item.
    ///
    /// Returns a reader via which the removal is visible.  Once all references to
    /// older readers are dropped, finalization will occur immediately.
    pub fn remove(&mut self, idx: usize) -> RcuCslabReader<T> {
        self.mark_removed(idx);
        self.schedule_finalization()
    }
}

pub struct VacantRcuEntry<'a, T>(MutexGuard<'a, Cslab<T>>);

impl<T> VacantRcuEntry<'_, T> {
    /// Returns the index which will be used by calling `insert()`
    /// on this `VacantEntry`.
    pub fn key(&self) -> usize {
        self.0.vacant_key().unwrap()
    }

    /// Inserts an item at the index returned by `key()`.
    pub fn insert(mut self, item: T) -> usize {
        self.0.insert(item).unwrap()
    }
}
