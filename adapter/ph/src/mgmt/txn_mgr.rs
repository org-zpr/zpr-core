//! ZDP transaction manager
//!
//! Simple struct to allocate ZDP transaction IDs.
//!
//! Transaction IDs have lifetimes defined by the individual ZDP messages
//! which use them, and are managed entirely by the message request sender:
//! they are blindly parroted by the recipient in responses.  Therefore
//! the sender only needs to coordinate with itself to ensure no overlapping
//! transaction IDs are used.
//!
//! This struct performs that coordination.  Transaction IDs are handed out
//! sequentially, as handles.  IDs are reserved until the corresponding handle
//! is dropped.  This may cause opening a transaction to block if the next ID
//! is still in use.

use std::collections::{btree_map, BTreeMap};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::Notify;

/// A transaction ID, suitable for use in a ZDP message.
pub type TxnId = u16;

/// A transaction handle, which wraps a transaction ID.
///
/// The wrapped transaction ID is reserved until this handle,
/// and all clones of it, are dropped.
///
/// Handles implement `Eq` and `Hash` and thus may be used as
/// keys in hash tables.
pub struct TxnHandle {
    mgr: Weak<TxnMgr>,
    id: TxnId,
}

impl TxnHandle {
    /// Returns the ID of this transaction.
    pub fn id(&self) -> TxnId {
        self.id
    }
}

impl Clone for TxnHandle {
    fn clone(&self) -> Self {
        if let Some(mgr) = self.mgr.upgrade() {
            mgr.ref_txn(self.id);
            Self {
                mgr: self.mgr.clone(),
                id: self.id,
            }
        } else {
            Self {
                mgr: Weak::default(),
                id: self.id,
            }
        }
    }
}

impl Drop for TxnHandle {
    fn drop(&mut self) {
        if let Some(mgr) = self.mgr.upgrade() {
            mgr.deref_txn(self.id);
        }
    }
}

impl PartialEq for TxnHandle {
    fn eq(&self, other: &Self) -> bool {
        self.mgr.ptr_eq(&other.mgr) && self.id == other.id
    }
}

impl Eq for TxnHandle {}

impl std::hash::Hash for TxnHandle {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.mgr.as_ptr().hash(state);
        self.id.hash(state);
    }
}

struct TxnMgrInner {
    /// The next transaction ID we want to use (which may not in fact be free).
    next_free: TxnId,
    /// Maps active transaction IDs to a refcount (0 being the initial reference).
    open: BTreeMap<TxnId, usize>,
}

/// ZDP transaction manager.
///
/// See module-level documentation for theory of use.
pub struct TxnMgr {
    inner: Mutex<TxnMgrInner>,
    /// Used to notify `open()` of possibly freed transaction ID.
    notify: Notify,
}

impl TxnMgr {
    /// Create a new transaction manager.
    pub fn new() -> Self {
        let inner = TxnMgrInner {
            next_free: 0,
            open: BTreeMap::new(),
        };

        Self {
            inner: Mutex::new(inner),
            notify: Notify::new(),
        }
    }

    /// Open a new transaction.
    ///
    /// Returns a handle to the transaction.
    ///
    /// The transaction will remain open until the handle is dropped.
    ///
    /// Blocks until a suitable transaction ID is available.
    pub async fn open(self: &Arc<Self>) -> TxnHandle {
        let id = self.open_raw().await;
        TxnHandle {
            mgr: Arc::downgrade(self),
            id,
        }
    }

    /// Get a handle to an existing transaction.
    ///
    /// This is primarily useful when looking up the transaction
    /// in a hash table keyed by the handle.
    pub fn get(self: &Arc<Self>, id: TxnId) -> Option<TxnHandle> {
        let mut inner = self.inner.lock().unwrap();
        let refcnt = inner.open.get_mut(&id)?;
        *refcnt += 1;
        Some(TxnHandle {
            mgr: Arc::downgrade(self),
            id,
        })
    }

    /// Open a new transaction, returning the raw ID.
    async fn open_raw(&self) -> TxnId {
        loop {
            // grab the lock
            let mut inner = self.inner.lock().unwrap();

            let next_free = inner.next_free;
            // If the ID we want is not in use,
            if let btree_map::Entry::Vacant(entry) = inner.open.entry(next_free) {
                // mark it as in-use and return it
                entry.insert(0);
                inner.next_free = inner.next_free.wrapping_add(1);
                return next_free;
            }

            // else, register to receive a notification when this changes
            // (note, we must register for the notification under lock
            // to avoid a missed notification!)
            let notified = self.notify.notified();

            // drop the lock
            drop(inner);

            // now wait for notification (which we registered for above under lock)
            notified.await;

            // and try again! (we might fail if someone else is racing us)
            //
            // (note, unless the scheduler is strongly fair (it's not) it's
            // possible under contention that we don't make progress; but
            // having to block for a transaction ID at all should be rare,
            // contending for one even more so, and being so unlucky as to
            // repeatedly lose the contention race yet more so, so we don't
            // worry about this)
        }
    }

    /// Increment the refcount of an open transaction.
    fn ref_txn(&self, id: TxnId) {
        let mut inner = self.inner.lock().unwrap();
        let Some(refcnt) = inner.open.get_mut(&id) else {
            panic!("reference of closed transaction");
        };

        *refcnt += 1;
    }

    /// Decrement the refcount of an open transaction.
    ///
    /// If no more references exist, close the transaction.
    fn deref_txn(&self, id: TxnId) {
        // grab the lock
        let mut inner = self.inner.lock().unwrap();

        let btree_map::Entry::Occupied(mut entry) = inner.open.entry(id) else {
            panic!("dereference of closed transaction");
        };

        let refcnt = entry.get_mut();
        if *refcnt > 0 {
            // if we're not the last reference, decrement the refcount and we're done
            *refcnt -= 1;
            return;
        }

        // we were the last reference: mark this ID as free
        entry.remove();

        // If the next desired ID is the one we just freed, it's possible
        // some calls to `open()` are waiting on a notification, so we'll want
        // to notify them that we've changed the situation.
        //
        // (Note that no-one can be waiting on the notify if this is _not_ true:
        // they register for notifications under lock only when this is true,
        // and any time we cause this to not be true, we bump all of them
        // out of the notify.)
        //
        // Only notifying when this is true allows us to skip taking the
        // (internal) notify lock for the vast majority of calls.
        let need_notify = inner.next_free == id;

        // drop the lock
        drop(inner);

        if need_notify {
            // If there are waiters to notify, do so, outside the lock
            // (to avoid them all immediately crashing into the lock) and
            // all en masse (because we may in fact unblock all of them
            // since we currently hand out IDs strictly sequentially).
            self.notify.notify_waiters();
        }
    }
}
