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

impl std::fmt::Debug for TxnHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", self.id)
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

#[cfg(test)]
mod tests {
    use super::{TxnId, TxnMgr};
    use futures::future::FutureExt;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Arc;
    use std::task::{Context, Poll, Waker};

    fn is_pending(f: &mut (impl Future + Unpin)) -> bool {
        matches!(
            pin!(f).poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        )
    }

    #[test]
    fn test_different_txn_ids() {
        let mgr = Arc::new(TxnMgr::new());

        let txn_a = mgr.open().now_or_never().unwrap();
        let txn_b = mgr.open().now_or_never().unwrap();
        let txn_c = mgr.open().now_or_never().unwrap();

        assert_ne!(txn_a.id(), txn_b.id());
        assert_ne!(txn_a.id(), txn_c.id());
        assert_ne!(txn_b.id(), txn_c.id());
    }

    #[test]
    fn test_txn_clone_get_identity() {
        let mgr = Arc::new(TxnMgr::new());

        let txn_a = mgr.open().now_or_never().unwrap();
        let txn_b = mgr.open().now_or_never().unwrap();
        let txn_a_clone = txn_a.clone();
        let txn_a_get = mgr.get(txn_a.id()).unwrap();

        assert_ne!(txn_a, txn_b);
        assert_ne!(txn_a_clone, txn_b);
        assert_ne!(txn_a_get, txn_b);
        assert_eq!(txn_a, txn_a);
        assert_eq!(txn_a, txn_a_clone);
        assert_eq!(txn_a, txn_a_get);
        assert_eq!(txn_a_clone, txn_a_get);
    }

    #[test]
    fn test_txn_get() {
        let mgr = Arc::new(TxnMgr::new());

        let txn_a = mgr.open().now_or_never().unwrap();
        let txn_b = mgr.open().now_or_never().unwrap();
        let txn_a_get = mgr.get(txn_a.id()).expect("couldn't find txn_a");
        let txn_b_get = mgr.get(txn_b.id()).expect("couldn't find txn_b");
        assert!(mgr.get(123).is_none(), "found non-existent transaction");

        assert_eq!(txn_a, txn_a_get);
        assert_eq!(txn_b, txn_b_get);
        assert_ne!(txn_a_get, txn_b_get);
    }

    #[test]
    fn test_txn_drop() {
        let mgr = Arc::new(TxnMgr::new());

        let txn_a = mgr.open().now_or_never().unwrap();
        let txn_b = mgr.open().now_or_never().unwrap();
        let txn_b_clone = txn_b.clone();
        let txn_b_get = mgr.get(txn_b.id()).expect("couldn't find txn_a");

        let txn_a_id = txn_a.id();
        let txn_b_id = txn_b.id();

        drop(txn_a);
        assert!(mgr.get(txn_a_id).is_none());
        assert!(mgr.get(txn_b_id).is_some());

        drop(txn_b);
        assert!(mgr.get(txn_b_id).is_some());

        drop(txn_b_clone);
        assert!(mgr.get(txn_b_id).is_some());

        drop(txn_b_get);
        assert!(mgr.get(txn_b_id).is_none());
    }

    #[test]
    fn test_blocking() {
        let mgr = Arc::new(TxnMgr::new());

        // burn a few first to test wrapping
        for _i in 0..3 {
            let _ = mgr.open().now_or_never().unwrap();
        }

        // we should be able to open the full space of txn IDs no problem
        let mut txns = Vec::new();
        for _i in 0..=TxnId::MAX {
            txns.push(mgr.open().now_or_never().unwrap());
        }

        // these should now block
        let mut should_block0 = Box::pin(mgr.open());
        let mut should_block1 = Box::pin(mgr.open());
        let mut should_block2 = Box::pin(mgr.open());
        assert!(is_pending(&mut should_block0));
        assert!(is_pending(&mut should_block1));
        assert!(is_pending(&mut should_block2));

        // close the oldest transactions to elicit different unblocking behaviors
        drop(txns.swap_remove(2));
        assert!(is_pending(&mut should_block0));
        assert!(is_pending(&mut should_block1));
        assert!(is_pending(&mut should_block2));

        drop(txns.swap_remove(0));
        should_block0
            .now_or_never()
            .expect("0 should have been unblocked");
        assert!(is_pending(&mut should_block1));
        assert!(is_pending(&mut should_block2));

        drop(txns.swap_remove(1));
        should_block1
            .now_or_never()
            .expect("1 should have been unblocked");
        should_block2
            .now_or_never()
            .expect("2 should have been unblocked");

        drop(txns);
    }
}
