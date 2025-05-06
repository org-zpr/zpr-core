//! "Two-way" queue.
//!
//! This multi-producer single-consumer queue differs from a standard queue
//! in that it does not transfer ownership of the items sent through it.
//! Rather, the consumer gets a (mutable) reference-only view of the item.
//! When the consumer is done with the item, its ownership is returned to
//! the producer which sent it through a return queue.  Items are returned
//! in the same order in which they are sent.
//!
//! Conceptually, one can think of this queue as a ring buffer in which the
//! consumer leaves items for the producer to later take back.
//!
//! Additional to the above functionality, the forward and return types may
//! differ if `TwoWayReturnable<Forward>` is implemented for the reverse
//! type.  (This is chosen instead of using `From` so that non-default conversions
//! can be used.)
//!
//! There are three components to any "two-way" queue flow.  Each "service"
//! to which items are being sent creates a single `Receiver` to receive
//! tiems on.  Each "client" which is sending items (to any number of
//! "services") creates a single `ReturnQueue` to receive returned items.
//! Then, for each client-server pairing, the client creates a `Sender` which
//! sends items to the given `Receiver`, to be returned on the client's own
//! `ReturnQueue`.
//!
//! The two main entry points to create all these objects are
//! `ReturnQueue::new()`, and `two_way_queue()`.  The former creates a
//! single `ReturnQueue`.  The latter creates a pair of a `SenderFactory`
//! and a `Receiver`.  The `SenderFactory` is then used to create `Sender`
//! instances linked to the `Receiver` and a supplied `ReturnQueue`.

#![allow(dead_code)]

use crate::sys::notify::Notify;
use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use std::os::fd::BorrowedFd;
use std::rc::Rc;
use std::sync::Arc;
use tokio::sync::mpsc;
use zpr_ext::std::cell::scalar::UsizeCell;

/// Trait representing a type which can be returned through a `TwoWayQueue`.
pub trait TwoWayReturnable<T> {
    /// Convert the received item into one to be returned to the producer.
    fn convert(value: T) -> Self;
}

impl<T> TwoWayReturnable<T> for T {
    fn convert(value: T) -> Self {
        value
    }
}

pub enum TrySendError<T> {
    Full(T),
    Closed(T),
}

pub enum TryRecvReturnError {
    Empty,
    Disconnected,
}

struct ReturnQueueHandleInner<U> {
    outgoing_return_q: mpsc::UnboundedSender<U>,
    notify: Notify,
}

type ReturnQueueHandle<U> = Arc<ReturnQueueHandleInner<U>>;

/// The return path of a two-way queue.
pub struct ReturnQueue<U> {
    incoming_return_q: mpsc::UnboundedReceiver<U>,
    handle: ReturnQueueHandle<U>,
    outstanding: Rc<UsizeCell>,
}

impl<U> ReturnQueue<U> {
    /// Construct a new return queue.
    pub fn new() -> Self {
        let (outgoing_return_q, incoming_return_q) = mpsc::unbounded_channel();

        let handle = ReturnQueueHandleInner {
            outgoing_return_q,
            notify: Notify::new().unwrap(),
        };

        Self {
            incoming_return_q,
            handle: Arc::new(handle),
            outstanding: Rc::new(UsizeCell::new(0)),
        }
    }

    /// Try to receive a single returned item.  Does not block, returning
    /// `None` if no items are immediately available (possibly because none
    /// are outstanding).
    pub fn try_recv_return(&mut self) -> Option<U> {
        if !self.handle.notify.consume() {
            return None;
        }

        let avail = self.incoming_return_q.len();

        let ret = self.incoming_return_q.try_recv().ok();
        if ret.is_some() {
            self.outstanding.fetch_sub(1);

            if avail > 1 {
                // It is likely that we ate the notification of these remaining items.
                // Re-post it.  (If we didn't eat it, this is harmless.)
                self.handle.notify.post();
            }
        }

        return ret;
    }

    /// Try to receive up to `limit` returned items.  Does not block,
    /// returning 0 if no items are immediately available (possibly because
    /// none are outstanding).
    pub fn try_recv_many_returns(&mut self, returns: &mut Vec<U>, limit: usize) -> usize {
        if !self.handle.notify.consume() {
            return 0;
        }

        let avail = self.incoming_return_q.len();
        if avail == 0 {
            return 0;
        }

        // Will not block, as we know something is there to receive.
        let recvd = self.incoming_return_q.blocking_recv_many(returns, limit);

        self.outstanding.fetch_sub(recvd);

        if avail > recvd {
            // It is likely that we ate the notification of these remaining items.
            // Re-post it.  (If we didn't eat it, this is harmless.)
            self.handle.notify.post();
        }

        return recvd;
    }

    pub fn poll_fd(&self) -> BorrowedFd<'_> {
        self.handle.notify.poll_fd()
    }
}

/// The producer half of a two-way queue.
pub struct Sender<T, U> {
    outgoing_q: mpsc::Sender<(T, ReturnQueueHandle<U>)>,
    return_q_handle: ReturnQueueHandle<U>,
    outstanding: Rc<UsizeCell>,
}

impl<T, U> Sender<T, U> {
    /// Try to send an item.  Note that it is possible for the queue
    /// to appear full for the reason that there are outstanding returns.
    pub fn try_send(&mut self, item: T) -> Result<(), TrySendError<T>> {
        match self
            .outgoing_q
            .try_send((item, self.return_q_handle.clone()))
        {
            Ok(()) => {
                self.outstanding.fetch_add(1);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full((item, _))) => Err(TrySendError::Full(item)),
            Err(mpsc::error::TrySendError::Closed((item, _))) => Err(TrySendError::Closed(item)),
        }
    }
}

/// `SenderFactory` is used to create `Sender` instances which send to the
/// associated `Receiver` and return items along the specified
/// `ReturnQueue`.
#[derive(Clone)]
pub struct SenderFactory<T, U> {
    outgoing_q: mpsc::Sender<(T, ReturnQueueHandle<U>)>,
}

impl<T, U> SenderFactory<T, U> {
    /// Construct a sender for the factory's associated receiver which returns items on the given return queue.
    pub fn make(&self, ret_q: &ReturnQueue<U>) -> Sender<T, U> {
        Sender {
            outgoing_q: self.outgoing_q.clone(),
            return_q_handle: ret_q.handle.clone(),
            outstanding: ret_q.outstanding.clone(),
        }
    }
}

/// The consumer half of a two-way queue.
pub struct Receiver<T, U> {
    incoming_q: mpsc::Receiver<(T, ReturnQueueHandle<U>)>,
}

impl<T, U> Receiver<T, U>
where
    U: TwoWayReturnable<T>,
{
    /// Asynchronously receive a single item from the producer.
    ///
    /// Returns `None` if-and-only-if the producer has closed its half.
    ///
    /// The item will be protected by the returned `ItemGuard`, and will be
    /// returned to the producer when the `ItemGuard` is dropped.
    ///
    /// If `U` implements `TwoWayReturnable<T>`, then the item will be
    /// transformed using `TwoWayReturnable::convert()` on its way back to
    /// the producer.
    pub async fn recv(&mut self) -> Option<ItemGuard<'_, T, U>> {
        let (item, return_q_handle) = self.incoming_q.recv().await?;
        Some(ItemGuard {
            item: ManuallyDrop::new(item),
            return_q_handle,
            receiver: PhantomData,
        })
    }
}

/// Guard for an item received from a two-way queue.
pub struct ItemGuard<'a, T, U: TwoWayReturnable<T>> {
    item: ManuallyDrop<T>,
    return_q_handle: ReturnQueueHandle<U>,
    receiver: PhantomData<&'a Receiver<T, U>>,
}

impl<T, U: TwoWayReturnable<T>> Deref for ItemGuard<'_, T, U> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.item
    }
}

impl<T, U: TwoWayReturnable<T>> DerefMut for ItemGuard<'_, T, U> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.item
    }
}

impl<T, U: TwoWayReturnable<T>> Drop for ItemGuard<'_, T, U> {
    fn drop(&mut self) {
        // SAFETY: because we are in the destructor, `take()` can never be called again
        let _ = self
            .return_q_handle
            .outgoing_return_q
            .send(U::convert(unsafe { ManuallyDrop::take(&mut self.item) }));

        self.return_q_handle.notify.post();
    }
}

/// Construct a receive queue of the specified size.
///
/// Also returns a `SenderFactory`, which can be used to create one or more
/// `Sender` instances associated with specified `ReturnQueue`s.
pub fn two_way_queue<T, U>(buffer: usize) -> (SenderFactory<T, U>, Receiver<T, U>) {
    let (outgoing_q, incoming_q) = mpsc::channel(buffer);
    (SenderFactory { outgoing_q }, Receiver { incoming_q })
}
