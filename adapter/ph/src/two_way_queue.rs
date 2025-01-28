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

#![allow(dead_code)]

use std::marker::PhantomData;
use std::mem::ManuallyDrop;
use std::ops::{Deref, DerefMut};
use tokio::sync::mpsc;

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

/// The producer half of a two-way queue.
pub struct Sender<T, U> {
    outgoing_q: mpsc::Sender<(T, mpsc::UnboundedSender<U>)>,
    outgoing_return_q: mpsc::UnboundedSender<U>,
    incoming_return_q: mpsc::UnboundedReceiver<U>,
    outstanding: usize,
}

impl<T, U> Sender<T, U> {
    /// Try to send an item.  Note that it is possible for the queue
    /// to appear full for the reason that there are outstanding returns.
    pub fn try_send(&mut self, item: T) -> Result<(), TrySendError<T>> {
        match self
            .outgoing_q
            .try_send((item, self.outgoing_return_q.clone()))
        {
            Ok(()) => {
                self.outstanding += 1;
                Ok(())
            }
            Err(mpsc::error::TrySendError::Full((item, _))) => Err(TrySendError::Full(item)),
            Err(mpsc::error::TrySendError::Closed((item, _))) => Err(TrySendError::Closed(item)),
        }
    }

    /// Receive a single returned item.  Blocks until there is such an item.
    ///
    /// Panics if called when no items are outstanding.
    pub fn blocking_recv_return(&mut self) -> U {
        assert!(self.outstanding > 0);
        let ret = self.incoming_return_q.blocking_recv().unwrap();
        self.outstanding -= 1;
        return ret;
    }

    /// Receive up to `limit` returned items.  Blocks until at least one item can be returned.
    ///
    /// Immediately returns 0 if-and-only-if `limit` is 0.
    ///
    /// Panics if called when no items are outstanding.
    pub fn blocking_recv_many_returns(&mut self, returns: &mut Vec<U>, limit: usize) -> usize {
        assert!(self.outstanding > 0 || limit == 0);
        let ret = self.incoming_return_q.blocking_recv_many(returns, limit);
        self.outstanding -= ret;
        return ret;
    }

    /// Try to receive a single returned item.  Does not block, returning
    /// `None` if no items are immediately available (possibly because none
    /// are outstanding).
    pub fn try_recv_return(&mut self) -> Option<U> {
        let ret = self.incoming_return_q.try_recv().ok();
        if ret.is_some() {
            self.outstanding -= 1;
        }
        return ret;
    }

    /// Try to receive up to `limit` returned items.  Does not block,
    /// returning 0 if no items are immediately available (possibly because
    /// none are outstanding).
    pub fn try_recv_many_returns(&mut self, returns: &mut Vec<U>, limit: usize) -> usize {
        for i in 0..limit {
            match self.incoming_return_q.try_recv() {
                Ok(item) => returns.push(item),
                Err(_) => {
                    self.outstanding -= i;
                    return i;
                }
            }
        }

        self.outstanding -= limit;
        return limit;
    }

    /// Async version of `blocking_recv_return()`.
    pub async fn recv_return(&mut self) -> U {
        let ret = self.incoming_return_q.recv().await.unwrap();
        self.outstanding -= 1;
        return ret;
    }

    /// Async version of `blocking_recv_many_returns()`.
    pub async fn recv_many_returns(&mut self, returns: &mut Vec<U>, limit: usize) -> usize {
        let ret = self.incoming_return_q.recv_many(returns, limit).await;
        self.outstanding -= ret;
        return ret;
    }
}

impl<T, U> Clone for Sender<T, U> {
    fn clone(&self) -> Self {
        let (outgoing_return_q, incoming_return_q) = mpsc::unbounded_channel();
        Self {
            outgoing_q: self.outgoing_q.clone(),
            outgoing_return_q,
            incoming_return_q,
            outstanding: 0,
        }
    }
}

/// The consumer half of a two-way queue.
pub struct Receiver<T, U> {
    incoming_q: mpsc::Receiver<(T, mpsc::UnboundedSender<U>)>,
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
        let (item, outgoing_return_q) = self.incoming_q.recv().await?;
        Some(ItemGuard {
            item: ManuallyDrop::new(item),
            outgoing_return_q,
            receiver: PhantomData,
        })
    }
}

/// Guard for an item received from a two-way queue.
pub struct ItemGuard<'a, T, U: TwoWayReturnable<T>> {
    item: ManuallyDrop<T>,
    outgoing_return_q: mpsc::UnboundedSender<U>,
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
            .outgoing_return_q
            .send(U::convert(unsafe { ManuallyDrop::take(&mut self.item) }));
    }
}

/// Construct a send-receive pair for a two-way queue.
pub fn two_way_queue<T, U>(buffer: usize) -> (Sender<T, U>, Receiver<T, U>) {
    let (outgoing_q, incoming_q) = mpsc::channel(buffer);
    let (outgoing_return_q, incoming_return_q) = mpsc::unbounded_channel();
    (
        Sender {
            outgoing_q,
            outgoing_return_q,
            incoming_return_q,
            outstanding: 0,
        },
        Receiver { incoming_q },
    )
}
