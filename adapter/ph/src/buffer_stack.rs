use std::ops::{Deref, DerefMut};
use std::sync::Mutex;
use tokio::sync::Notify;
use zpr_ext::std::mem::{drop_guard, DropGuard};

#[cfg(test)]
tokio::task_local! {
    static BARRIER: &tokio::sync::Barrier;
}

macro_rules! test_barrier_wait {
    () => {
        #[cfg(test)]
        match BARRIER.try_with(|b| b.wait()) {
            Ok(b) => {
                b.await;
            }
            Err(_) => (),
        }
    };
}

/// This is used by the ingress stage to allocate buffers for incoming
/// packets.  Buffers are reused in a LIFO manner to promote cache reuse.
pub struct BufferStack<const BUFSIZ: usize> {
    buffers: Mutex<Vec<Box<[u8; BUFSIZ]>>>,
    notify: Notify,
}

/// Owning reference to a buffer allocated from the stack.
pub struct Buffer<const BUFSIZ: usize>(Box<[u8; BUFSIZ]>);

impl<const BUFSIZ: usize> Deref for Buffer<BUFSIZ> {
    type Target = [u8; BUFSIZ];

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl<const BUFSIZ: usize> DerefMut for Buffer<BUFSIZ> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}

#[allow(dead_code)]
impl<const BUFSIZ: usize> BufferStack<BUFSIZ> {
    pub const BUFFER_SIZE: usize = BUFSIZ;

    pub fn new<I>(bufs: I) -> Self
    where
        I: IntoIterator<Item = Box<[u8; BUFSIZ]>>,
    {
        Self {
            buffers: Mutex::new(bufs.into_iter().collect()),
            notify: Notify::new(),
        }
    }

    /// Blocks until a single buffer can be returned.
    pub async fn get_buffer(&self) -> Buffer<BUFSIZ> {
        loop {
            test_barrier_wait!();

            let notified = {
                let mut bufs = self.buffers.lock().unwrap();

                match bufs.pop() {
                    Some(buf) => break Buffer(buf),
                    None => (),
                }

                // register for notifications before dropping the mutex
                // to avoid lost notification (and therefore hanging)
                let notified = self.notify.notified();

                drop(bufs);

                notified
            };

            test_barrier_wait!();

            notified.await;
        }
    }

    /// Same as `get_buffer()`, but returns the buffer in a `DropGuard`
    /// which will automatically return the buffer to the pool if it goes
    /// out of scope.
    pub async fn get_buffer_guarded(&self) -> impl DropGuard<Buffer<BUFSIZ>> + '_ {
        drop_guard(self.get_buffer().await, |buf| self.put_buffer(buf))
    }

    /// Attempts to acquire a single buffer.  Does not block.
    pub fn try_get_buffer(&self) -> Option<Buffer<BUFSIZ>> {
        self.buffers.lock().unwrap().pop().map(|b| Buffer(b))
    }

    /// Blocks until at least 1 buffer can be returned.
    /// Returns up to n buffers.
    /// Exception: if n is 0, returns immediately with no buffers.
    pub async fn get_buffers(&self, n: usize, bufs_out: &mut Vec<Buffer<BUFSIZ>>) -> usize {
        if n == 0 {
            return 0;
        }

        loop {
            test_barrier_wait!();

            let notified = {
                let mut bufs = self.buffers.lock().unwrap();

                let to_get = std::cmp::min(n, bufs.len());

                for _ in 0..to_get {
                    // note: intentional reversing!  keep bufs on top of stack hot
                    bufs_out.push(Buffer(bufs.pop().unwrap()));
                }

                if to_get > 0 {
                    break to_get;
                }

                // register for notifications before dropping the mutex
                // to avoid lost notification (and therefore hanging)
                let notified = self.notify.notified();

                drop(bufs);

                notified
            };

            test_barrier_wait!();

            notified.await;
        }
    }

    /// Does not block.  May return 0 if no buffers could be returned.
    /// Returns up to n buffers.
    pub fn try_get_buffers(&self, n: usize, bufs_out: &mut Vec<Buffer<BUFSIZ>>) -> usize {
        if n == 0 {
            return 0;
        }

        let mut bufs = self.buffers.lock().unwrap();

        let to_get = std::cmp::min(n, bufs.len());

        for _ in 0..to_get {
            // note: intentional reversing!  keep bufs on top of stack hot
            bufs_out.push(Buffer(bufs.pop().unwrap()));
        }

        to_get
    }

    /// Returns a single buffer.  Does not block.
    pub fn put_buffer(&self, buf: Buffer<BUFSIZ>) {
        let mut bufs = self.buffers.lock().unwrap();
        let was_empty = bufs.is_empty();
        bufs.push(buf.0);
        drop(bufs);
        if was_empty {
            self.notify.notify_waiters();
        }
    }

    /// Returns all buffers in the given collection.  Does not block.
    pub fn put_buffers<I>(&self, bufs_in: I)
    where
        I: IntoIterator<Item = Buffer<BUFSIZ>>,
    {
        let mut it = bufs_in.into_iter();
        match it.next() {
            Some(first_buf) => {
                let mut bufs = self.buffers.lock().unwrap();
                let was_empty = bufs.is_empty();
                bufs.push(first_buf.0);
                for buf in it {
                    bufs.push(buf.0);
                }
                drop(bufs);
                if was_empty {
                    self.notify.notify_waiters();
                }
            }

            None => (), // avoid taking the lock
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_buffer_notify_race() {
        let buf = Box::new([0u8; 1]);
        let bs = Box::leak(Box::new(BufferStack::<1>::new([])));
        let barrier = Box::leak(Box::new(tokio::sync::Barrier::new(2)));
        let gb_task = tokio::task::spawn(BARRIER.scope(barrier, bs.get_buffer()));

        // allow gb_task to discover that there are no buffers
        barrier.wait().await;

        // add a buffer
        bs.put_buffer(Buffer(buf));

        // allow gb_task to register for notifications
        barrier.wait().await;

        // allow gb_task to discover the now-present buffer
        barrier.wait().await;

        // confirm that gb_task is now ready
        let _buf = tokio::select! {
            biased;
            res = gb_task => res.unwrap(),
            () = std::future::ready(()) => panic!("deadlock"),
        };
    }

    #[tokio::test]
    async fn get_buffers_notify_race() {
        let buf = Box::new([0u8; 1]);
        let bs = Box::leak(Box::new(BufferStack::<1>::new([])));
        let barrier = Box::leak(Box::new(tokio::sync::Barrier::new(2)));
        let gb_task = tokio::task::spawn(BARRIER.scope(barrier, async {
            let mut vec = Vec::new();
            bs.get_buffers(1, &mut vec).await
        }));

        // allow gb_task to discover that there are no buffers
        barrier.wait().await;

        // add a buffer
        bs.put_buffer(Buffer(buf));

        // allow gb_task to register for notifications
        barrier.wait().await;

        // allow gb_task to discover the now-present buffer
        barrier.wait().await;

        // confirm that gb_task is now ready
        let _buf = tokio::select! {
            biased;
            res = gb_task => res.unwrap(),
            () = std::future::ready(()) => panic!("deadlock"),
        };
    }
}
