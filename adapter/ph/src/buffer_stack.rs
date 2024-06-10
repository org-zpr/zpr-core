use std::sync::Mutex;
use tokio::sync::Notify;

// This is used by the ingress stage to allocate buffers for incoming
// packets.  Buffers are reused in a LIFO manner to promote cache reuse.

pub struct BufferStack<'buf, const BUFSIZ: usize> {
    buffers: Mutex<Vec<&'buf mut [u8; BUFSIZ]>>,
    notify: Notify
}

impl<'buf, const BUFSIZ: usize> BufferStack<'buf, BUFSIZ> {
    pub const BUFFER_SIZE: usize = BUFSIZ;

    pub fn new<I>(bufs: I) -> Self where I: IntoIterator<Item = &'buf mut [u8; BUFSIZ]> {
        Self{buffers: Mutex::new(bufs.into_iter().collect()), notify: Notify::new()}
    }

    pub async fn get_buffer(&self) -> &'buf mut [u8; BUFSIZ] {
        loop {
            {
                let mut bufs = self.buffers.lock().unwrap();
                match bufs.pop() {
                    Some(buf) => return buf,
                    None => ()
                }
            }

            self.notify.notified().await;
        }
    }

    // Blocks until at least 1 buffer can be returned.
    // Returns up to n buffers.
    // Exception: if n is 0, returns immediately with no buffers.
    pub async fn get_buffers(
        &self, n: usize, bufs_out: &mut Vec<&'buf mut [u8; BUFSIZ]>
    ) -> usize {
        if n == 0 { return 0; }

        loop {
            {
                // `bufs` this needs to be lexically scoped as
                // Rust's non-lexical scope logic isn't smart enough yet
                // to figure out we don't need to hold the mutex over
                // the `await`, even with `drop(bufs)`!
                // hence the contorted logic here
                let mut bufs = self.buffers.lock().unwrap();
                let to_get = std::cmp::min(n, bufs.len());
                for _ in 0..to_get {
                    // note: intentional reversing!  keep bufs on top of stack hot
                    bufs_out.push(bufs.pop().unwrap());
                }
                if to_get > 0 { return to_get; }
            }

            self.notify.notified().await;
        }
    }

    pub fn put_buffer(&self, buf: &'buf mut [u8; BUFSIZ]) {
        let mut bufs = self.buffers.lock().unwrap();
        let was_empty = bufs.is_empty();
        bufs.push(buf);
        drop(bufs);
        if was_empty {
            self.notify.notify_waiters();
        }
    }

    pub fn put_buffers<I>(
        &self, bufs_in: I
    ) where I: IntoIterator<Item = &'buf mut [u8; BUFSIZ]> {
        let mut it = bufs_in.into_iter();
        match it.next() {
            Some(first_buf) => {
                let mut bufs = self.buffers.lock().unwrap();
                let was_empty = bufs.is_empty();
                bufs.push(first_buf);
                bufs.extend(it);
                drop(bufs);
                if was_empty {
                    self.notify.notify_waiters();
                }
            },

            None => ()  // avoid taking the lock
        }
    }
}
