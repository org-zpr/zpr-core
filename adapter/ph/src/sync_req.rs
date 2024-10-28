use crate::packet::Packet;
use crate::zdp;
use std::future::Future;
use std::sync::Mutex as StdMutex;
use tokio::sync::oneshot;
use tokio::sync::{Mutex as TokioMutex, MutexGuard as TokioMutexGuard};
use tracing::debug;
use zpr;

pub struct SyncReqState<'pktbuf> {
    listener_state: StdMutex<ListenerState<'pktbuf>>,
    window_state: TokioMutex<WindowState>,
}

struct ListenerState<'pktbuf> {
    response_listener: Option<(zpr::SeqNum, oneshot::Sender<Response<'pktbuf>>)>,
}

struct WindowState {
    next_seq_num: zpr::SeqNum,
}

pub type Response<'pktbuf> = (zdp::ZdpPacketType, Packet<'pktbuf>);

pub struct Permit<'a> {
    /// use our lock on the window state as a semaphore
    /// (this is an appropriate use of a tokio-Mutex which is
    /// essentially just a semaphore)
    window_state: TokioMutexGuard<'a, WindowState>,
    /// sequence number associated with this permit
    seq_num: zpr::SeqNum,
}

impl Permit<'_> {
    pub fn seq_num(&self) -> zpr::SeqNum {
        self.seq_num
    }
}

pub struct ResponseError();

pub struct ResponseFuture<'pktbuf> {
    receiver: oneshot::Receiver<Response<'pktbuf>>,
}

impl<'pktbuf> ResponseFuture<'pktbuf> {
    pub fn hangup(&mut self) -> Option<Response<'pktbuf>> {
        self.receiver.close();
        // catch any message which raced the close
        self.receiver.try_recv().ok()
    }
}

impl<'pktbuf> Future for ResponseFuture<'pktbuf> {
    type Output = Result<Response<'pktbuf>, ResponseError>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        std::pin::pin!(&mut self.receiver)
            .poll(cx)
            .map_err(|_| ResponseError())
    }
}

impl<'pktbuf> SyncReqState<'pktbuf> {
    pub fn new() -> Self {
        Self {
            listener_state: StdMutex::new(ListenerState {
                response_listener: None,
            }),
            // NOTE/TODO/FIXME: all the synchronization logic in this file
            // is only correct with window size == 1.  Growing the window
            // size (and implementing it correctly) is pending further
            // design decisions.
            window_state: TokioMutex::new(WindowState { next_seq_num: 0 }),
        }
    }

    pub async fn acquire_permit(&self) -> Permit {
        let mut window_state = self.window_state.lock().await;
        let seq_num = window_state.next_seq_num;
        window_state.next_seq_num += 1;
        Permit {
            window_state,
            seq_num,
        }
    }

    pub fn is_associated_permit(&self, permit: &Permit) -> bool {
        std::ptr::eq(
            TokioMutexGuard::mutex(&permit.window_state),
            &self.window_state,
        )
    }

    pub fn install_response_listener(&self, permit: &Permit) -> ResponseFuture<'pktbuf> {
        assert!(self.is_associated_permit(permit));
        let (sender, receiver) = oneshot::channel();
        self.listener_state.lock().unwrap().response_listener = Some((permit.seq_num(), sender));
        ResponseFuture { receiver }
    }

    pub fn clear_response_listener(&self, permit: &Permit) {
        assert!(self.is_associated_permit(permit));
        self.listener_state.lock().unwrap().response_listener = None;
    }

    pub fn forward_response(
        &self,
        seq_num: zpr::SeqNum,
        response: Response<'pktbuf>,
    ) -> Result<(), Packet<'pktbuf>> {
        let listener = &mut self.listener_state.lock().unwrap().response_listener;
        match listener {
            Some((expected_seq_num, _)) => {
                if seq_num != *expected_seq_num {
                    debug!("expected seq num {} got {}", expected_seq_num, seq_num);
                    return Err(response.1);
                }

                match listener.take().unwrap().1.send(response) {
                    Ok(()) => Ok(()),
                    Err(response) => Err(response.1),
                }
            }

            _ => Err(response.1),
        }
    }
}
