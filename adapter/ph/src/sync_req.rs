use crate::packet::Packet;
use crate::zdp;
use std::future::Future;
use std::sync::{Arc, Mutex};
use tokio::sync::{oneshot, Semaphore, OwnedSemaphorePermit, TryAcquireError};

pub struct SyncReqState<'pktbuf> {
    state: Mutex<SyncReqStateInner<'pktbuf>>,
    semaphore: Arc<Semaphore>,
}

struct SyncReqStateInner<'pktbuf> {
    response_listener: Option<oneshot::Sender<Response<'pktbuf>>>,
}

pub type Response<'pktbuf> = (zdp::ZdpPacketType, Packet<'pktbuf>);

pub type Permit = OwnedSemaphorePermit;

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

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        std::pin::pin!(&mut self.receiver).poll(cx).map_err(|_| ResponseError())
    }
}

impl<'pktbuf> SyncReqState<'pktbuf> {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(SyncReqStateInner { response_listener: None }),
            semaphore: Arc::new(Semaphore::new(1)),
        }
    }

    pub fn acquire_permit(&self) -> impl Future<Output = Permit> {
        let sem = self.semaphore.clone();
        async { sem.acquire_owned().await.expect("coding error: semaphore closed") }
    }

    #[allow(dead_code)]
    pub fn try_acquire_permit(&self) -> Option<Permit> {
        match self.semaphore.clone().try_acquire_owned() {
            Ok(permit) => Some(permit),
            Err(TryAcquireError::Closed) => panic!("coding error: semaphore closed"),
            Err(TryAcquireError::NoPermits) => None,
        }
    }

    pub fn install_response_listener(&self) -> ResponseFuture<'pktbuf> {
        let (sender, receiver) = oneshot::channel();
        self.state.lock().unwrap().response_listener = Some(sender);
        ResponseFuture { receiver }
    }

    pub fn clear_response_listener(&self) {
        self.state.lock().unwrap().response_listener = None;
    }

    pub fn forward_response(&self, response: Response<'pktbuf>) -> Result<(), Packet<'pktbuf>> {
        match self.state.lock().unwrap().response_listener.take() {
            Some(sender) =>
                match sender.send(response) {
                    Ok(()) => Ok(()),
                    Err(response) => Err(response.1),
                },

            None => Err(response.1),
        }
    }
}
