use crate::buffer_stack::BufferStack;
use crate::capture_worker::CaptureWorker;
use crate::config;
use crate::counter::*;
use crate::counters_enum::*;
use crate::fastpath;
use crate::flow_control::FlowControl;
use crate::mgmt;
use crate::packet::*;
use crate::queues::*;
use crate::tun_ctl::TunCtl;
use crate::zdp::*;
use crate::zpr;
use bytes::Buf;
use core::time::Duration;
use enum_map::EnumMap;
use std::result::Result;
use std::sync::Mutex;
use tokio::sync::{
    oneshot::{channel, Sender},
    Semaphore, SemaphorePermit,
};
use tokio::time::sleep;
use zerocopy::FromBytes;
use zpr_ext::std::mem::{drop_guard, DropGuard};

/// Interface to full assembly of all stages.
///
/// This is the "public interface" that all stages of the system use to talk
/// to each other (via queues), and to shared resources (e.g. the buffer stack).
///
/// All queues and shared resources here should be bounded, so that
/// backpressure can flow from any processing stage all the way back to the
/// kernel network ingest queues, and that service time of any packet
/// transiting the system is not permitted to grow indefinitely under
/// pressure.
///
/// The intention is that there are no hidden unbounded queues in the system
/// (such as a mutex held over a blocking operation).  If a resource is
/// highly contended resulting in a bottleneck, that should result in some
/// visible queue becoming full.

pub struct Assembly<'pktbuf> {
    // Shared resources.  These may be accessed by any part of the system.
    pub buffer_stack: BufferStack<'pktbuf, { config::PACKET_BUFFER_SIZE }>,

    pub mgmt_processor: MgmtProcessor<'pktbuf>,
    pub agent_input: AgentInput<'pktbuf>,
    pub substrate_egress: SubstrateEgress<'pktbuf>,

    // Used to intercept packets that are unencrypted but still have ZDP headers
    pub capture_queue: Capture<'pktbuf>,
    pub capture_worker: CaptureWorker,
    pub flow_control: FlowControl,

    pub counters: EnumMap<CounterType, Counter>,

    pub tun_ctl: TunCtl<'pktbuf>,

    pub sync_req_state: SyncReqState<'pktbuf>,
}

pub struct SyncReqState<'pktbuf> {
    inner_req: Mutex<SyncReqInnerState<'pktbuf>>,
    semaphore: Semaphore,
}

struct SyncReqInnerState<'pktbuf> {
    reply_channel: Option<Sender<(Packet<'pktbuf>, ZdpPacketType)>>,
}

impl<'pktbuf> SyncReqState<'pktbuf> {
    pub fn new() -> Self {
        Self {
            inner_req: SyncReqInnerState {
                reply_channel: None,
            }
            .into(),
            semaphore: Semaphore::new(1),
        }
    }
    pub fn get_sender(&self) -> Option<Sender<(Packet<'pktbuf>, ZdpPacketType)>> {
        self.inner_req.lock().unwrap().reply_channel.take()
    }

    // Private to prevent a rogue agent from setting the sender.
    fn set_sender(&self, sender: Option<Sender<(Packet<'pktbuf>, ZdpPacketType)>>) {
        let mut inner_req = self.inner_req.lock().unwrap();
        inner_req.reply_channel = sender;
    }
}

#[allow(dead_code)]
pub enum SyncReqError {
    LinkClosed,
    ProtocolError,
    Timeout,
}

impl<'pktbuf> Assembly<'pktbuf> {
    /// Sender function for non-per flow request management packet.
    /// Requires the type of ZDP packet being sent as well as the type of the
    /// expected response packet.
    /// pkt_fn allows the function to create the proper body of the ZDP packet to send
    /// Returns the received packet without any ZdpHeader (just management response body) or an error
    pub async fn send_sync_non_flow_req(
        &self,
        zdp_request_type: ZdpPacketType,
        zdp_response_type: ZdpPacketType,
        pkt_fn: impl Fn(&mut Packet<'_>) + Send + 'static,
    ) -> Result<Packet<'pktbuf>, SyncReqError> {
        self.send_sync_req_helper(zdp_request_type, zdp_response_type, None, pkt_fn)
            .await
    }

    /// Sender function for per flow request management packet.
    /// Requires the type of ZDP packet being sent as well as the type of the
    /// expected response packet. Also requires stream_id of the packet.
    /// pkt_fn allows the function to create the proper body of the ZDP packet to send
    /// Returns the received packet without any ZdpHeader (just management response body) or an error
    #[allow(dead_code)]
    pub async fn send_sync_per_flow_req(
        &self,
        zdp_request_type: ZdpPacketType,
        zdp_response_type: ZdpPacketType,
        stream_id: u32,
        pkt_fn: impl Fn(&mut Packet<'_>) + Send + 'static,
    ) -> Result<(u32, Packet<'pktbuf>), SyncReqError> {
        match self
            .send_sync_req_helper(zdp_request_type, zdp_response_type, Some(stream_id), pkt_fn)
            .await
        {
            Ok(mut pkt) => {
                let per_flow_hdr = ZdpPerFlowHeader::ref_from_prefix(pkt.body())
                    .expect("too-short inbound packet");
                let stream_id = per_flow_hdr.stream_id;
                pkt.advance(std::mem::size_of::<ZdpPerFlowHeader>());
                Ok((stream_id.into(), pkt))
            }
            Err(err) => Err(err),
        }
    }

    /// Helper for send management request function
    /// Requires the type of ZDP packet being sent as well as the type of the
    /// expected response packet. The Option determines whether the function is helping the per-flow or
    /// non-per flow sender.
    /// pkt_fn allows the function to create the proper body of the ZDP packet to send
    /// Returns the received packet without the ZdpBaseHeader, but still any other Zdp header information
    /// not included in the ZdpBaseHeader, or an error
    async fn send_sync_req_helper(
        &self,
        zdp_request_type: ZdpPacketType,
        zdp_response_type: ZdpPacketType,
        stream_id: Option<u32>,
        pkt_fn: impl Fn(&mut Packet<'_>) + Send + 'static,
    ) -> Result<Packet<'pktbuf>, SyncReqError> {
        let permit: SemaphorePermit = self.sync_req_state.semaphore.acquire().await.unwrap(); // TODO error handling in case we don't get permit
        let (sender, mut receiver) = channel::<(Packet<'pktbuf>, ZdpPacketType)>();

        self.sync_req_state.set_sender(Some(sender));

        for _i in 0..=config::DEFAULT_REQUEST_RETRY_COUNT {
            let buf = drop_guard(self.buffer_stack.get_buffer().await, |buf| {
                self.buffer_stack.put_buffer(buf)
            });
            let mut packet = Packet::new_guarded(buf, config::DEFAULT_MESSAGE_HEADROOM);
            pkt_fn(&mut packet);

            // Determine if sending a non-flow or per-flow message
            match stream_id {
                Some(stream_id) => {
                    mgmt::send_per_flow_mgmt(
                        self,
                        zpr::ADAPTER_DOCKING_SESSION_ID, /* FIXME */
                        zdp_request_type,
                        stream_id,
                        packet.into_inner(),
                    );
                }
                None => {
                    mgmt::send_non_flow_mgmt(
                        self,
                        zpr::ADAPTER_DOCKING_SESSION_ID, /* FIXME */
                        zdp_request_type,
                        packet.into_inner(),
                    );
                }
            }
            tokio::select! {
                received_val = &mut receiver => {
                    drop(permit);
                    return self.match_received(received_val, SyncReqError::LinkClosed, zdp_response_type);
                }
                _ = sleep(Duration::from_secs(config::DEFAULT_REQUEST_RETRY_TIMER as u64)) => ()
            }
        }
        self.sync_req_state.set_sender(None);
        receiver.close();
        drop(permit);
        return self.match_received(
            receiver.try_recv(),
            SyncReqError::Timeout,
            zdp_response_type,
        );
    }

    fn match_received<T>(
        &self,
        result: Result<(Packet<'pktbuf>, ZdpPacketType), T>,
        err_type: SyncReqError,
        zdp_response_type: ZdpPacketType,
    ) -> Result<Packet<'pktbuf>, SyncReqError> {
        match result {
            Ok(rec_tuple) => {
                if zdp_response_type != rec_tuple.1 {
                    fastpath::drop_and_count(self, rec_tuple.0, CounterType::BadMgmtResponse);
                    return Err(SyncReqError::ProtocolError);
                }
                return Ok(rec_tuple.0);
            }
            Err(_) => return Err(err_type),
        }
    }

    pub async fn send_hello_req(&self) {
        let response = self
            .send_sync_non_flow_req(
                ZdpPacketType::HelloRequest,
                ZdpPacketType::HelloResponse,
                move |_packet| {},
            )
            .await;
        match response {
            Ok(hello_res) => {
                let hdr = ZdpHelloResponseHeader::ref_from_prefix(hello_res.body())
                    .expect("too-short inbound packet");
                let status = hdr.status;
                println!("Received HelloResponse, status: {}", status);
            }
            Err(err) => match err {
                SyncReqError::LinkClosed => eprintln!("LinkClosed error with HelloRequest"),
                SyncReqError::ProtocolError => eprintln!("ProtocolError error with HelloRequest"),
                SyncReqError::Timeout => eprintln!("Timeout error with HelloRequest"),
            },
        }
    }
}
