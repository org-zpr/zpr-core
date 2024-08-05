use crate::buffer_stack::BufferStack;
use crate::capture_worker::CaptureWorker;
use crate::config;
use crate::counter::*;
use crate::counters_enum::*;
use crate::flow_control::FlowControl;
use crate::packet::*;
use crate::queues::*;
use crate::tun_ctl::TunCtl;
use crate::zdp::*;
use bytes::{Buf, BufMut};
use enum_map::EnumMap;
use std::result::Result;
use std::sync::Mutex;
use tokio::sync::{
    oneshot::{channel, Sender},
    Semaphore, SemaphorePermit,
};
use zerocopy::FromBytes;

// Interface to full assembly of all stages.

// This is the "public interface" that all stages of the system use to talk
// to each other (via queues), and to shared resources (e.g. the buffer stack).

// All queues and shared resources here should be bounded, so that
// backpressure can flow from any processing stage all the way back to the
// kernel network ingest queues, and that service time of any packet
// transiting the system is not permitted to grow indefinitely under
// pressure.

// The intention is that there are no hidden unbounded queues in the system
// (such as a mutex held over a blocking operation).  If a resource is
// highly contended resulting in a bottleneck, that should result in some
// visible queue becoming full.

pub struct Assembly<'pktbuf> {
    // Shared resources.  These may be accessed by any part of the system.
    pub buffer_stack: BufferStack<'pktbuf, { config::PACKET_BUFFER_SIZE }>,

    // Inbound (dock->adapter) agent packet path.  Keep these topologically
    // sorted according to expected packet flow.
    pub inbound_processor: InboundProcessor<'pktbuf>,
    pub inbound_send: InboundSend<'pktbuf>,

    // Outbound (adapter->dock) agent packet path.  Keep these topologically
    // sorted according to expected packet flow.
    pub outbound_processor: OutboundProcessor<'pktbuf>,
    pub outbound_send: OutboundSend<'pktbuf>,

    // Used to intercept packets that are unencrypted but still have ZDP headers
    pub capture_queue: Capture<'pktbuf>,
    pub capture_worker: CaptureWorker,
    pub flow_control: FlowControl,

    pub counters: EnumMap<CounterType, Counter>,

    pub tun_ctl: TunCtl<'pktbuf>,

    pub sync_req_state: SyncReqState<'pktbuf>,
}

#[allow(dead_code)]
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
}

#[allow(dead_code)]
pub enum SyncReqError {
    LinkClosed,
    ProtocolError,
}

impl<'pktbuf> Assembly<'pktbuf> {
    async fn send_sync_req_helper(
        &self,
        zdp_request_type: ZdpPacketType,
        zdp_response_type: ZdpPacketType,
        stream_id: Option<u32>,
        packet: Packet<'pktbuf>,
    ) -> Result<Packet<'pktbuf>, SyncReqError> {
        let permit: SemaphorePermit = self.sync_req_state.semaphore.acquire().await.unwrap(); // TODO error handling in case we don't get permit
        let (sender, receiver) = channel::<(Packet<'pktbuf>, ZdpPacketType)>();
        {
            let mut inner_req = self.sync_req_state.inner_req.lock().unwrap();
            inner_req.reply_channel = Some(sender);
        }

        // Determine if sending a non-flow or per-flow message
        match stream_id {
            Some(stream_id) => {
                self.outbound_processor
                    .enqueue_per_flow_mgmt(zdp_request_type, stream_id, packet)
                    .await
            }
            None => {
                self.outbound_processor
                    .enqueue_non_flow_mgmt(zdp_request_type, packet)
                    .await
            }
        }

        // Check received packet type, remove base header
        match receiver.await {
            Ok(rec_tuple) => {
                drop(permit);
                if zdp_response_type != rec_tuple.1 {
                    let ret_buf = rec_tuple.0.destroy();
                    self.buffer_stack.put_buffer(ret_buf);
                    self.counters[CounterType::BadMgmtResponse].increment();
                    return Err(SyncReqError::ProtocolError);
                }
                Ok(rec_tuple.0)
            }
            Err(_) => return Err(SyncReqError::LinkClosed),
        }
    }

    #[allow(dead_code)]
    pub async fn send_sync_non_flow_req(
        &self,
        zdp_request_type: ZdpPacketType,
        zdp_response_type: ZdpPacketType,
        packet: Packet<'pktbuf>,
    ) -> Result<Packet<'pktbuf>, SyncReqError> {
        self.send_sync_req_helper(zdp_request_type, zdp_response_type, None, packet)
            .await
    }

    #[allow(dead_code)]
    pub async fn send_sync_per_flow_req(
        &self,
        zdp_request_type: ZdpPacketType,
        zdp_response_type: ZdpPacketType,
        stream_id: u32,
        packet: Packet<'pktbuf>,
    ) -> Result<(u32, Packet<'pktbuf>), SyncReqError> {
        match self
            .send_sync_req_helper(zdp_request_type, zdp_response_type, Some(stream_id), packet)
            .await
        {
            Ok(mut pkt) => {
                let per_flow_hdr = ZdpPerFlowHeader::ref_from_prefix(pkt.body())
                    .expect("too-short inbound packet");
                let stream_id = per_flow_hdr.stream_id;
                pkt.advance(std::mem::size_of::<ZdpPerFlowHeader>());
                Ok((stream_id, pkt))
            }
            Err(err) => Err(err),
        }
    }

    pub async fn send_report(&self, to_send: &str) {
        // this condition will need to be adjusted when we have complete ZPR packets
        // with the information at the end of the packet at well
        if PACKET_BUFFER_MAX_BODY_SIZE - config::DEFAULT_MESSAGE_HEADROOM < to_send.len() {
            return;
        }
        let buf = self.buffer_stack.get_buffer().await;
        let mut pkt = Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM);
        let hdr = pkt.alloc_zeroed_header::<ZdpReportHeader>();
        hdr.report_data_length = to_send.len() as u16;
        pkt.put(to_send.as_bytes());
        self.outbound_processor
            .enqueue_non_flow_mgmt(ZdpPacketType::Report, pkt)
            .await;
    }

    pub async fn send_discard(&self) {
        let buf = self.buffer_stack.get_buffer().await;
        let pkt = Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM);
        self.outbound_processor
            .enqueue_non_flow_mgmt(ZdpPacketType::Discard, pkt)
            .await;
    }

    pub async fn send_hello_req(&self) {
        let buf = self.buffer_stack.get_buffer().await;
        let hello_req = Packet::new(buf, config::DEFAULT_MESSAGE_HEADROOM);
        let response = self
            .send_sync_non_flow_req(
                ZdpPacketType::HelloRequest,
                ZdpPacketType::HelloResponse,
                hello_req,
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
            },
        }
    }
}
