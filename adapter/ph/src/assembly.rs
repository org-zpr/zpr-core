use crate::buffer_stack::BufferStack;
use crate::capture_worker::CaptureWorker;
use crate::config;
use crate::counter::*;
use crate::counters_enum::*;
use crate::flow_control::FlowControl;
use crate::packet::Packet;
use crate::queues::*;
use crate::tun_ctl::TunCtl;
use crate::zdp;
use crate::zdp::*;
use bytes::Buf;
use enum_map::EnumMap;
use std::result::Result;
use tokio::sync::{
    oneshot::{channel, Sender},
    Mutex, Semaphore, SemaphorePermit,
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

pub struct SyncReqState<'pktbuf> {
    inner_req: Mutex<SyncReqInnerState<'pktbuf>>, // don't need to be pub now, may change in future
    semaphore: Semaphore,
}

pub struct SyncReqInnerState<'pktbuf> {
    reply_channel: Option<Sender<Packet<'pktbuf>>>,
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
}

pub enum SyncReqError {
    LinkClosed,
    ProtocolError,
}

impl<'pktbuf> Assembly<'pktbuf> {
    pub async fn send_sync_non_flow_req(
        &self,
        zdp_packet_type: zdp::ZdpPacketType,
        packet: Packet<'pktbuf>,
    ) -> Result<Packet<'pktbuf>, SyncReqError> {
        let permit: SemaphorePermit = self.sync_req_state.semaphore.acquire().await.unwrap(); // TODO error handling in case we don't get permit
        let (sender, receiver) = channel::<Packet<'pktbuf>>();
        {
            let mut inner_req = self.sync_req_state.inner_req.lock().await;
            inner_req.reply_channel = Some(sender);
        }
        let sent_hdr =
            ZdpBaseHeader::ref_from_prefix(packet.body()).expect("too-short inbound packet");
        let sent_pkt_type = sent_hdr.packet_type;

        self.outbound_processor
            .enqueue_non_flow_mgmt(zdp_packet_type, packet)
            .await;
        match receiver.await {
            Ok(mut rec_pkt) => {
                drop(permit);
                let rec_hdr = ZdpBaseHeader::ref_from_prefix(rec_pkt.body())
                    .expect("too-short inbound packet");
                if sent_pkt_type != rec_hdr.packet_type {
                    let ret_buf = rec_pkt.destroy();
                    self.buffer_stack.put_buffer(ret_buf);
                    self.counters[CounterType::BadMgmtResponse].increment();
                    return Err(SyncReqError::ProtocolError);
                }
                rec_pkt.advance(std::mem::size_of::<ZdpBaseHeader>());
                return Ok(rec_pkt);
            }
            Err(_) => return Err(SyncReqError::LinkClosed), // drop permit here as well? or will it automatically happen when the function gets popped off the call stack?
        }
    }

    pub async fn send_sync_per_flow_req(
        &self,
        zdp_packet_type: zdp::ZdpPacketType,
        stream_id: u32,
        packet: Packet<'pktbuf>,
    ) -> Result<(u32, Packet<'pktbuf>), SyncReqError> {
        let permit: SemaphorePermit = self.sync_req_state.semaphore.acquire().await.unwrap(); // TODO error handling in case we don't get permit
        let (sender, receiver) = channel::<Packet<'pktbuf>>();
        {
            let mut inner_req = self.sync_req_state.inner_req.lock().await;
            inner_req.reply_channel = Some(sender);
        }
        let sent_hdr =
            ZdpPerFlowHeader::ref_from_prefix(packet.body()).expect("too-short inbound packet"); // could also use ZdpBaseHeader here b/c the beginning of both headers are the same
        let sent_pkt_type = sent_hdr.base_header.packet_type;

        self.outbound_processor
            .enqueue_per_flow_mgmt(zdp_packet_type, stream_id, packet)
            .await;
        match receiver.await {
            Ok(mut rec_pkt) => {
                drop(permit);
                let rec_hdr = ZdpPerFlowHeader::ref_from_prefix(rec_pkt.body())
                    .expect("too-short inbound packet");
                if sent_pkt_type != rec_hdr.base_header.packet_type {
                    let ret_buf = rec_pkt.destroy();
                    self.buffer_stack.put_buffer(ret_buf);
                    self.counters[CounterType::BadMgmtResponse].increment();
                    return Err(SyncReqError::ProtocolError);
                }
                let rec_stream_id = rec_hdr.stream_id;
                rec_pkt.advance(std::mem::size_of::<ZdpPerFlowHeader>());
                return Ok((rec_stream_id, rec_pkt));
            }
            Err(_) => return Err(SyncReqError::LinkClosed),
        }
    }
}
