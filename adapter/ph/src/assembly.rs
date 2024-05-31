use crate::config;
use crate::buffer_stack::BufferStack;
use crate::queues::*;

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
    pub outbound_send: OutboundSend<'pktbuf>
}
