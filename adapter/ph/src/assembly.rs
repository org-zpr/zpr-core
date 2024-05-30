// Interface to full assembly of all stages.

use crate::config;
use crate::buffer_stack::BufferStack;
use crate::queues::*;

pub struct Assembly<'pktbuf> {
    pub buffer_stack: BufferStack<'pktbuf, { config::PACKET_BUFFER_SIZE }>,
    pub inbound_processor: InboundProcessor<'pktbuf>,
    pub inbound_send: InboundSend<'pktbuf>,
    pub outbound_processor: OutboundProcessor<'pktbuf>,
    pub outbound_send: OutboundSend<'pktbuf>
}
