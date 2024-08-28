use crate::adapter_tables::{AltEntry, AltPep};
use crate::assembly::{self, Assembly};
use crate::counters_enum::CounterType;
use crate::fastpath;
use crate::packet::Packet;
use crate::queues::AdapterManagerMessage;
use crate::zdp;
use crate::zpr;
use bytes::{Buf, BufMut};
use std::future::Future;
use tokio::sync::mpsc;
use zpr_ext::zerocopy::{AsBytesExt, FromBytesExt};

async fn worker<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    queue: &mut mpsc::Receiver<AdapterManagerMessage<'pktbuf>>,
) {
    while let Some(msg) = queue.recv().await {
        match msg {
            AdapterManagerMessage::RequestTetherId(pkt) => {
                // for now, perform these sequentially...
                // ideally, we place these into a JoinSet,
                // but let's work out how message sequencing works before doing that!!
                do_request_tether_id(asm, pkt).await;
            },
        }
    }
}

pub fn launch<'pktbuf>(
    asm: impl std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync + 'pktbuf,
    mut queue: mpsc::Receiver<AdapterManagerMessage<'pktbuf>>,
) -> impl Future<Output = ()> + Send + 'pktbuf
{
    async move { worker(&*asm, &mut queue).await }
}

// RFC 6.5 § 6.3.11
async fn do_request_tether_id<'pktbuf>(asm: &Assembly<'pktbuf>, pkt: Packet<'pktbuf>) {
    // TODO: node version... that just allocates a tether ID directly from the internal dock, no messages exchanged

    // just extract 5t and drop packet for now, storing & resending it later is a TODO
    let five_tuple = *pkt.metadata().five_tuple();
    fastpath::drop_and_count(asm, pkt, CounterType::DroppedAwaitingBind);

    // if there's already an entry, this is a duplicate request
    // (NOTE: we should be the only ones modifying this table!)
    if asm.alt.inspect(&five_tuple, |_entry| ()).is_some() {
        return;
    }

    // mark ALT entry as pending to attempt to (i.e. racily) prevent
    // fastpath from issuing multiple requests
    asm.alt.insert(five_tuple, AltEntry::Pending);

    // compress only IP addresses for now
    let compression_mode: zpr::CompressionMode = 0;

    eprintln!("Issuing bind request for {}", five_tuple);

    // send Bind request
    let response = asm.send_sync_per_flow_req(
        zdp::ZdpPacketType::BindAgentAddressRequest,
        zdp::ZdpPacketType::BindAgentAddressResponse,
        0, move |mut req| {
            zdp::ZdpBindAgentAddressRequestHeader {
                ip_version: five_tuple.l3_type,
                compression_mode,
            }.write_to_buf(&mut req);

            match five_tuple.l3_type {
                zpr::L3Type::Ipv4 => {
                    req.put(five_tuple.src_address.read_as_v4().as_slice());
                    req.put(five_tuple.dst_address.read_as_v4().as_slice());
                }

                zpr::L3Type::Ipv6 => {
                    req.put(five_tuple.src_address.v6.as_slice());
                    req.put(five_tuple.dst_address.v6.as_slice());
                }

                other => panic!("bad L3 type: {}", other.0),
            }

            req.put_u8(five_tuple.l4_protocol);

            if compression_mode != 0 {
                todo!("L4 compression");
            }
        }
    ).await;

    match interpret_bind_response(asm, response) {
        Ok(tether_id) => {
            // Bind succeeded; add to ALT.
            eprintln!("Bind of {} succeeded: {}", five_tuple, tether_id);
            asm.alt.alter(&five_tuple,
                |entry| {
                    assert!(matches!(entry, AltEntry::Pending));
                    *entry = AltEntry::Active(AltPep { compression_mode, tether_id });
                }).unwrap();
        }

        Err(err) => {
            // Bind failed; remove pending entry from ALT.
            eprintln!("Bind of {} failed: {}", five_tuple, err);
            asm.alt.remove(&five_tuple);
        }
    }
}

enum BindError {
    SyncReqError(assembly::SyncReqError),
    BadStructure,
    BindError(Box<str>),
}

impl std::fmt::Display for BindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::SyncReqError(err) => err.fmt(f),
            Self::BadStructure => write!(f, "bad structure"),
            Self::BindError(msg) => f.write_str(&*msg),
        }
    }
}

fn interpret_bind_response<'pktbuf>(asm: &Assembly<'pktbuf>, response: Result<(zpr::StreamId, Packet<'pktbuf>), assembly::SyncReqError>)
    -> Result<zpr::StreamId, BindError>
{
    match response {
        Ok((tether_id, mut resp)) => {
            let Some(hdr) = zdp::ZdpBindAgentAddressResponseHeader::read_from_buf(&mut resp) else {
                fastpath::drop_and_count(asm, resp, CounterType::BadStructure);
                return Err(BindError::BadStructure);
            };

            match hdr.status_code {
                zdp::ZdpBindAgentAddressResponseHeader::STATUS_CODE_SUCCESS => {
                    asm.buffer_stack.put_buffer(resp.destroy());
                    Ok(tether_id)
                }

                zdp::ZdpBindAgentAddressResponseHeader::STATUS_CODE_OTHER => {
                    if hdr.info_len as usize > resp.remaining() {
                        fastpath::drop_and_count(asm, resp, CounterType::BadStructure);
                        return Err(BindError::BadStructure);
                    }

                    let Ok(msg) = std::str::from_utf8(&resp.body()[..hdr.info_len as usize]) else {
                        fastpath::drop_and_count(asm, resp, CounterType::BadStructure);
                        return Err(BindError::BadStructure);
                    };
                    let msg: Box<str> = msg.into();

                    asm.buffer_stack.put_buffer(resp.destroy());
                    Err(BindError::BindError(msg))
                }

                _ => {
                    fastpath::drop_and_count(asm, resp, CounterType::BadStructure);
                    Err(BindError::BadStructure)
                }
            }
        }

        Err(err) =>
            Err(BindError::SyncReqError(err)),
    }
}
