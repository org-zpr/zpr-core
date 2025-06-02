//! Handlers for management requests.

use crate::adapter_tables;
use crate::assembly::{self, Assembly, PhMode};
use crate::auth;
use crate::config;
use crate::counters;
use crate::defs::*;
use crate::link_state::LinkEvent;
use crate::logging::targets::{FLOW_MGMT, REPORTING, ZDP};
use crate::net_defs::IpAddress;
use crate::packet::Packet;
use crate::zdp;
use bytes::{Buf, BufMut};
use std::num::NonZero;
use std::sync::Arc;
use thiserror::Error;
use tracing::*;
use zpr;
use zpr_ext::zerocopy::{FromBytesExt, IntoBytesExt};

/// Indicates whether the mgmt message was handled successfully.
/// (It may be the case that the mgmt message itself indicates
/// failure of a remote operation; modulo a parsing issue,
/// handling such a message would still be considered successful.)
#[derive(Debug, Error)]
pub enum HandleMgmtError {
    #[error("unknown packet type: {0}")]
    UnknownType(u8),
    #[error("bad packet structure")]
    BadStructure,
}

impl From<HandleMgmtError> for counters::CounterType {
    fn from(err: HandleMgmtError) -> Self {
        match err {
            HandleMgmtError::UnknownType(_type) => Self::UnknownType,
            HandleMgmtError::BadStructure => Self::BadStructure,
        }
    }
}

pub type HandleMgmtResult = Result<(), (HandleMgmtError, Packet)>;

/// handle a Report message (RFC 6.5 § 6.3.13)
pub async fn handle_report(_asm: &Arc<Assembly>, mut pkt: Packet) -> HandleMgmtResult {
    let Ok(hdr) = zdp::ZdpReportHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    // TODO handle protocol errors i.e. if the body is shorter
    let report_data_length: usize = hdr.report_data_length.into();
    pkt.advance(std::mem::size_of::<zdp::ZdpReportHeader>());
    if pkt.body().len() >= report_data_length {
        info!(
            target: REPORTING,
            "{}: {}",
            pkt.metadata().ingress_link_id,
            std::str::from_utf8(&pkt.body()[..report_data_length]).unwrap()
        );
    }
    Ok(())
}

/// handle a Discard message (RFC 6.5 § 6.3.1)
pub async fn handle_discard(_asm: &Arc<Assembly>, pkt: Packet) -> HandleMgmtResult {
    // TODO print to debug log, when implemented
    info!(
        target: REPORTING,
        "Discard message received from {}",
        pkt.metadata().ingress_link_id
    );
    Ok(())
}

/// handle an Echo Request message (RFC 6.5 § 6.3.2)
pub async fn handle_echo_request(
    asm: &Arc<Assembly>,
    seq_num: zpr::SeqNum,
    pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;
    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = rsp_pkt.alloc_zeroed_header::<zdp::ZdpEchoHeader>();
    hdr.sequence_number = ((seq_num & 0xffff) as u16).into();

    super::core::send_non_flow_mgmt(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::EchoResponse,
        rsp_pkt,
    )
    .await;

    Ok(())
}

pub async fn handle_echo_response(asm: &Arc<Assembly>, mut pkt: Packet) -> HandleMgmtResult {
    let Ok(hdr) = zdp::ZdpEchoHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    let _ = asm.process_link_state_event(
        pkt.metadata().ingress_link_id,
        LinkEvent::ReceivedEchoResponse {
            sequence_number: hdr.sequence_number.into(),
        },
    );

    Ok(())
}

/// TODO: Not yet in RFC 6
///
/// Message from node requesting authentication.
///
///
pub async fn handle_init_authentication_request(
    asm: &Arc<Assembly>,
    seq_num: zpr::SeqNum,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let Ok(hdr) = zdp::ZdpInitAuthenticationRequestHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };
    let is_bootstrap = hdr.flags & zdp::init_authentication_flags::BOOTSTRAP_SUPPORT != 0;

    let challenge_opt: Option<auth::ZdpInitAuthenticationPayload>;

    if is_bootstrap {
        if hdr.data_len == 0 {
            warn!(target: ZDP, "Received Init Authentication with bootstrap support but no payload");
            return Err((HandleMgmtError::BadStructure, pkt));
        }
        if hdr.data_len < size_of::<auth::ZdpInitAuthenticationPayload>() as u16 {
            warn!(target: ZDP, "Received Init Authentication with unexpected payload size {}", hdr.data_len);
            return Err((HandleMgmtError::BadStructure, pkt));
        }
        if pkt.remaining() < usize::from(hdr.data_len) {
            warn!(target: ZDP, "packet too short for payload");
            return Err((HandleMgmtError::BadStructure, pkt));
        }
        debug!(target: ZDP, "Received Init Authentication +bootstrap for link {ingress_link_id}");

        let Ok(payload) = auth::ZdpInitAuthenticationPayload::read_from_buf(&mut pkt) else {
            return Err((HandleMgmtError::BadStructure, pkt));
        };
        challenge_opt = Some(payload);
    } else {
        debug!(target: ZDP, "Received Init Authentication for link {ingress_link_id} -- bootstrap not supported");
        challenge_opt = None;
    }

    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = rsp_pkt.alloc_zeroed_header::<zdp::ZdpInitAuthenticationResponseHeader>();
    hdr.status_code = zdp::ResponseCode::Success;

    super::core::send_non_flow_mgmt_response(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::InitAuthenticationResponse,
        seq_num,
        rsp_pkt,
    )
    .await;

    let _ = asm.process_link_state_event(
        ingress_link_id,
        LinkEvent::ReceivedInitAuth((is_bootstrap, challenge_opt)),
    );

    Ok(())
}

/// handle a Terminate Request (RFC 6.5 § 6.3.3)
pub async fn handle_terminate_request(
    asm: &Arc<Assembly>,
    _seq_num: zpr::SeqNum,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;
    let Ok(hdr) = zdp::ZdpTerminateLinkRequestHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    info!(target: ZDP, "Received Terminate Request for link {ingress_link_id}");

    let response_code = match asm.process_link_state_event(
        ingress_link_id,
        LinkEvent::ReceivedTerminateRequest(hdr.reason_code),
    ) {
        Ok(_) => zdp::ResponseCode::Success,
        Err(_) => zdp::ResponseCode::Other,
    };

    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = rsp_pkt.alloc_zeroed_header::<zdp::ZdpTerminateLinkResponseHeader>();
    hdr.response_code = response_code;

    super::core::send_non_flow_mgmt(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::TerminateLinkResponse,
        rsp_pkt,
    )
    .await;

    if response_code == zdp::ResponseCode::Success {
        let _ = asm.process_link_state_event(ingress_link_id, LinkEvent::SentTerminate);
    }
    Ok(())
}

pub async fn handle_terminate_response(asm: &Arc<Assembly>, mut pkt: Packet) -> HandleMgmtResult {
    let Ok(hdr) = zdp::ZdpTerminateLinkResponseHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    let link_id = pkt.metadata().ingress_link_id;
    let resp_code = hdr.response_code;
    debug!(target: ZDP, "Link {link_id}: received TerminateLinkResponse, status: {resp_code:?}");
    let _ = asm
        .process_link_state_event(link_id, LinkEvent::ReceivedTerminateResponse(resp_code))
        .map_err(|_| ());

    Ok(())
}

/// handle a Terminate Indication (RFC 6.5 § 6.3.3)
pub async fn handle_terminate_indication(
    asm: &Arc<Assembly>,
    _seq_num: zpr::SeqNum,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;
    let Ok(hdr) = zdp::ZdpTerminateLinkIndicationHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    debug!(target: ZDP, "Received Terminate Indication for link {ingress_link_id}");

    let _ = asm.process_link_state_event(
        ingress_link_id,
        LinkEvent::ReceivedTerminateIndication(hdr.reason_code),
    );
    Ok(())
}

/// handle a Hello Request (RFC 6.5 § 6.3.4)
/// Reads the hello, fire a ReceivedHelloRequest event, and then sends a response.
pub async fn handle_hello_request(
    asm: &Arc<Assembly>,
    _seq_num: zpr::SeqNum,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;

    debug!(target: ZDP, "Received Hello Request for link {ingress_link_id}");

    let Ok(hdr) = zdp::ZdpHelloRequestHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };
    let bytes_needed = match hdr.ip_version {
        zpr::L3Type::Ipv4 => 4,
        zpr::L3Type::Ipv6 => 16,
        _ => {
            warn!(target: ZDP, "link {ingress_link_id}: invalid ip_version field");
            return Err((HandleMgmtError::BadStructure, pkt));
        }
    };
    if pkt.remaining() < bytes_needed {
        warn!(target: ZDP, "link {ingress_link_id}: packet too short for actor address");
        return Err((HandleMgmtError::BadStructure, pkt));
    }
    let actor_addr: IpAddress = match hdr.ip_version {
        zpr::L3Type::Ipv4 => {
            let Ok(addr_bytes) = <[u8; 4]>::read_from_buf(&mut pkt) else {
                return Err((HandleMgmtError::BadStructure, pkt));
            };
            addr_bytes.into()
        }
        zpr::L3Type::Ipv6 => {
            let Ok(addr_bytes) = <[u8; 16]>::read_from_buf(&mut pkt) else {
                return Err((HandleMgmtError::BadStructure, pkt));
            };
            addr_bytes.into()
        }
        _ => panic!("unreachable - already handled this error above"),
    };

    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = rsp_pkt.alloc_zeroed_header::<zdp::ZdpHelloResponseHeader>();

    hdr.status = match asm
        .process_link_state_event(ingress_link_id, LinkEvent::ReceivedHelloRequest(actor_addr))
    {
        Err(_) => zdp::ResponseCode::Other,
        Ok(()) => zdp::ResponseCode::Success,
    };

    super::core::send_non_flow_mgmt(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::HelloResponse,
        rsp_pkt,
    )
    .await;

    Ok(())
}

pub async fn handle_hello_response(asm: &Arc<Assembly>, mut pkt: Packet) -> HandleMgmtResult {
    let Ok(hdr) = zdp::ZdpHelloResponseHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    let link_id = pkt.metadata().ingress_link_id;
    let status = hdr.status;
    debug!(target: ZDP, "Link {link_id}: received HelloResponse, status: {status:?}");
    let _ = asm
        .process_link_state_event(link_id, LinkEvent::ReceivedHelloResponse(status))
        .map_err(|_| ());

    Ok(())
}

/// Handle the AcquireZprAddressRequest (TODO: Not yet in RFC 6)
///
/// This message is from an adapter to a node.  Or in the future from
/// a joining node to an existing node.
///
/// This request must include an authentication blob from the
/// adapter.
///
/// In the future we (node/vs) will assign a ZPR address to the adapter
/// after verifying authentication.  During a transition period to full
/// authentication we permit the adapter to send us an address it wants
/// to have and if authentication succeeds, we just send that address
/// back (in the grant message).
///
/// The authentication blob may come from bootstrap auth or from real
/// auth-service auth.
///
pub async fn handle_acquire_zpr_address_request(
    asm: &Arc<Assembly>,
    seq_num: zpr::SeqNum,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let mut status_code = zdp::ResponseCode::Other;

    let parse_res = parse_acquire_zpr_address_request(&mut pkt);
    if parse_res.is_ok() {
        status_code = zdp::ResponseCode::Success; // parse OK
    } else {
        warn!(target: ZDP, "Link {ingress_link_id} Failed to parse Acquire Zpr Address Request message");
    }

    // Send an ACK.
    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = rsp_pkt.alloc_zeroed_header::<zdp::ZdpAcquireZprAddressResponseHeader>();
    hdr.status_code = status_code;

    super::core::send_non_flow_mgmt_response(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::AcquireZprAddressResponse,
        seq_num,
        rsp_pkt,
    )
    .await;

    // Now we can do our async prcessing of the acquire which will involve talking to
    // the visa service.

    let (actor_addresses, blob) = match parse_res {
        Ok((actor_addresses, blob)) => (actor_addresses, blob),
        Err(_) => {
            return Ok(()); // this only happens if we fail to parse the blob above
        }
    };
    debug!(target: ZDP, "Link {}: received Acquire ZPR Address Request for link with addresses {:?}", ingress_link_id, actor_addresses);

    if let Err(e) = asm.process_link_state_event(
        ingress_link_id,
        LinkEvent::ReceivedAcquireZprAddressRequest(actor_addresses, blob),
    ) {
        error!(target: ZDP, "Link {ingress_link_id}: Failed to process ReceivedAcquireZprAddressRequest event: {:?}", e);
    }

    Ok(())
}

/// Handle the GrantZprAddressRequest (TODO: Not yet in RFC 6)
///
/// This message comes from a node post verification of the authentication blob
/// which we get in an Acquire message.
///
/// This will fire off a link state event that includes the addresses.
/// If the request indicates a fail, we send the event with empty address list.
pub async fn handle_grant_zpr_address_request(
    asm: &Arc<Assembly>,
    _seq_num: zpr::SeqNum,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let mut status_code = zdp::ResponseCode::Other;

    match parse_grant_zpr_address_request(&mut pkt) {
        Ok(Ok(actor_addresses)) => {
            if actor_addresses.is_empty() {
                error!(target: ZDP, "Received Grant Zpr Address Request with no addresses");
                let _ = asm.process_link_state_event(
                    ingress_link_id,
                    LinkEvent::ReceivedGrantZprAddressRequest(None),
                );
            } else {
                info!(target: ZDP,
                    "Received Grant Zpr Address Request for link {} with addresses {:?}", ingress_link_id, actor_addresses);
                if asm
                    .process_link_state_event(
                        ingress_link_id,
                        LinkEvent::ReceivedGrantZprAddressRequest(Some(actor_addresses)),
                    )
                    .is_ok()
                {
                    status_code = zdp::ResponseCode::Success;
                }
            }
        }
        Ok(Err(c)) => {
            info!(target: ZDP, "Grant request indicates non-success; code: {:?}", c);
            if asm
                .process_link_state_event(
                    ingress_link_id,
                    LinkEvent::ReceivedGrantZprAddressRequest(None),
                )
                .is_ok()
            {
                status_code = zdp::ResponseCode::Success; // parsing was successful
            }
        }
        Err(_) => {
            error!(target: ZDP, "Failed to parse Grant Zpr Address Request message, grant fails.");
            // Need to tell state machine.
            let _ = asm.process_link_state_event(
                ingress_link_id,
                LinkEvent::ReceivedGrantZprAddressRequest(None),
            );
        }
    }

    // Send an ACK.
    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = rsp_pkt.alloc_zeroed_header::<zdp::ZdpGrantZprAddressResponse>();
    hdr.status_code = status_code;

    super::core::send_non_flow_mgmt(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::GrantZprAddressResponse,
        rsp_pkt,
    )
    .await;
    Ok(())
}

pub async fn handle_grant_zpr_address_response(
    asm: &Arc<Assembly>,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let Ok(hdr) = zdp::ZdpGrantZprAddressResponse::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    let link_id = pkt.metadata().ingress_link_id;
    let resp_code = hdr.status_code;
    debug!(target: ZDP, "Link {link_id}: received GrantZprAddressResponse, status: {resp_code:?}");
    let _ = asm
        .process_link_state_event(link_id, LinkEvent::ReceivedGrantResponse(resp_code))
        .map_err(|_| ());

    Ok(())
}

/// Returns tuple of (actor_addresses, blob)
/// The addresses are left the address requested by the adapter. This is left over from
/// the older register-actor-address.  Until we are actually assigning addresses we
/// will honor the senders request.
///
/// The blob is a base64 encoded json object.
fn parse_acquire_zpr_address_request(
    pkt: &mut Packet,
) -> Result<(Option<Vec<IpAddress>>, String), HandleMgmtError> {
    let Ok(hdr) = zdp::ZdpAcquireZprAddressRequestHeader::read_from_buf(pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    // In memmory:
    //     header
    //     blob
    //     actor addresses (optional)

    let blob: String;
    let blen = hdr.blob_len.get() as usize;
    if blen == 0 {
        // BLOB must be sent!
        error!(target: ZDP, "Received AcquireZprAddressRequest with no blob");
        return Err(HandleMgmtError::BadStructure);
    } else {
        if pkt.remaining() < blen {
            warn!(target: ZDP, "packet too short for blob");
            return Err(HandleMgmtError::BadStructure);
        }
        let blob_buffer = pkt.copy_to_bytes(blen);
        match String::from_utf8(blob_buffer.into()) {
            Ok(b) => {
                blob = b;
            }
            Err(_) => {
                warn!(target: ZDP, "failed to parse blob as utf8");
                return Err(HandleMgmtError::BadStructure);
            }
        }
    }

    let actor_addresses: Option<Vec<IpAddress>>;
    if hdr.addr_count > 0 {
        let bytes_needed = match hdr.ip_version {
            zpr::L3Type::Ipv4 => 4 * hdr.addr_count as usize,
            zpr::L3Type::Ipv6 => 16 * hdr.addr_count as usize,
            _ => {
                warn!(target: ZDP, "invalid ip_version field");
                return Err(HandleMgmtError::BadStructure);
            }
        };
        if pkt.remaining() < bytes_needed {
            warn!(target: ZDP, "packet too short for addresses");
            return Err(HandleMgmtError::BadStructure);
        }
        let mut addrs = Vec::new();
        for _ in 0..hdr.addr_count {
            let addr: IpAddress;
            match hdr.ip_version {
                zpr::L3Type::Ipv4 => {
                    let Ok(addr_bytes) = <[u8; 4]>::read_from_buf(pkt) else {
                        return Err(HandleMgmtError::BadStructure);
                    };
                    addr = addr_bytes.into();
                }
                zpr::L3Type::Ipv6 => {
                    let Ok(addr_bytes) = <[u8; 16]>::read_from_buf(pkt) else {
                        return Err(HandleMgmtError::BadStructure);
                    };
                    addr = addr_bytes.into();
                }
                _ => {
                    panic!("already handled this error above")
                }
            }
            addrs.push(addr);
        }
        actor_addresses = Some(addrs);
    } else {
        actor_addresses = None;
    }
    Ok((actor_addresses, blob))
}

/// The grant is a message from a node to an adapter (future: or to a joining node).
/// In includes the address (or addresses) we have been assigned to use.
fn parse_grant_zpr_address_request(
    pkt: &mut Packet,
) -> Result<Result<Vec<IpAddress>, zdp::ResponseCode>, HandleMgmtError> {
    let Ok(hdr) = zdp::ZdpGrantZprAddressRequestHeader::read_from_buf(pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    // In memmory:
    //     header
    //     actor addresses (optional)

    if hdr.status_code != zdp::ResponseCode::Success {
        warn!(target: ZDP, "Received Grant Zpr Address Request with non-success status code {:?}", hdr.status_code);
        return Ok(Err(hdr.status_code));
    }

    let mut actor_addresses = Vec::new();
    let bytes_needed = match hdr.ip_version {
        zpr::L3Type::Ipv4 => 4 * hdr.addr_count as usize,
        zpr::L3Type::Ipv6 => 16 * hdr.addr_count as usize,
        _ => {
            warn!(target: ZDP, "invalid ip_version field");
            return Err(HandleMgmtError::BadStructure);
        }
    };
    if pkt.remaining() < bytes_needed {
        warn!(target: ZDP, "packet too short for addresses");
        return Err(HandleMgmtError::BadStructure);
    }
    for _ in 0..hdr.addr_count {
        let addr: IpAddress;
        match hdr.ip_version {
            zpr::L3Type::Ipv4 => {
                let Ok(addr_bytes) = <[u8; 4]>::read_from_buf(pkt) else {
                    return Err(HandleMgmtError::BadStructure);
                };
                addr = addr_bytes.into();
            }
            zpr::L3Type::Ipv6 => {
                let Ok(addr_bytes) = <[u8; 16]>::read_from_buf(pkt) else {
                    return Err(HandleMgmtError::BadStructure);
                };
                addr = addr_bytes.into();
            }
            _ => {
                return Err(HandleMgmtError::BadStructure);
            }
        }
        actor_addresses.push(addr);
    }
    Ok(Ok(actor_addresses))
}

/// handle a Bind Actor Address Request (RFC 6.5 § 6.3.11)
pub async fn handle_bind_actor_address_request(
    asm: &Arc<Assembly>,
    seq_num: zpr::SeqNum,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let Ok(hdr) = zdp::ZdpBindActorAddressRequestHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    // TODO: disallow bind requests between nodes

    // read addresses (always present)
    let src_address;
    let dst_address;
    match hdr.ip_version {
        zpr::L3Type::Ipv4 => {
            let Ok(src_addr) = <[u8; 4]>::read_from_buf(&mut pkt) else {
                return Err((HandleMgmtError::BadStructure, pkt));
            };
            src_address = src_addr.into();

            let Ok(dst_addr) = <[u8; 4]>::read_from_buf(&mut pkt) else {
                return Err((HandleMgmtError::BadStructure, pkt));
            };
            dst_address = dst_addr.into();
        }

        zpr::L3Type::Ipv6 => {
            let Ok(src_addr) = <[u8; 16]>::read_from_buf(&mut pkt) else {
                return Err((HandleMgmtError::BadStructure, pkt));
            };
            src_address = src_addr.into();

            let Ok(dst_addr) = <[u8; 16]>::read_from_buf(&mut pkt) else {
                return Err((HandleMgmtError::BadStructure, pkt));
            };
            dst_address = dst_addr.into();
        }

        _ => {
            return Err((HandleMgmtError::BadStructure, pkt));
        }
    };

    // read IP Protocol (always present)
    if pkt.remaining() < 1 {
        return Err((HandleMgmtError::BadStructure, pkt));
    }
    let ip_protocol = pkt.get_u8();

    // read source port (optional)
    let src_port;
    if hdr.compression_mode & zpr::compression_mode::SOURCE_PORT_PRESENT != 0 {
        if pkt.remaining() < 2 {
            return Err((HandleMgmtError::BadStructure, pkt));
        }
        src_port = pkt.get_u16();
    } else {
        src_port = 0;
    }

    // read destination port (optional)
    let dst_port;
    if hdr.compression_mode & zpr::compression_mode::DESTINATION_PORT_PRESENT != 0 {
        if pkt.remaining() < 2 {
            return Err((HandleMgmtError::BadStructure, pkt));
        }
        dst_port = pkt.get_u16();
    } else {
        dst_port = 0;
    }

    let compression_mode = hdr.compression_mode;

    let five_tuple = FiveTuple::new(
        hdr.ip_version,
        src_address,
        dst_address,
        ip_protocol,
        src_port,
        dst_port,
    );

    let Some(ingress_link_id) = NonZero::new(pkt.metadata().ingress_link_id) else {
        // who sent this??
        error!(target: FLOW_MGMT, "coding error: stray packet from unknown source; dropping");
        return Ok(());
    };

    // read triggering-packet body
    let packet_body: Vec<u8> = pkt.body().into();

    // recycle request buffer for response
    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);

    let ingress_tether_id;

    match asm.ph_mode {
        PhMode::Node => {
            // TODO: errors need more consideration here
            match super::dock::bind_actor_address(
                asm,
                ingress_link_id,
                compression_mode,
                five_tuple,
                packet_body,
            )
            .await
            {
                Ok(ingress_tid) => {
                    // success; respond with ingress tether ID
                    zdp::ZdpBindActorAddressResponseHeader {
                        status_code: zdp::ResponseCode::Success,
                        info_len: 0,
                    }
                    .write_to_buf(&mut rsp_pkt)
                    .unwrap();

                    ingress_tether_id = ingress_tid;
                }

                Err(super::dock::BindActorAddressError::PolicyError) => {
                    // send error to requestor
                    let message = "policy error";

                    zdp::ZdpBindActorAddressResponseHeader {
                        status_code: zdp::ResponseCode::Other,
                        info_len: message.len() as u8,
                    }
                    .write_to_buf(&mut rsp_pkt)
                    .unwrap();

                    rsp_pkt.put(message.as_bytes());

                    ingress_tether_id = 0;
                }

                Err(super::dock::BindActorAddressError::ParseError(error)) => {
                    // send error to requestor
                    zdp::ZdpBindActorAddressResponseHeader {
                        status_code: zdp::ResponseCode::Other,
                        info_len: error.len() as u8,
                    }
                    .write_to_buf(&mut rsp_pkt)
                    .unwrap();

                    rsp_pkt.put(error.as_bytes());

                    ingress_tether_id = 0;
                }

                Err(super::dock::BindActorAddressError::AddRouteError(
                    assembly::AddRouteError::PftFull,
                )) => {
                    // PFT full; respond with error message
                    // TODO: maybe tick a counter somewhere?
                    let message = "PFT full";

                    zdp::ZdpBindActorAddressResponseHeader {
                        status_code: zdp::ResponseCode::Other,
                        info_len: message.len() as u8,
                    }
                    .write_to_buf(&mut rsp_pkt)
                    .unwrap();

                    rsp_pkt.put(message.as_bytes());

                    ingress_tether_id = 0;
                }

                Err(super::dock::BindActorAddressError::AddRouteError(
                    assembly::AddRouteError::PeerGone,
                )) => {
                    // peer went away; don't bother responding
                    return Ok(());
                }

                Err(super::dock::BindActorAddressError::AddRouteError(
                    assembly::AddRouteError::VisaGone,
                )) => {
                    // send error to requestor
                    let message = "policy error";

                    zdp::ZdpBindActorAddressResponseHeader {
                        status_code: zdp::ResponseCode::Other,
                        info_len: message.len() as u8,
                    }
                    .write_to_buf(&mut rsp_pkt)
                    .unwrap();

                    rsp_pkt.put(message.as_bytes());

                    ingress_tether_id = 0;
                }

                Err(super::dock::BindActorAddressError::AddRouteError(
                    assembly::AddRouteError::BindFailed(err),
                )) => {
                    // unable to bind next-hop; respond with error message
                    // TODO: maybe tick a counter somewhere?
                    let message = format!("unable to bind next-hop: {}", err);

                    zdp::ZdpBindActorAddressResponseHeader {
                        status_code: zdp::ResponseCode::Other,
                        info_len: message.len() as u8,
                    }
                    .write_to_buf(&mut rsp_pkt)
                    .unwrap();

                    rsp_pkt.put(message.as_bytes());

                    ingress_tether_id = 0;
                }
            }
        }

        PhMode::Adapter => {
            // form PEP
            let pep = adapter_tables::DltPep {
                compression_mode,
                five_tuple,
            };

            // TODO: reverse path

            // attempt to insert into DLT
            match asm.dlt.insert(pep) {
                Ok(tid) => {
                    // success; respond with tether ID
                    // TODO: maybe tick a counter somewhere?
                    zdp::ZdpBindActorAddressResponseHeader {
                        status_code: zdp::ResponseCode::Success,
                        info_len: 0,
                    }
                    .write_to_buf(&mut rsp_pkt)
                    .unwrap();

                    ingress_tether_id = tid;
                }

                Err(()) => {
                    // DLT full; respond with error message
                    // TODO: maybe tick a counter somewhere?
                    let message = "DLT full";

                    zdp::ZdpBindActorAddressResponseHeader {
                        status_code: zdp::ResponseCode::Other,
                        info_len: message.len() as u8,
                    }
                    .write_to_buf(&mut rsp_pkt)
                    .unwrap();

                    rsp_pkt.put(message.as_bytes());

                    ingress_tether_id = 0;
                }
            }
        }
    }

    // respond to requestor
    super::core::send_per_flow_mgmt_response(
        asm,
        ingress_link_id.get(),
        zdp::ZdpPacketType::BindActorAddressResponse,
        ingress_tether_id,
        seq_num,
        rsp_pkt,
    )
    .await;

    Ok(())
}
