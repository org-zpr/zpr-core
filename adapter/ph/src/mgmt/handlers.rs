//! Handlers for management requests.
//!
//! These handlers just decode the packet and forward work to whatever
//! internal API is responsible for handling it.  There are no "smarts" in
//! this module.

use super::txn_mgr::TxnId;
use super::{adapter, dock};
use crate::assembly::{Assembly, PhMode};
use crate::auth;
use crate::counters;
use crate::link_state::{LinkEvent, LinkStateError};
use crate::logging::targets::{FLOW_MGMT, REPORTING, ZDP};
use crate::packet::Packet;
use crate::tc;
use crate::tlv;
use crate::zdp;
use bytes::Buf;
use std::net::SocketAddr;
use std::num::NonZero;
use std::sync::Arc;
use thiserror::Error;
use tracing::*;
use zpr::packet_info::{L3Type, LinkId, Tcst};
use zpr_ext::zerocopy::FromBytesExt;
use zpr_utils::net_defs::IpAddress;

/// Indicates whether the mgmt message was handled successfully.
/// (It may be the case that the mgmt message itself indicates
/// failure of a remote operation; modulo a parsing issue,
/// handling such a message would still be considered successful.)
#[derive(Debug, Error)]
pub enum HandleMgmtError {
    #[error("unknown packet type: {0}")]
    UnknownType(u8),

    #[error("message not permitted")]
    MessageNotPermitted,

    #[error("bad packet structure")]
    BadStructure,

    #[error("unknown transaction")]
    UnknownTransaction,

    #[error("link state error: {0}")]
    LinkStateError(#[from] LinkStateError),

    #[error("link closed")]
    LinkClosed,
}

impl From<&HandleMgmtError> for counters::ManagementCounterType {
    fn from(err: &HandleMgmtError) -> Self {
        match err {
            HandleMgmtError::UnknownType(_type) => Self::UnknownType,
            HandleMgmtError::BadStructure => Self::BadStructure,
            HandleMgmtError::MessageNotPermitted => Self::OtherError,
            HandleMgmtError::UnknownTransaction => Self::UnknownTransaction,
            HandleMgmtError::LinkStateError(_) => Self::OtherError,
            HandleMgmtError::LinkClosed => Self::OtherError,
        }
    }
}

impl From<super::core::MgmtSendError> for HandleMgmtError {
    fn from(err: super::core::MgmtSendError) -> Self {
        match err {
            super::core::MgmtSendError::LinkClosed => HandleMgmtError::LinkClosed,
        }
    }
}

impl From<adapter::InstallTetherError> for HandleMgmtError {
    fn from(err: adapter::InstallTetherError) -> Self {
        match err {
            adapter::InstallTetherError::NoSuchTransaction => HandleMgmtError::UnknownTransaction,
        }
    }
}

impl From<dock::InstallTetherError> for HandleMgmtError {
    fn from(err: dock::InstallTetherError) -> Self {
        match err {
            dock::InstallTetherError::NoSuchTransaction => HandleMgmtError::UnknownTransaction,
            dock::InstallTetherError::LinkClosed => HandleMgmtError::LinkClosed,
        }
    }
}

pub type HandleMgmtResult = Result<(), HandleMgmtError>;

/// handle a Report message (RFC 6.5 § 6.3.13)
pub async fn handle_report(_asm: &Arc<Assembly>, mut pkt: Packet) -> HandleMgmtResult {
    let Ok(hdr) = zdp::ZdpReportHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
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
pub async fn handle_echo_request(_asm: &Arc<Assembly>, _pkt: Packet) -> HandleMgmtResult {
    // we simply rely on the ZDPR ACK
    Ok(())
}

/// TODO: Not yet in RFC 6
///
/// Message from node requesting authentication.
/// Sends a [zdp::ZdpInitAuthenticationResponse] back.
///
pub async fn handle_init_authentication_request(
    asm: &Arc<Assembly>,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let Ok(hdr) = zdp::ZdpInitAuthenticationRequestHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };
    let is_bootstrap = hdr.flags & zdp::init_authentication_flags::BOOTSTRAP_SUPPORT != 0;

    let challenge_opt: Option<auth::ZdpInitAuthenticationPayload>;

    if is_bootstrap {
        if hdr.data_len == 0 {
            warn!(target: ZDP, "Received Init Authentication with bootstrap support but no payload");
            return Err(HandleMgmtError::BadStructure);
        }
        if hdr.data_len < size_of::<auth::ZdpInitAuthenticationPayload>() as u16 {
            warn!(target: ZDP, "Received Init Authentication with unexpected payload size {}", hdr.data_len);
            return Err(HandleMgmtError::BadStructure);
        }
        if pkt.remaining() < usize::from(hdr.data_len) {
            warn!(target: ZDP, "packet too short for payload");
            return Err(HandleMgmtError::BadStructure);
        }
        debug!(target: ZDP, "Received Init Authentication +bootstrap for link {ingress_link_id}");

        let Ok(payload) = auth::ZdpInitAuthenticationPayload::read_from_buf(&mut pkt) else {
            return Err(HandleMgmtError::BadStructure);
        };
        challenge_opt = Some(payload);
    } else {
        debug!(target: ZDP, "Received Init Authentication for link {ingress_link_id} -- bootstrap not supported");
        challenge_opt = None;
    }

    asm.process_link_state_event(
        ingress_link_id,
        LinkEvent::ReceivedInitAuth((is_bootstrap, challenge_opt)),
    )?;

    Ok(())
}

/// handle a Terminate Link or Docking Session message (TODO: document in RFC 17)
///
/// Sends [LinkEvent::ReceivedTerminateLink] into the link state machine.
/// Sends a ZdpTerminateResponse message back to the sender.
/// Sends a [LinkEvent::SentTerminate] event into the link state machine.
pub async fn handle_terminate_link_or_docking_session(
    asm: &Arc<Assembly>,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;
    let Ok(hdr) = zdp::ZdpTerminateLinkOrDockingSessionHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    info!(target: ZDP, "Received Terminate Link or Docking Session for link {ingress_link_id}");

    asm.process_link_state_event(
        ingress_link_id,
        LinkEvent::ReceivedTerminateLink(hdr.reason_code),
    )?;

    Ok(())
}

/// handle a Hello Request (RFC 6.5 § 6.3.4)
/// Reads the hello, fire a ReceivedHelloRequest event, and then sends a response.
///
pub async fn handle_hello_request(asm: &Arc<Assembly>, mut pkt: Packet) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;
    if asm.ph_mode != PhMode::Node {
        warn!(target: ZDP, "Link {ingress_link_id} received Hello Request but not in node mode");
        return Err(HandleMgmtError::MessageNotPermitted);
    }
    debug!(target: ZDP, "Received Hello Request for link {ingress_link_id}");

    let tlv_data = match tlv::parse_from_buf(&mut pkt) {
        Ok(data) => data,
        Err(_) => {
            error!(target: ZDP, "Link {ingress_link_id}: Failed to parse HelloRequest TLV data");
            return Err(HandleMgmtError::BadStructure);
        }
    };

    // We just emit the TLV stuff to log but only use window size.
    for (tlv_type, tlv_value) in &tlv_data {
        match *tlv_type {
            tlv::DataType::WINDOW_SIZE => {
                process_window_size_tlv(&asm, ingress_link_id, "HelloRequest", tlv_value)?;
            }
            _ => {
                info!(
                    "Link {ingress_link_id}: HelloRequest includes ignored TLV type: {tlv_type} => {tlv_value:?}"
                );
            }
        }
    }

    asm.process_link_state_event(ingress_link_id, LinkEvent::ReceivedHelloRequest)?;

    Ok(())
}

pub async fn handle_hello_response(asm: &Arc<Assembly>, mut pkt: Packet) -> HandleMgmtResult {
    let Ok(hdr) = zdp::ZdpHelloResponseHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    let link_id = pkt.metadata().ingress_link_id;
    let status = hdr.status;
    debug!(target: ZDP, "Link {link_id}: received HelloResponse, status: {status:?}");

    // Following status are the TLVs.
    // A tlv has a type (number) and a value.
    let tlv_data = match tlv::parse_from_buf(&mut pkt) {
        Ok(data) => data,
        Err(e) => {
            error!(target: ZDP, "Link {link_id}: HelloResponse - failed to parse TLVs: {:?}", e);
            return Err(HandleMgmtError::BadStructure);
        }
    };

    // ASA = Authentication Service Address (will have a port too)
    let mut asa_addresses = Vec::<SocketAddr>::new();
    let mut aaa_address: Option<IpAddress> = None;

    for (tlv_type, tlv_value) in &tlv_data {
        match tlv_type {
            &tlv::DataType::VERSION => {
                info!(target: ZDP, "Link {link_id}: HelloResponse - peer version is : {}", tlv_value[0]);
            }
            &tlv::DataType::WINDOW_SIZE => {
                process_window_size_tlv(&asm, link_id, "HelloResponse", tlv_value)?;
            }
            &tlv::DataType::POLICY_ID => {
                info!(target: ZDP, "Link {link_id}: HelloResponse - peer policy ID is : {}", tlv_value[0]);
            }
            &tlv::DataType::ASA => {
                for asa_entry in tlv_value {
                    match asa_entry {
                        tlv::TlvValue::SocketAddr(sa) => {
                            info!(target: ZDP, "Link {link_id}: HelloResponse includes ASA address:{sa}");
                            asa_addresses.push(sa.clone());
                        }
                        _ => {
                            warn!(target: ZDP, "Link {link_id}: HelloResponse ASA value type is wrong: {asa_entry:?}");
                            return Err(HandleMgmtError::BadStructure);
                        }
                    }
                }
            }
            &tlv::DataType::AAA => {
                for aaa_entry in tlv_value {
                    if aaa_address.is_some() {
                        warn!(target: ZDP, "Link {link_id}: HelloResponse includes multiple AAA addresses");
                        return Err(HandleMgmtError::BadStructure);
                    }
                    match aaa_entry {
                        tlv::TlvValue::Ipv4Addr(ipa) => {
                            info!(target: ZDP, "Link {link_id}: HelloResponse includes AAA address:{ipa}");
                            aaa_address = Some(IpAddress::new_from_std_v4(ipa));
                        }
                        tlv::TlvValue::Ipv6Addr(ipa) => {
                            info!(target: ZDP, "Link {link_id}: HelloResponse includes AAA address:{ipa}");
                            aaa_address = Some(IpAddress::new_from_std_v6(ipa));
                        }
                        _ => {
                            warn!(target: ZDP, "Link {link_id}: HelloResponse AAA value type is wrong: {aaa_entry:?}");
                            return Err(HandleMgmtError::BadStructure);
                        }
                    }
                }
            }
            _ => {
                info!(target: ZDP, "Link {link_id}: HelloResponse includes ignored TLV type: {tlv_type}, continuing");
            }
        }
    }

    // AAA is required.
    if aaa_address.is_none() {
        warn!(target: ZDP, "Link {link_id}: HelloResponse did not include AAA");
        return Err(HandleMgmtError::BadStructure);
    }

    let maybe_asa_addrs = if asa_addresses.is_empty() {
        warn!(target: ZDP, "Link {link_id}: HelloResponse did not include ASA");
        None
    } else {
        Some(asa_addresses)
    };

    asm.process_link_state_event(
        link_id,
        LinkEvent::ReceivedHelloResponse(status, aaa_address.unwrap(), maybe_asa_addrs),
    )?;

    Ok(())
}

fn process_window_size_tlv(
    asm: &Assembly,
    link_id: LinkId,
    message_name: &str,
    tlv_value: &[tlv::TlvValue],
) -> HandleMgmtResult {
    for window_size_entry in tlv_value {
        match window_size_entry {
            tlv::TlvValue::U16(window_size) => {
                if *window_size < 1 {
                    warn!(target: ZDP, "Link {link_id}: {message_name} window size is invalid: {window_size}");
                } else {
                    info!(target: ZDP, "Link {link_id}: Applying window size {window_size} from {message_name}");
                    asm.peer_table.inspect(link_id, |ps| {
                        ps.zdpr_send
                            .lock()
                            .unwrap()
                            .adjust_window_size(*window_size as usize)
                    });
                }
            }
            _ => {
                warn!(target: ZDP, "Link {link_id}: {message_name} window size type is wrong: {window_size_entry:?}");
                return Err(HandleMgmtError::BadStructure);
            }
        }
    }
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
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let Ok((actor_addresses, blob)) = parse_acquire_zpr_address_request(&mut pkt) else {
        error!(target: ZDP, "Link {ingress_link_id} Failed to parse Acquire Zpr Address Request message");
        return Err(HandleMgmtError::BadStructure);
    };

    // Now we can do our async prcessing of the acquire which will involve talking to
    // the visa service.

    debug!(target: ZDP, "Link {}: received Acquire ZPR Address Request for link with addresses {:?}", ingress_link_id, actor_addresses);

    asm.process_link_state_event(
        ingress_link_id,
        LinkEvent::ReceivedAcquireZprAddressRequest(actor_addresses, blob),
    )?;

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
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let grant_event_payload;
    match parse_grant_zpr_address_request(&mut pkt) {
        Ok(Ok(actor_addresses)) => {
            if actor_addresses.is_empty() {
                error!(target: ZDP, "Received Grant Zpr Address Request with no addresses");
                return Err(HandleMgmtError::BadStructure);
            } else {
                info!(target: ZDP,
                    "Received Grant Zpr Address Request for link {} with addresses {:?}", ingress_link_id, actor_addresses);
                grant_event_payload = Some(actor_addresses);
            }
        }
        Ok(Err(c)) => {
            info!(target: ZDP, "Grant request indicates non-success; code: {:?}", c);
            grant_event_payload = None;
        }
        Err(_) => {
            error!(target: ZDP, "Failed to parse Grant Zpr Address Request message, grant fails.");
            return Err(HandleMgmtError::BadStructure);
        }
    };

    asm.process_link_state_event(
        ingress_link_id,
        LinkEvent::ReceivedGrantZprAddressRequest(grant_event_payload),
    )?;

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
    let Ok(hdr) = zdp::ZdpAcquireZprAddressHeader::read_from_buf(pkt) else {
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
            L3Type::Ipv4 => 4 * hdr.addr_count as usize,
            L3Type::Ipv6 => 16 * hdr.addr_count as usize,
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
                L3Type::Ipv4 => {
                    let Ok(addr_bytes) = <[u8; 4]>::read_from_buf(pkt) else {
                        return Err(HandleMgmtError::BadStructure);
                    };
                    addr = addr_bytes.into();
                }
                L3Type::Ipv6 => {
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
    let Ok(hdr) = zdp::ZdpGrantZprAddressHeader::read_from_buf(pkt) else {
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
        L3Type::Ipv4 => 4 * hdr.addr_count as usize,
        L3Type::Ipv6 => 16 * hdr.addr_count as usize,
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
            L3Type::Ipv4 => {
                let Ok(addr_bytes) = <[u8; 4]>::read_from_buf(pkt) else {
                    return Err(HandleMgmtError::BadStructure);
                };
                addr = addr_bytes.into();
            }
            L3Type::Ipv6 => {
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
    txn_id: TxnId,
    mut pkt: Packet,
) -> HandleMgmtResult {
    if !matches!(asm.ph_mode, PhMode::Node) {
        error!(target: ZDP, "Link {}: received BindActorAddress message on adapter", pkt.metadata().ingress_link_id);
        return Err(HandleMgmtError::MessageNotPermitted);
    }

    let Ok(hdr) = zdp::ZdpBindActorAddressRequestHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    let l3_type = hdr.l3_type;

    let endpoint_packet_length = hdr.endpoint_packet_length.get() as usize;
    if endpoint_packet_length > pkt.len() {
        return Err(HandleMgmtError::BadStructure);
    }

    // drop any garbage after the packet body
    pkt.shrink_by(pkt.len() - endpoint_packet_length);

    let Some(ingress_link_id) = NonZero::new(pkt.metadata().ingress_link_id) else {
        // who sent this??
        error!(target: FLOW_MGMT, "coding error: stray packet from unknown source; dropping");
        return Ok(());
    };

    debug!(target: ZDP, "Link {ingress_link_id}: handlers.handle_bind_actor_address_request");

    dock::bind_actor_address(asm, ingress_link_id, txn_id, l3_type, pkt.body());

    Ok(())
}

pub async fn handle_bind_egress_stream_request(
    asm: &Arc<Assembly>,
    txn_id: TxnId,
    mut pkt: Packet,
) -> HandleMgmtResult {
    if !matches!(asm.ph_mode, PhMode::Adapter) {
        error!(target: ZDP, "Link {}: received BindEgressStream message on node", pkt.metadata().ingress_link_id);
        return Err(HandleMgmtError::MessageNotPermitted);
    }

    let Ok(hdr) = zdp::ZdpBindEgressStreamRequestHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    if !matches!(hdr.tcst, Tcst::Ip5Tuple) {
        warn!(target: ZDP, "Link {}: unsupported TCST {}", pkt.metadata().ingress_link_id, hdr.tcst.0);
        return Err(HandleMgmtError::BadStructure);
    }

    let Ok(tc) = tc::Ip5TupleTc::deserialize(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    let Some(ingress_link_id) = NonZero::new(pkt.metadata().ingress_link_id) else {
        // who sent this??
        error!(target: FLOW_MGMT, "coding error: stray packet from unknown source; dropping");
        return Ok(());
    };

    debug!(
        target: ZDP,
        "Link {}: handlers.handle_bind_egress_stream_request -- five_tuple {}",
        ingress_link_id.get(), tc.five_tuple()
    );

    adapter::bind_egress_stream(asm, ingress_link_id, txn_id, tc);

    Ok(())
}

pub async fn handle_bind_actor_address_response(
    asm: &Arc<Assembly>,
    txn_id: TxnId,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let link_id = pkt.metadata().ingress_link_id;

    let Some(peer_state) = asm.peer_table.get(link_id) else {
        return Err(HandleMgmtError::LinkClosed);
    };

    let Some(txn) = peer_state.txn_mgr.get(txn_id) else {
        return Err(HandleMgmtError::UnknownTransaction);
    };

    let Ok(hdr) = zdp::ZdpBindActorAddressResponseHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    match hdr.status_code {
        zdp::ResponseCode::Success => {
            let stream_id = pkt.metadata().ingress_stream_id;

            let Ok(tcst) = Tcst::read_from_buf(&mut pkt) else {
                return Err(HandleMgmtError::BadStructure);
            };

            if !matches!(tcst, Tcst::Ip5Tuple) {
                warn!(target: ZDP, "Link {}: unsupported TCST {}", pkt.metadata().ingress_link_id, tcst.0);
                return Err(HandleMgmtError::BadStructure);
            }

            let Ok(tc) = tc::Ip5TupleTc::deserialize(&mut pkt) else {
                return Err(HandleMgmtError::BadStructure);
            };

            adapter::install_tether(&asm, &txn, stream_id, tc)?;
            Ok(())
        }

        zdp::ResponseCode::Other => {
            if hdr.info_len as usize > pkt.remaining() {
                return Err(HandleMgmtError::BadStructure);
            }

            let Ok(msg) = std::str::from_utf8(&pkt.body()[..hdr.info_len as usize]) else {
                return Err(HandleMgmtError::BadStructure);
            };

            adapter::deny_tether(&asm, &txn, msg)?;
            Ok(())
        }

        _ => Err(HandleMgmtError::BadStructure),
    }
}

pub async fn handle_bind_egress_stream_response(
    asm: &Arc<Assembly>,
    txn_id: TxnId,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let link_id = pkt.metadata().ingress_link_id;

    let Some(peer_state) = asm.peer_table.get(link_id) else {
        return Err(HandleMgmtError::LinkClosed);
    };

    let Some(txn) = peer_state.txn_mgr.get(txn_id) else {
        return Err(HandleMgmtError::UnknownTransaction);
    };

    let Ok(hdr) = zdp::ZdpBindActorAddressResponseHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    match hdr.status_code {
        zdp::ResponseCode::Success => {
            let stream_id = pkt.metadata().ingress_stream_id;

            dock::install_tether(&asm, NonZero::new(link_id).unwrap(), &txn, stream_id)?;
            Ok(())
        }

        zdp::ResponseCode::Other => {
            if hdr.info_len as usize > pkt.remaining() {
                return Err(HandleMgmtError::BadStructure);
            }

            let Ok(msg) = std::str::from_utf8(&pkt.body()[..hdr.info_len as usize]) else {
                return Err(HandleMgmtError::BadStructure);
            };

            dock::deny_tether(&asm, NonZero::new(link_id).unwrap(), &txn, msg)?;
            Ok(())
        }

        _ => Err(HandleMgmtError::BadStructure),
    }
}

pub async fn handle_unbind_actor_address_request(
    asm: &Arc<Assembly>,
    txn_id: TxnId,
    mut pkt: Packet,
) -> HandleMgmtResult {
    Ok(())
}

pub async fn handle_unbind_egress_stream_request(
    asm: &Arc<Assembly>,
    txn_id: TxnId,
    mut pkt: Packet,
) -> HandleMgmtResult {
    if !matches!(asm.ph_mode, PhMode::Adapter) {
        error!(target: ZDP, "Link {}: received BindEgressStream message on node", pkt.metadata().ingress_link_id);
        return Err(HandleMgmtError::MessageNotPermitted);
    }

    let Some(ingress_link_id) = NonZero::new(pkt.metadata().ingress_link_id) else {
        // who sent this??
        error!(target: FLOW_MGMT, "coding error: stray packet from unknown source; dropping");
        return Ok(());
    };

    debug!(
        target: ZDP,
        "Link {}: handlers.handle_unbind_egress_stream_request",
        ingress_link_id.get()
    );

    adapter::unbind_egress_stream(asm, ingress_link_id, txn_id, pkt.metadata().ingress_stream_id);

    Ok(())
}
