//! Handlers for management requests.

use crate::adapter_tables;
use crate::assembly::{self, Assembly, PhMode, VERSION};
use crate::auth;
use crate::classifier;
use crate::config;
use crate::counters;
use crate::link_state::{LinkEvent, LinkStateError};
use crate::logging::targets::{FLOW_MGMT, REPORTING, ZDP};
use crate::net_defs::{ip_number, IpAddress};
use crate::packet::Packet;
use crate::tlv::{self, TlvEncoding};
use crate::zdp;
use bytes::{Buf, BufMut};
use std::net::SocketAddr;
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

    #[error("message not permitted")]
    MessageNotPermitted,

    #[error("bad packet structure")]
    BadStructure,

    #[error("link closed")]
    LinkClosed,
}

impl From<HandleMgmtError> for counters::ManagementCounterType {
    fn from(err: HandleMgmtError) -> Self {
        match err {
            HandleMgmtError::UnknownType(_type) => Self::UnknownType,
            HandleMgmtError::BadStructure => Self::BadStructure,
            HandleMgmtError::MessageNotPermitted => Self::OtherError,
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

pub type HandleMgmtResult = Result<(), HandleMgmtError>;

/// Fire an event into the given link state machine. If there is an event handler error
/// it will be returned but only after we try to send in an ERROR event which should
/// end up triggering a link shutdown.
///
/// The error result is returned for informational purposes only. If you are getting an
/// error we have already logged it and have attempted to send an Error event into the
/// link state machine.
fn dispatch_link_state_event_or_error(
    asm: &Arc<Assembly>,
    link_id: zpr::LinkId,
    event: LinkEvent,
) -> Result<(), LinkStateError> {
    if let Err(ls_err) = asm.process_link_state_event(link_id, event) {
        error!(target: ZDP, "Link {link_id} failed to process link state event:  {ls_err}");
        match asm.process_link_state_event(link_id, LinkEvent::Error) {
            Err(e) => {
                // TODO: I assume this is possible if we for example have async closed the link.
                error!(target: ZDP, "Link {link_id}: failed to process Error event: {e}");
            }
            Ok(()) => (),
        }
        Err(ls_err)
    } else {
        Ok(())
    }
}

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

    let _ = dispatch_link_state_event_or_error(
        asm,
        ingress_link_id,
        LinkEvent::ReceivedInitAuth((is_bootstrap, challenge_opt)),
    );

    Ok(())
}

/// handle a Terminate Request (RFC 6.5 § 6.3.3)
///
/// Sends [LinkEvent::ReceivedTerminateRequest] into the link state machine.
/// Sends a ZdpTerminateResponse message back to the sender.
/// Sends a [LinkEvent::SentTerminate] event into the link state machine.
pub async fn handle_terminate_request(asm: &Arc<Assembly>, mut pkt: Packet) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;
    let Ok(hdr) = zdp::ZdpTerminateLinkRequestHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
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
    .await?;

    // Tell state machine we sent a TerminateLinkResponse. This will trigger `clean_up_link_state`.
    let _ = asm.process_link_state_event(ingress_link_id, LinkEvent::SentTerminate);

    Ok(())
}

pub async fn handle_terminate_response(asm: &Arc<Assembly>, mut pkt: Packet) -> HandleMgmtResult {
    let Ok(hdr) = zdp::ZdpTerminateLinkResponseHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    let link_id = pkt.metadata().ingress_link_id;
    let resp_code = hdr.response_code;
    debug!(target: ZDP, "Link {link_id}: received TerminateLinkResponse, status: {resp_code:?}");
    let _ignore_errors = asm
        .process_link_state_event(link_id, LinkEvent::ReceivedTerminateResponse(resp_code))
        .map_err(|_| ());

    Ok(())
}

/// handle a Terminate Indication (RFC 6.5 § 6.3.3)
pub async fn handle_terminate_indication(asm: &Arc<Assembly>, mut pkt: Packet) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;
    let Ok(hdr) = zdp::ZdpTerminateLinkIndicationHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    debug!(target: ZDP, "Received Terminate Indication for link {ingress_link_id}");

    let _ignore_errors = asm.process_link_state_event(
        ingress_link_id,
        LinkEvent::ReceivedTerminateIndication(hdr.reason_code),
    );
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

    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = rsp_pkt.alloc_zeroed_header::<zdp::ZdpHelloResponseHeader>();

    let response_status =
        match asm.process_link_state_event(ingress_link_id, LinkEvent::ReceivedHelloRequest) {
            Err(_) => zdp::ResponseCode::Other,
            Ok(()) => zdp::ResponseCode::Success,
        };

    let mut aaa_address: Option<IpAddress> = None;

    if response_status == zdp::ResponseCode::Success {
        // Technically we do not need to supply an AAA address to an adapter fronting the visa service,
        // or if we do not have an external authentication service available.  For simplicity we just
        // always hand one out.
        if let Some(pool) = asm.address_pool.lock().unwrap().as_mut() {
            let addr = pool.get_aaa_address();
            debug!(target: ZDP, "Link {ingress_link_id}: HelloResponse - allocated AAA address: {addr} (active pool size: {})",
                pool.len());
            aaa_address = Some(addr);

            // Store the AAA in the link memory so we can free it later.
            match asm.process_link_state_event(ingress_link_id, LinkEvent::AssignedAAA(addr)) {
                Err(e) => {
                    // Highly improbable
                    panic!("Link {ingress_link_id}: failed to process AssignedAAA event: {e}");
                }
                Ok(()) => (),
            }
        } else {
            // Programming error: if we are a node, we must have a pool.
            panic!("adapter (node) handling a hello-request missing address pool");
        }
    }

    hdr.status = response_status;

    // Policy ID and version are always included, even if not SUCCESS.
    let policy_id: i64 = 0; // TODO: We get policy ID from visa service. Record that somewhere, access it here.
    TlvEncoding::new_policy_id(policy_id).put(&mut rsp_pkt);
    TlvEncoding::new_version(VERSION).put(&mut rsp_pkt);
    super::helpers::put_window_size_tlv(&asm, ingress_link_id, &mut rsp_pkt);

    if response_status == zdp::ResponseCode::Success {
        let svclist = asm.vs_auth_services.read().unwrap();
        if svclist.is_valid() {
            // If we have a list of services, include them in the response.
            // TODO: The ASA is set as a SocketAddr which doesn't feel quite right.  Maybe should be a URI.
            for authservice in &svclist.services {
                if let Some(sa) = authservice.get_socket_addr() {
                    debug!(target: ZDP, "Link {ingress_link_id}: HelloResponse - adding ASA address: {sa}");
                    TlvEncoding::new_asa(sa).put(&mut rsp_pkt);
                } else {
                    warn!(target: ZDP, "Link {ingress_link_id}: HelloResponse - service {} has no valid ASA address", authservice.service_id);
                }
            }
        } else {
            warn!(target: ZDP, "Link {ingress_link_id}: HelloResponse - no valid auth services available");
        }
        if let Some(aaa_addr) = aaa_address {
            TlvEncoding::new_aaa(aaa_addr).put(&mut rsp_pkt);
        }
    }

    super::core::send_non_flow_mgmt(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::HelloResponse,
        rsp_pkt,
    )
    .await?;

    let close_link = if response_status == zdp::ResponseCode::Success {
        match asm.process_link_state_event(ingress_link_id, LinkEvent::SentHelloResponse) {
            Err(e) => {
                error!(target: ZDP, "Link {ingress_link_id}: Failed to process SentHelloResponse event: {:?}", e);
                true
            }
            Ok(()) => false,
        }
    } else {
        // TODO: The framework within which this function is called does not allow us to
        // return an error back which would trigger a link shutdown.  So we do it manually
        // and just return Ok() though things are not in fact OK.
        info!(target: ZDP, "Link {ingress_link_id}: HelloRequest processing failed, shutting down link");
        true
    };
    if close_link {
        match asm.process_link_state_event(ingress_link_id, LinkEvent::Error) {
            Err(e) => {
                error!(target: ZDP, "Link {ingress_link_id}: failed to process Error event: {e}");
            }
            Ok(()) => (),
        }
    }

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

    let _ = dispatch_link_state_event_or_error(
        asm,
        link_id,
        LinkEvent::ReceivedHelloResponse(status, aaa_address.unwrap(), maybe_asa_addrs),
    );

    Ok(())
}

fn process_window_size_tlv(
    asm: &Assembly,
    link_id: zpr::LinkId,
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

    let _ = dispatch_link_state_event_or_error(
        asm,
        ingress_link_id,
        LinkEvent::ReceivedAcquireZprAddressRequest(actor_addresses, blob),
    );

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

    let processing_result = asm.process_link_state_event(
        ingress_link_id,
        LinkEvent::ReceivedGrantZprAddressRequest(grant_event_payload),
    );

    // If we got an error from the state machine, send an error back into it.
    if let Err(e) = processing_result {
        error!(target: ZDP, "Link {ingress_link_id}: Failed to process GrantZprAddressRequest event: {:?}", e);
        let _ignore_errors = asm.process_link_state_event(ingress_link_id, LinkEvent::Error);
    }
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
    txn_id: u16,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let Ok(hdr) = zdp::ZdpBindActorAddressRequestHeader::read_from_buf(&mut pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    let classification = match classifier::classify(&mut pkt) {
        Ok(cls) => cls,
        Err(_why) => {
            return Err(HandleMgmtError::BadStructure);
        }
    };

    match classification {
        classifier::ClassifierResult::OK => (),
        classifier::ClassifierResult::UnclassifiedL4 => {
            warn!(target: ZDP, "Link {}: unsupported IP protocol {}", pkt.metadata().ingress_link_id, pkt.metadata().get_l4_protocol());
            return Err(HandleMgmtError::BadStructure);
        }
        _ => {
            return Err(HandleMgmtError::BadStructure);
        }
    }

    // This step is likely not strictly necessary, the original format set the src and dst
    // port to be the same when using ICMP or IPV6_ICMP, which classifier::classify does not
    // so this keeps it in line
    match pkt.metadata().get_l4_protocol() {
        ip_number::ICMP | ip_number::IPV6_ICMP => {
            let metadata = pkt.metadata_mut();
            metadata.set_dst_port(metadata.get_src_port_hbo());
        }
        _ => (),
    }
    let five_tuple = *pkt.metadata().five_tuple();

    let packet_body: Vec<u8> = pkt.body().to_vec(); // copy to send to visa service

    let compression_mode = hdr.compression_mode;

    let Some(ingress_link_id) = NonZero::new(pkt.metadata().ingress_link_id) else {
        // who sent this??
        error!(target: FLOW_MGMT, "coding error: stray packet from unknown source; dropping");
        return Ok(());
    };

    debug!(
        target: ZDP,
        "Link {}: handlers.handle_bind_actor_address_request -- five_tuple {five_tuple}", ingress_link_id.get(),
    );

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
        txn_id,
        rsp_pkt,
    )
    .await?;

    Ok(())
}
