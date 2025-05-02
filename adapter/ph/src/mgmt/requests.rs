//! Management requests.
#![allow(dead_code)]

use super::core;
use crate::auth::ZdpInitAuthenticationPayload;
use crate::counters::CounterType;
use crate::defs::*;
use crate::logging::targets::ZDP;
use crate::mgmt::core::SyncReqError;
use crate::zdp;
use crate::{assembly::Assembly, auth};

use bytes::{Buf, BufMut};
use std::net::IpAddr;
use thiserror::Error;
use tracing::*;
use zpr::{self, L3TypeDeriveable};
use zpr_ext::zerocopy::{FromBytesExt, IntoBytesExt};

/// send a Key Management message (RFC 6.5 § 6.2.8)
pub async fn send_key_management(
    asm: &Assembly,
    link_id: zpr::LinkId,
    km_id: zpr::KmId,
    payload: &[u8],
) {
    let mut pkt = core::new_heap_packet();

    let km_hdr = pkt.alloc_zeroed_header::<zdp::ZdpKeyManagementHeader>();
    km_hdr.message_type = km_id.into();
    km_hdr.message_length = (payload.len() as u16).into();

    pkt.put(payload);

    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::KeyManagement, pkt).await;
}

#[allow(dead_code)]
/// send a Discard message (RFC 6.5 § 6.3.1)
pub async fn send_discard(asm: &Assembly, link_id: zpr::LinkId) {
    let pkt = core::new_heap_packet();
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Discard, pkt).await;
}

/// send an Echo Request and wait for the Response (RFC 6.5 § 6.3.2)
pub async fn send_echo_request(asm: &Assembly, link_id: zpr::LinkId) -> Result<(), SyncReqError> {
    let mut echo = core::send_sync_non_flow_req(
        asm,
        link_id,
        zdp::ZdpPacketType::EchoRequest,
        zdp::ZdpPacketType::EchoResponse,
        move |_packet| {},
    )
    .await?;

    // TODO: Break these apart
    let Ok(_) = zdp::ZdpEchoHeader::read_from_buf(&mut echo) else {
        core::count_event(asm, &mut echo, CounterType::BadStructure);
        return Err(SyncReqError::ProtocolError);
    };
    Ok(())
}

/// send a Hello Request and wait for the Response (RFC 6.5 § 6.3.4)
pub async fn send_hello_request(
    asm: &Assembly,
    link_id: zpr::LinkId,
) -> Result<zdp::ResponseCode, ()> {
    let response = core::send_sync_non_flow_req(
        asm,
        link_id,
        zdp::ZdpPacketType::HelloRequest,
        zdp::ZdpPacketType::HelloResponse,
        move |_packet| {},
    )
    .await;

    // TODO: Break these apart
    match response {
        Ok(mut hello_res) => {
            let Ok(hdr) = zdp::ZdpHelloResponseHeader::read_from_buf(&mut hello_res) else {
                core::count_event(asm, &mut hello_res, CounterType::BadStructure);
                return Err(());
            };
            let status = hdr.status;
            debug!(target: ZDP, "Link {link_id}: received HelloResponse, status: {status:?}");
            Ok(status)
        }

        Err(err) => {
            warn!(target: ZDP, "Link {link_id}: error with HelloRequest: {err}");
            Err(())
        }
    }
}

/// Send Init Authentication (NOT YET IN RFC 6)
///
/// A side effect in the Hello Request handler ([handlers::handle_hello_request]).
///
/// Message payload is ([zdp::ZdpInitAuthenticationPayload]):
///
/// Blake 3 hash is used in keyed-hash mode. The peer_table keeps track of a 256-bit
/// key on each link.  It in the future it may even change it from time to time.
/// The nonce and hash are returned in the bootstrap authentication BLOB and
/// are checked by the node before processing.
///
pub async fn send_init_authentication_request(
    asm: &Assembly,
    link_id: zpr::LinkId,
) -> Result<zdp::ResponseCode, ()> {
    // TODO: Whether or not we are in bootstrap mode comes from visa service.  For now hardcoded ON.
    let is_bootstrap = true;

    let payload: auth::ZdpInitAuthenticationPayload;
    let mut flags = 0u8;

    if is_bootstrap {
        flags |= zdp::init_authentication_flags::BOOTSTRAP_SUPPORT;

        // TODO: Pretty sure I do not need `inspect_sync` below. The key is set at create time and not changed.
        let key = asm.peer_table.inspect(link_id, {
            |peer| {
                let mut key = [0u8; auth::AUTH_KEY_SIZE_BYTES];
                key[0..auth::AUTH_KEY_SIZE_BYTES]
                    .copy_from_slice(&peer.auth_key[0..auth::AUTH_KEY_SIZE_BYTES]);
                key
            }
        });
        match key {
            Some(key) => payload = ZdpInitAuthenticationPayload::new(&key),
            None => {
                // TODO: Possibly we want to send the Init Authentication message anyway, but
                //       just not support bootstrap mode.
                error!(target: ZDP, "unable to send Init Authentication: no auth key found for link {link_id}");
                return Err(());
            }
        }
    } else {
        payload = ZdpInitAuthenticationPayload::new_empty();
    }
    debug!(target: ZDP, "Link {link_id}: sending IntitAuthenticationRequest, flags: {flags:x?}");
    let response = core::send_sync_non_flow_req(
        asm,
        link_id,
        zdp::ZdpPacketType::InitAuthenticationRequest,
        zdp::ZdpPacketType::InitAuthenticationResponse,
        move |mut req| {
            let hdr = zdp::ZdpInitAuthenticationRequestHeader {
                flags,
                data_len: (size_of::<auth::ZdpInitAuthenticationPayload>() as u16).into(),
            };
            hdr.write_to_buf(&mut req).unwrap();
            payload.write_to_buf(&mut req).unwrap();
        },
    )
    .await;

    match response {
        Ok(mut init_auth_res) => {
            let Ok(hdr) =
                zdp::ZdpInitAuthenticationResponseHeader::read_from_buf(&mut init_auth_res)
            else {
                core::count_event(asm, &mut init_auth_res, CounterType::BadStructure);
                return Err(());
            };
            let status = hdr.status_code;
            debug!(target: ZDP, "Link {link_id}: Received InitAuthenticationResponse, status: {status:?}");
            Ok(status)
        }

        Err(err) => {
            warn!(target: ZDP, "Link {link_id}: error with InitAuthenticationRequest: {}", err);
            Err(())
        }
    }
}

/// Send an AcquireZPRAddressRequest (TODO: not yet in RFC 6)
///
/// All requested addresses must be same IP version.
/// The `blob` is for bootstrap authentcation and can be empty.
///
/// Once this returns the link_state should transition to RegisterAA
/// as we wait for a grant.
pub async fn send_acquire_zpr_address_request(
    asm: &Assembly,
    link_id: zpr::LinkId,
    actor_addrs: &[IpAddr],
    blob: Option<Vec<u8>>,
) -> Result<zdp::ResponseCode, ()> {
    // Copy the blob amd addrs for use in closure below.
    let blob_data = blob.unwrap_or_default();
    let mut c_actor_addrs = Vec::new();
    c_actor_addrs.extend_from_slice(actor_addrs);

    let response = core::send_sync_non_flow_req(
        asm,
        link_id,
        zdp::ZdpPacketType::AcquireZprAddressRequest,
        zdp::ZdpPacketType::AcquireZprAddressResponse,
        move |mut req| {
            let ip_version = if c_actor_addrs.is_empty() {
                zpr::L3Type::Ipv6 // whatever, doesn't matter since count is zero.
            } else {
                c_actor_addrs[0].l3_type()
            };
            let hdr = zdp::ZdpAcquireZprAddressRequestHeader {
                blob_len: (blob_data.len() as u16).into(),
                ip_version,
                addr_count: c_actor_addrs.len() as u8,
            };
            hdr.write_to_buf(&mut req).unwrap();
            if !blob_data.is_empty() {
                req.put_slice(&blob_data);
            }
            for addr in &c_actor_addrs {
                match addr {
                    IpAddr::V4(addr) => req.put(&addr.octets()[..]),
                    IpAddr::V6(addr) => req.put(&addr.octets()[..]),
                }
            }
        },
    )
    .await;

    match response {
        Ok(mut rpkt) => {
            let Ok(hdr) = zdp::ZdpAcquireZprAddressResponseHeader::read_from_buf(&mut rpkt) else {
                core::count_event(asm, &mut rpkt, CounterType::BadStructure);
                return Err(());
            };
            let resp_code = hdr.status_code;
            debug!(
                "Link {link_id} Received AcquireZprAddressResponse, status: {:?}",
                resp_code
            );
            Ok(resp_code)
        }

        Err(err) => {
            warn!(
                "Link {link_id}: error with AcquireZprAddressResponse: {}",
                err
            );
            Err(())
        }
    }
}

/// Send an GrantZprAddressRequest (TODO: not yet in RFC 6)
///
/// All granted addresses must be same IP version.
///
/// Once this returns the link_state should transition from RegisterAA
/// to (I think) Active.
pub async fn send_grant_zpr_address_request(
    asm: &Assembly,
    link_id: zpr::LinkId,
    status_code: zdp::ResponseCode,
    actor_addrs: &[IpAddr],
) -> Result<zdp::ResponseCode, ()> {
    let mut c_actor_addrs = Vec::new();
    c_actor_addrs.extend_from_slice(actor_addrs);

    info!(target: ZDP, "Link {link_id} - sending GrantZprAddressRequest, status: {status_code:?}");
    let response = core::send_sync_non_flow_req(
        asm,
        link_id,
        zdp::ZdpPacketType::GrantZprAddressRequest,
        zdp::ZdpPacketType::GrantZprAddressResponse,
        move |mut req| {
            let ip_version = if c_actor_addrs.is_empty() {
                zpr::L3Type::Ipv6 // whatever, doesn't matter since count is zero.
            } else {
                c_actor_addrs[0].l3_type()
            };
            let hdr = zdp::ZdpGrantZprAddressRequestHeader {
                status_code,
                ip_version,
                addr_count: c_actor_addrs.len() as u8,
            };
            hdr.write_to_buf(&mut req).unwrap();
            for addr in &c_actor_addrs {
                match addr {
                    IpAddr::V4(addr) => req.put(&addr.octets()[..]),
                    IpAddr::V6(addr) => req.put(&addr.octets()[..]),
                }
            }
        },
    )
    .await;

    match response {
        Ok(mut rpkt) => {
            let Ok(hdr) = zdp::ZdpGrantZprAddressResponseHeader::read_from_buf(&mut rpkt) else {
                core::count_event(asm, &mut rpkt, CounterType::BadStructure);
                return Err(());
            };
            let resp_code = hdr.status_code;
            debug!(
                "Link {link_id}: received GrantZprAddressResponse, status: {:?}",
                resp_code
            );
            Ok(resp_code)
        }

        Err(err) => {
            warn!(
                "Link {link_id}: error with GrantZprAddressResponse: {}",
                err
            );
            Err(())
        }
    }
}

/// send a Terminate Request (RFC 6.5 § 6.3.3)
pub async fn send_terminate_request<'a, 'pktbuf>(
    asm: &Assembly,
    link_id: zpr::LinkId,
    reason: zdp::TerminateReason,
) -> Result<zdp::ResponseCode, ()> {
    let response = core::send_sync_non_flow_req(
        asm,
        link_id,
        zdp::ZdpPacketType::TerminateLinkRequest,
        zdp::ZdpPacketType::TerminateLinkResponse,
        move |mut req| {
            zdp::ZdpTerminateLinkRequestHeader {
                reason_code: reason,
                data_len: 0,
            }
            .write_to_buf(&mut req)
            .unwrap();
        },
    )
    .await;

    // TODO: Break these apart
    match response {
        Ok(mut terminate_res) => {
            let Ok(hdr) = zdp::ZdpTerminateLinkResponseHeader::read_from_buf(&mut terminate_res)
            else {
                core::count_event(asm, &mut terminate_res, CounterType::BadStructure);
                return Err(());
            };
            let resp_code = hdr.response_code;
            debug!(
                "Link {link_id}: received TerminateLinkResponse, status: {:?}",
                resp_code
            );
            Ok(resp_code)
        }

        Err(err) => {
            warn!("Link {link_id}: error with TerminateLinkResponse: {}", err);
            Err(())
        }
    }
}

/// send a Terminate Indication (RFC 6.5 § 6.3.3)
pub async fn send_terminate_indication<'a, 'pktbuf>(
    asm: &Assembly,
    link_id: zpr::LinkId,
    reason: zdp::TerminateReason,
) {
    let mut pkt = core::new_heap_packet();
    let hdr = pkt.alloc_zeroed_header::<zdp::ZdpTerminateLinkIndicationHeader>();
    hdr.reason_code = reason;
    core::send_non_flow_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::TerminateLinkIndication,
        pkt,
    )
    .await;
}

#[derive(Debug, Error)]
pub enum BindActorAddressError {
    #[error("{0}")]
    SyncReqError(core::SyncReqError),
    #[error("bad structure")]
    BadStructure,
    #[error("{0}")]
    BindActorAddressError(Box<str>),
}

/// send a Bind Actor Address Request and wait for the Response (RFC 6.5 § 6.3.11)
pub async fn send_bind_actor_address_request(
    asm: &Assembly,
    link_id: zpr::LinkId,
    compression_mode: zpr::CompressionMode,
    five_tuple: FiveTuple,
    packet_body: Vec<u8>,
) -> Result<zpr::StreamId, BindActorAddressError> {
    let response = core::send_sync_per_flow_req(
        asm,
        link_id,
        zdp::ZdpPacketType::BindActorAddressRequest,
        zdp::ZdpPacketType::BindActorAddressResponse,
        0,
        move |mut req| {
            zdp::ZdpBindActorAddressRequestHeader {
                ip_version: five_tuple.l3_type,
                compression_mode,
            }
            .write_to_buf(&mut req)
            .unwrap();

            match five_tuple.l3_type {
                zpr::L3Type::Ipv4 => {
                    req.put(five_tuple.src_address.read_as_v4().as_slice());
                    req.put(five_tuple.dst_address.read_as_v4().as_slice());
                }

                zpr::L3Type::Ipv6 => {
                    req.put(five_tuple.src_address.v6.as_slice());
                    req.put(five_tuple.dst_address.v6.as_slice());
                }

                other => panic!("Link {link_id}: bad L3 type: {}", other.0),
            }

            req.put_u8(five_tuple.l4_protocol);

            if compression_mode != 0 {
                todo!("L4 compression");
            }

            req.put_slice(&packet_body);
        },
    )
    .await;

    match response {
        Ok((tether_id, mut resp)) => {
            let Ok(hdr) = zdp::ZdpBindActorAddressResponseHeader::read_from_buf(&mut resp) else {
                core::count_event(asm, &mut resp, CounterType::BadStructure);
                return Err(BindActorAddressError::BadStructure);
            };

            match hdr.status_code {
                zdp::ResponseCode::Success => Ok(tether_id),

                zdp::ResponseCode::Other => {
                    if hdr.info_len as usize > resp.remaining() {
                        core::count_event(asm, &mut resp, CounterType::BadStructure);
                        return Err(BindActorAddressError::BadStructure);
                    }

                    let Ok(msg) = std::str::from_utf8(&resp.body()[..hdr.info_len as usize]) else {
                        core::count_event(asm, &mut resp, CounterType::BadStructure);
                        return Err(BindActorAddressError::BadStructure);
                    };
                    let msg: Box<str> = msg.into();

                    Err(BindActorAddressError::BindActorAddressError(msg))
                }

                _ => {
                    core::count_event(asm, &mut resp, CounterType::BadStructure);
                    Err(BindActorAddressError::BadStructure)
                }
            }
        }

        Err(err) => Err(BindActorAddressError::SyncReqError(err)),
    }
}

#[allow(dead_code)]
/// send a Report message (RFC 6.5 § 6.3.13)
pub async fn send_report(asm: &Assembly, link_id: zpr::LinkId, report: &str) {
    // TODO this condition will need to be adjusted when we have complete ZPR packets
    // with the information at the end of the packet at well
    /*if packet::PACKET_BUFFER_MAX_BODY_SIZE - config::DEFAULT_MESSAGE_HEADROOM < report.len() {
        return;
    }*/  // CTP FIXME
    let mut pkt = core::new_heap_packet();
    let hdr = pkt.alloc_zeroed_header::<zdp::ZdpReportHeader>();
    hdr.report_data_length = (report.len() as u16).into();
    pkt.put(report.as_bytes());
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Report, pkt).await;
}
