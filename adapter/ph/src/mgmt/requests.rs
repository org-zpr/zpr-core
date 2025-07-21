//! Management requests.
//!
//! No logic lives in here; this is just a simple API to send ZDP messages.

#![allow(dead_code)]

use super::core;
use crate::counters::CounterType;
use crate::defs::*;
use crate::logging::targets::ZDP;
use crate::tlv::TlvEncoding;
use crate::zdp;
use crate::{assembly::Assembly, auth};

use bytes::{Buf, BufMut};
use std::net::{IpAddr, Ipv6Addr};
use thiserror::Error;
use tracing::*;
use zpr::{self, L3TypeDeriveable};
use zpr_ext::zerocopy::{FromBytesExt, IntoBytesExt};

/// send a Key Management message (RFC 6.5 § 6.2.8)
pub fn send_key_management(
    asm: &Assembly,
    link_id: zpr::LinkId,
    km_id: zpr::KmId,
    payload: &[u8],
) -> zpr::SeqNum {
    let mut pkt = core::new_heap_packet();

    let km_hdr = pkt.alloc_zeroed_header::<zdp::ZdpKeyManagementHeader>();
    km_hdr.message_type = km_id.into();
    km_hdr.message_length = (payload.len() as u16).into();

    pkt.put(payload);

    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::KeyManagement, pkt)
}

/// send a Discard message (RFC 6.5 § 6.3.1)
pub fn send_discard(asm: &Assembly, link_id: zpr::LinkId) -> zpr::SeqNum {
    let pkt = core::new_heap_packet();
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Discard, pkt)
}

/// send an Echo Request (RFC 6.5 § 6.3.2)
pub fn send_echo_request(asm: &Assembly, link_id: zpr::LinkId) -> zpr::SeqNum {
    let mut pkt = core::new_heap_packet();
    pkt.alloc_zeroed_header::<zdp::ZdpEchoHeader>();
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::EchoRequest, pkt)
}

/// send a Hello Request and wait for the Response (RFC 6.5 § 6.3.4)
///
/// Originally this was used to send the pre-configured ZPR address of the
/// remote adapter into the node.  This is no longer necessary.
///
/// TODO: Remove the addrs parameter.
pub fn send_hello_request(
    asm: &Assembly,
    link_id: zpr::LinkId,
    actor_addrs: &[IpAddr],
) -> zpr::SeqNum {
    let mut req = core::new_heap_packet();
    for addr in actor_addrs {
        let tlv = TlvEncoding::new_static_addr_std(addr.to_owned());
        tlv.put(&mut req);
    }
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::HelloRequest, req)
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
pub fn send_init_authentication_request(
    asm: &Assembly,
    link_id: zpr::LinkId,
    flags: u8,
    payload: auth::ZdpInitAuthenticationPayload,
) -> zpr::SeqNum {
    debug!(target: ZDP, "Link {link_id}: sending InitAuthenticationRequest, flags: {flags:x?}");

    let mut req = core::new_heap_packet();

    let hdr = zdp::ZdpInitAuthenticationRequestHeader {
        flags,
        data_len: (size_of::<auth::ZdpInitAuthenticationPayload>() as u16).into(),
    };
    hdr.write_to_buf(&mut req).unwrap();
    payload.write_to_buf(&mut req).unwrap();

    core::send_non_flow_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::InitAuthenticationRequest,
        req,
    )
}

/// Send an AcquireZPRAddressRequest (TODO: not yet in RFC 6)
///
/// The `blob` is for bootstrap authentcation and can be empty.
///
/// Once this returns the link_state should transition to RegisterAA
/// as we wait for a grant.
///
/// ## Panics
/// - Panics if all requested addresses are not the same IP version.
pub fn send_acquire_zpr_address_request(
    asm: &Assembly,
    link_id: zpr::LinkId,
    actor_addrs: &[IpAddr],
    blob: Option<&[u8]>,
) -> zpr::SeqNum {
    let blob = blob.unwrap_or_default();

    let mut req = core::new_heap_packet();

    let ip_version = if actor_addrs.is_empty() {
        zpr::L3Type::Ipv6 // whatever, doesn't matter since count is zero.
    } else {
        actor_addrs[0].l3_type()
    };
    let hdr = zdp::ZdpAcquireZprAddressRequestHeader {
        blob_len: (blob.len() as u16).into(),
        ip_version,
        addr_count: actor_addrs.len() as u8,
    };
    hdr.write_to_buf(&mut req).unwrap();
    req.put_slice(blob);
    for addr in actor_addrs {
        match addr {
            IpAddr::V4(addr) => {
                if ip_version != zpr::L3Type::Ipv4 {
                    panic!(
                        "attempt to send an IPv4 address with IPv6 type acquire zpr address packet"
                    )
                }
                req.put(&addr.octets()[..])
            }
            IpAddr::V6(addr) => {
                if ip_version != zpr::L3Type::Ipv6 {
                    panic!(
                        "attempt to send an IPv6 address with IPv4 type acquire zpr address packet"
                    )
                }
                req.put(&addr.octets()[..])
            }
        }
    }

    core::send_non_flow_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::AcquireZprAddressRequest,
        req,
    )
}

/// Send an GrantZprAddressRequest (TODO: not yet in RFC 6)
///
/// All granted addresses must be same IP version.
///
/// Once this returns the link_state should transition from RegisterAA
/// to (I think) Active.
///
/// ## Panics
/// - Panics if all granted addresses are not the same IP version.
pub fn send_grant_zpr_address_request(
    asm: &Assembly,
    link_id: zpr::LinkId,
    status_code: zdp::ResponseCode,
    actor_addrs: &[IpAddr],
) -> zpr::SeqNum {
    info!(target: ZDP, "Link {link_id} - sending GrantZprAddressRequest, status: {status_code:?}");

    let mut req = core::new_heap_packet();

    let ip_version = if actor_addrs.is_empty() {
        zpr::L3Type::Ipv6 // whatever, doesn't matter since count is zero.
    } else {
        actor_addrs[0].l3_type()
    };
    let hdr = zdp::ZdpGrantZprAddressRequestHeader {
        status_code,
        ip_version,
        addr_count: actor_addrs.len() as u8,
    };
    hdr.write_to_buf(&mut req).unwrap();
    for addr in actor_addrs {
        match addr {
            IpAddr::V4(addr) => {
                if ip_version != zpr::L3Type::Ipv4 {
                    panic!(
                        "attempt to send an IPv4 address with IPv6 type grant zpr address packet"
                    )
                }
                req.put(&addr.octets()[..])
            }
            IpAddr::V6(addr) => {
                if ip_version != zpr::L3Type::Ipv6 {
                    panic!(
                        "attempt to send an IPv6 address with IPv4 type grant zpr address packet"
                    )
                }
                req.put(&addr.octets()[..])
            }
        }
    }

    core::send_non_flow_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::GrantZprAddressRequest,
        req,
    )
}

/// send a Terminate Request (RFC 6.5 § 6.3.3)
pub fn send_terminate_request<'a, 'pktbuf>(
    asm: &Assembly,
    link_id: zpr::LinkId,
    reason: zdp::TerminateReason,
) -> zpr::SeqNum {
    let mut pkt = core::new_heap_packet();
    pkt.push_header(&zdp::ZdpTerminateLinkRequestHeader {
        reason_code: reason,
        data_len: 0,
    });
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::TerminateLinkRequest, pkt)
}

/// send a Terminate Indication (RFC 6.5 § 6.3.3)
pub fn send_terminate_indication<'a, 'pktbuf>(
    asm: &Assembly,
    link_id: zpr::LinkId,
    reason: zdp::TerminateReason,
) -> zpr::SeqNum {
    let mut pkt = core::new_heap_packet();
    let hdr = pkt.alloc_zeroed_header::<zdp::ZdpTerminateLinkIndicationHeader>();
    hdr.reason_code = reason;
    core::send_non_flow_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::TerminateLinkIndication,
        pkt,
    )
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
    info!(target: ZDP, "Link {link_id}: sending BindActorAddressRequest for {five_tuple} with compression mode {compression_mode} packet_body size {}", packet_body.len());
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

            // No longer append source/dest addresses or layer4 protocol; just append the packet body
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

/// send a Report message (RFC 6.5 § 6.3.13)
pub fn send_report(asm: &Assembly, link_id: zpr::LinkId, report: &str) -> zpr::SeqNum {
    // TODO this condition will need to be adjusted when we have complete ZPR packets
    // with the information at the end of the packet at well
    /*if packet::PACKET_BUFFER_MAX_BODY_SIZE - config::DEFAULT_MESSAGE_HEADROOM < report.len() {
        return;
    }*/  // CTP FIXME
    let mut pkt = core::new_heap_packet();
    let hdr = pkt.alloc_zeroed_header::<zdp::ZdpReportHeader>();
    hdr.report_data_length = (report.len() as u16).into();
    pkt.put(report.as_bytes());
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Report, pkt)
}
