//! Management requests.
//!
//! No logic lives in here; this is just a simple API to send ZDP messages.

#![allow(dead_code)]

use super::core::{self, Sent};
use super::txn_mgr::TxnId;
use crate::config;
use crate::counters::ManagementCounterType;
use crate::defs::*;
use crate::logging::targets::ZDP;
use crate::tc;
use crate::zdp;
use crate::{assembly::Assembly, auth};

use bytes::{Buf, BufMut};
use std::net::IpAddr;
use thiserror::Error;
use tracing::*;
use zpr::packet_info::{KmId, L3Type, L3TypeDeriveable, LinkId, StreamId, Tcst};
use zpr_ext::zerocopy::{FromBytesExt, IntoBytesExt};

/// send a Key Management message (RFC 6.5 § 6.2.8)
pub fn send_key_management(asm: &Assembly, link_id: LinkId, km_id: KmId, payload: &[u8]) {
    let mut pkt = core::new_heap_packet();

    let km_hdr = pkt.alloc_zeroed_header::<zdp::ZdpKeyManagementHeader>();
    km_hdr.message_type = km_id.into();
    km_hdr.message_length = (payload.len() as u16).into();

    pkt.put(payload);

    let hdr = pkt.alloc_zeroed_header::<zdp::ZdpBaseHeader>();
    hdr.packet_type = zdp::ZdpPacketType::KeyManagement;

    // bypass ZDPR
    let _ = asm
        .mgmt_substrate_egress
        .try_enqueue_packet(link_id, &mut pkt);
}

/// send a Discard message (RFC 6.5 § 6.3.1)
pub fn send_discard(asm: &Assembly, link_id: LinkId) -> Sent<'_> {
    let pkt = core::new_heap_packet();
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::Discard, pkt)
}

/// send an Echo Request (RFC 6.5 § 6.3.2)
pub fn send_echo_request(asm: &Assembly, link_id: LinkId) -> Sent<'_> {
    let mut pkt = core::new_heap_packet();
    pkt.alloc_zeroed_header::<zdp::ZdpEchoHeader>();
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::EchoRequest, pkt)
}

/// send a Hello Request and wait for the Response (RFC 6.5 § 6.3.4)
///
/// Originally this was used to send the pre-configured ZPR address of the
/// remote adapter into the node.  This is no longer necessary.
///
pub fn send_hello_request(asm: &Assembly, link_id: LinkId) -> Sent<'_> {
    let mut pkt = core::new_heap_packet();
    pkt.alloc_zeroed_header::<zdp::ZdpHelloRequestHeader>();
    super::helpers::put_window_size_tlv(asm, link_id, &mut pkt);
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::HelloRequest, pkt)
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
    link_id: LinkId,
    flags: u8,
    payload: auth::ZdpInitAuthenticationPayload,
) -> Sent<'_> {
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
/// The `actor_addrs` is a list of addresses that this sender is
/// requesting.  It will be up to the visa service to determine
/// the correct address(es) to grant.
///
/// The `blob` is for bootstrap authentcation and can be empty.
///
/// Once this returns the link_state should transition to RegisterAA
/// as we wait for a grant.
///
/// ## Panics
/// - Panics if all requested addresses are not the same IP version.
pub fn send_acquire_zpr_address_request<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    actor_addrs: &'_ [IpAddr],
    blob: Option<&'_ [u8]>,
) -> Sent<'a> {
    let blob = blob.unwrap_or_default();

    let mut req = core::new_heap_packet();

    let ip_version = if actor_addrs.is_empty() {
        L3Type::Ipv6 // whatever, doesn't matter since count is zero.
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
                if ip_version != L3Type::Ipv4 {
                    panic!(
                        "attempt to send an IPv4 address with IPv6 type acquire zpr address packet"
                    )
                }
                req.put(&addr.octets()[..])
            }
            IpAddr::V6(addr) => {
                if ip_version != L3Type::Ipv6 {
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
pub fn send_grant_zpr_address_request<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    status_code: zdp::ResponseCode,
    actor_addrs: &'_ [IpAddr],
) -> Sent<'a> {
    info!(target: ZDP, "Link {link_id} - sending GrantZprAddressRequest, status: {status_code:?}");

    let mut req = core::new_heap_packet();

    let ip_version = if actor_addrs.is_empty() {
        L3Type::Ipv6 // whatever, doesn't matter since count is zero.
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
                if ip_version != L3Type::Ipv4 {
                    panic!(
                        "attempt to send an IPv4 address with IPv6 type grant zpr address packet"
                    )
                }
                req.put(&addr.octets()[..])
            }
            IpAddr::V6(addr) => {
                if ip_version != L3Type::Ipv6 {
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
    link_id: LinkId,
    reason: zdp::TerminateReason,
) -> Sent<'_> {
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
    link_id: LinkId,
    reason: zdp::TerminateReason,
) -> Sent<'_> {
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
    #[error("bad structure")]
    BadStructure,
    #[error("{0}")]
    BindActorAddressError(String),
    #[error("link closed")]
    LinkClosed,
}

impl From<core::MgmtSendError> for BindActorAddressError {
    fn from(err: core::MgmtSendError) -> Self {
        match err {
            core::MgmtSendError::LinkClosed => Self::LinkClosed,
        }
    }
}

/// send a Bind Actor Address Request and wait for the Response (RFC 6.5 § 6.3.11)
pub fn send_bind_actor_address_request<'a>(
    asm: &'a Assembly,
    link_id: LinkId,
    txn_id: TxnId,
    five_tuple: &FiveTuple,
    packet_body: &[u8],
) -> Sent<'a> {
    info!(target: ZDP, "Link {link_id}: sending BindActorAddressRequest for {five_tuple} with packet_body size {}", packet_body.len());

    let mut req = core::new_heap_packet();
    let bind_req_hdr = req.alloc_zeroed_header::<zdp::ZdpBindActorAddressRequestHeader>();
    let endpoint_packet_length =
        std::cmp::min(config::BIND_REQUEST_MAX_PAYLOAD_LENGTH, packet_body.len());
    bind_req_hdr
        .endpoint_packet_length
        .set(endpoint_packet_length as u16);
    req.put_slice(&packet_body[..endpoint_packet_length]);

    core::send_per_flow_txn_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::BindActorAddressRequest,
        0,
        txn_id,
        req,
    )
}

pub async fn send_bind_egress_stream_request(
    asm: &Assembly,
    link_id: LinkId,
    tc: tc::Ip5TupleTc,
) -> Result<StreamId, BindActorAddressError> {
    info!(target: ZDP, "Link {link_id}: sending BindEgressStreamRequest for {tc}");

    let (sender, receiver) = tokio::sync::oneshot::channel();

    let Some(peer_state) = asm.peer_table.get(link_id) else {
        return Err(BindActorAddressError::LinkClosed);
    };

    let txn = peer_state.txn_mgr.open().await;
    let txn_id = txn.id();
    peer_state
        .bind_req_state
        .lock()
        .unwrap()
        .insert(txn, sender);

    drop(peer_state);

    let mut req = core::new_heap_packet();
    let bind_req_hdr = req.alloc_zeroed_header::<zdp::ZdpBindEgressStreamRequestHeader>();
    bind_req_hdr.tcst = Tcst::Ip5Tuple;
    tc.serialize(&mut req);

    core::send_per_flow_txn_mgmt(
        asm,
        link_id,
        zdp::ZdpPacketType::BindEgressStreamRequest,
        0,
        txn_id,
        req,
    )
    .await?;

    let Ok(mut resp) = receiver.await else {
        return Err(BindActorAddressError::LinkClosed);
    };

    let Ok(hdr) = zdp::ZdpBindEgressStreamResponseHeader::read_from_buf(&mut resp) else {
        core::count_event(asm, ManagementCounterType::BadStructure);
        return Err(BindActorAddressError::BadStructure);
    };

    match hdr.status_code {
        zdp::ResponseCode::Success => Ok(resp.metadata().ingress_stream_id),

        zdp::ResponseCode::Other => {
            if hdr.info_len as usize > resp.remaining() {
                core::count_event(asm, ManagementCounterType::BadStructure);
                return Err(BindActorAddressError::BadStructure);
            }

            let Ok(msg) = std::str::from_utf8(&resp.body()[..hdr.info_len as usize]) else {
                core::count_event(asm, ManagementCounterType::BadStructure);
                return Err(BindActorAddressError::BadStructure);
            };

            Err(BindActorAddressError::BindActorAddressError(msg.to_owned()))
        }

        _ => {
            core::count_event(asm, ManagementCounterType::BadStructure);
            Err(BindActorAddressError::BadStructure)
        }
    }
}

/// send a Report message (RFC 6.5 § 6.3.13)
pub fn send_report<'a>(asm: &'a Assembly, link_id: LinkId, report: &'_ str) -> Sent<'a> {
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
