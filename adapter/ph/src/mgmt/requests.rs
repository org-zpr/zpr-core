//! Management requests.
#![allow(dead_code)]

use super::core;
use crate::assembly::Assembly;
use crate::counters::CounterType;
use crate::defs::*;
use crate::logging::targets::ZDP;
use crate::mgmt::core::SyncReqError;
use crate::peer_table::AUTH_KEY_SIZE_BYTES;
use crate::zdp;
use bytes::{Buf, BufMut};
use openssl::rand::rand_bytes;
use std::net::IpAddr;
use std::time::SystemTime;
use thiserror::Error;
use tracing::*;
use zpr;
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
            debug!(target: ZDP, "Received HelloResponse, status: {status:?}");
            Ok(status)
        }

        Err(err) => {
            warn!(target: ZDP, "{err} error with HelloRequest");
            Err(())
        }
    }
}

/// Send Init Authentication (NOT YET IN RFC 6)
///
/// This call is not integrated into the link state machine and is called
/// as a side effect in the Hello Request handler ([handlers::handle_hello_request]).
///
/// Message payload is ([zdp::ZdpInitAuthenticationPayload]):
///
///     offset  0: flags (1 byte)
///     offset  1: 8-byte nonce
///     offset  9: 8-byte (64 bit, big endian) create time (unix seconds)
///     offset 17: 32-byte blake3 hash
///
/// Blake 3 hash is used in keyed-hash mode. The peer_table keeps track of a 256-bit
/// key on each link.  It in the future it may even change it from time to time.
/// The nonce and hash are returned in the bootstrap authentication BLOB and
/// are checked by the node before processing.
///
pub async fn send_init_authentication(asm: &Assembly, link_id: zpr::LinkId) {
    let ctime = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u64;
    let be_time = ctime.to_be_bytes();

    let mut nonce = [0u8; 8];

    // TODO: Whether or not we are in bootstrap mode comes from visa service.  For now hardcoded ON.
    let is_bootstrap = true;

    let payload: zdp::ZdpInitAuthenticationPayload;

    if is_bootstrap {
        rand_bytes(&mut nonce).expect("failed to generate random bytes for nonce");

        // TODO: Pretty sure I do not need `inspect_sync` below. The key is set at create time and not changed.
        let key = asm.peer_table.inspect(link_id, {
            |peer| {
                let mut key = [0u8; AUTH_KEY_SIZE_BYTES];
                key[0..AUTH_KEY_SIZE_BYTES].copy_from_slice(&peer.auth_key[0..AUTH_KEY_SIZE_BYTES]);
                key
            }
        });

        match key {
            Some(key) => {
                let mut hasher = blake3::Hasher::new_keyed(&key);
                hasher.update(&nonce);
                hasher.update(&be_time);
                let hmac = blake3::keyed_hash(&key, &nonce);
                payload = zdp::ZdpInitAuthenticationPayload {
                    flags: zdp::init_authentication_flags::BOOTSTRAP_SUPPORT,
                    nonce,
                    ctime: ctime.into(),
                    hmac: hmac.into(),
                }
            }
            None => {
                // TODO: Possibly we want to send the Init Authentication message anyway, but
                //       just not support bootstrap mode.
                error!(target: ZDP, "unable to send Init Authentication: no auth key found for link {link_id}");
                return;
            }
        }
    } else {
        // non-bootstrap mode, just send empty payload.
        payload = zdp::ZdpInitAuthenticationPayload {
            flags: 0x0,
            nonce,
            ctime: 0.into(),
            hmac: [0u8; 32],
        };
    }
    let mut pkt = core::new_heap_packet();
    payload.write_to_buf(&mut pkt).unwrap();
    core::send_non_flow_mgmt(asm, link_id, zdp::ZdpPacketType::InitAuthentication, pkt).await;
}

/// send a Register Actor Address Request (RFC 6.5 § 6.3.10)
pub async fn send_register_actor_address_request(
    asm: &Assembly,
    link_id: zpr::LinkId,
    actor_addr: IpAddr,
) -> Result<zdp::ResponseCode, ()> {
    let response = core::send_sync_non_flow_req(
        asm,
        link_id,
        zdp::ZdpPacketType::RegisterActorAddressRequest,
        zdp::ZdpPacketType::RegisterActorAddressResponse,
        move |mut req| match actor_addr {
            IpAddr::V4(addr) => {
                zdp::ZdpRegisterActorAddressRequestHeader {
                    ip_version: zpr::L3Type::Ipv4,
                }
                .write_to_buf(&mut req)
                .unwrap();
                req.put(&addr.octets()[..]);
            }

            IpAddr::V6(addr) => {
                zdp::ZdpRegisterActorAddressRequestHeader {
                    ip_version: zpr::L3Type::Ipv6,
                }
                .write_to_buf(&mut req)
                .unwrap();
                req.put(&addr.octets()[..]);
            }
        },
    )
    .await;

    // TODO: Break these apart
    match response {
        Ok(mut register_res) => {
            let Ok(hdr) =
                zdp::ZdpRegisterActorAddressResponseHeader::read_from_buf(&mut register_res)
            else {
                core::count_event(asm, &mut register_res, CounterType::BadStructure);
                return Err(());
            };
            debug!(
                target: ZDP,
                "Received RegisterActorAddressResponse, status: {:?}",
                hdr.status_code
            );
            return Ok(hdr.status_code);
        }

        Err(err) => {
            warn!(target: ZDP, "{err} error with RegisterActorAddressRequest");
            return Err(());
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
            info!("Received TerminateLinkResponse, status: {:?}", resp_code);
            Ok(resp_code)
        }

        Err(err) => {
            warn!("{} error with TerminateLinkResponse", err);
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

                other => panic!("bad L3 type: {}", other.0),
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
