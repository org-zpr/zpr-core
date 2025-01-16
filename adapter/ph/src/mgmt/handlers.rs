//! Handlers for management requests.

use crate::adapter_tables;
use crate::assembly::{self, Assembly, PhMode};
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
use tracing::*;
use zpr;
use zpr_ext::zerocopy::{FromBytesExt, IntoBytesExt};

pub enum HandleMgmtError {
    UnknownType(u8),
    BadStructure,
    LinkStateError,
}

impl From<HandleMgmtError> for counters::CounterType {
    fn from(err: HandleMgmtError) -> Self {
        match err {
            HandleMgmtError::UnknownType(_type) => Self::UnknownType,
            HandleMgmtError::BadStructure => Self::BadStructure,
            HandleMgmtError::LinkStateError => Self::OtherError,
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

/// handle a Terminate Request (RFC 6.5 § 6.3.3)
pub async fn handle_terminate_request(
    asm: &Arc<Assembly>,
    seq_num: zpr::SeqNum,
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

    super::core::send_non_flow_mgmt_response(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::TerminateLinkResponse,
        seq_num,
        rsp_pkt,
    )
    .await;

    if response_code == zdp::ResponseCode::Success {
        let _ = asm.process_link_state_event(ingress_link_id, LinkEvent::SentTerminate);
    }
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
pub async fn handle_hello_request(
    asm: &Arc<Assembly>,
    seq_num: zpr::SeqNum,
    pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;

    debug!(target: ZDP, "Received Hello Request for link {ingress_link_id}");

    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = rsp_pkt.alloc_zeroed_header::<zdp::ZdpHelloResponseHeader>();

    hdr.status =
        match asm.process_link_state_event(ingress_link_id, LinkEvent::ReceivedHelloRequest) {
            Err(_) => zdp::ResponseCode::Other,
            Ok(()) => zdp::ResponseCode::Success,
        };

    super::core::send_non_flow_mgmt_response(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::HelloResponse,
        seq_num,
        rsp_pkt,
    )
    .await;
    Ok(())
}

/// handle a Hello Response (RFC 6.5 § 6.3.4)
pub async fn handle_hello_response(
    asm: &Arc<Assembly>,
    _seq_num: zpr::SeqNum,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let Ok(hdr) = zdp::ZdpHelloResponseHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };
    let status = hdr.status;
    debug!(target: ZDP, "Received Hello Response for link {ingress_link_id}, status: {status:?}");

    if asm
        .process_link_state_event(ingress_link_id, LinkEvent::ReceivedHelloResponse(status))
        .is_err()
    {
        return Err((HandleMgmtError::LinkStateError, pkt));
    };

    Ok(())
}

/// handle a Register Agent Address Request (RFC 6.5 § 6.3.10)
pub async fn handle_register_agent_address_request(
    asm: &Arc<Assembly>,
    seq_num: zpr::SeqNum,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;

    let mut status_code = zdp::ResponseCode::Other;
    if let Ok(agent_address) = parse_register_agent_address_request(&mut pkt) {
        debug!(target: ZDP, "Received Register Agent Address Request for link {ingress_link_id} with address {agent_address}");

        if asm
            .process_link_state_event(
                ingress_link_id,
                LinkEvent::ReceivedRegisterRequest(agent_address),
            )
            .is_ok()
        {
            status_code = zdp::ResponseCode::Success;
        }
    }

    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = rsp_pkt.alloc_zeroed_header::<zdp::ZdpRegisterAgentAddressResponseHeader>();
    hdr.status_code = status_code;

    super::core::send_non_flow_mgmt_response(
        asm,
        ingress_link_id,
        zdp::ZdpPacketType::RegisterAgentAddressResponse,
        seq_num,
        rsp_pkt,
    )
    .await;
    Ok(())
}

fn parse_register_agent_address_request(pkt: &mut Packet) -> Result<IpAddress, HandleMgmtError> {
    let Ok(hdr) = zdp::ZdpRegisterAgentAddressRequestHeader::read_from_buf(pkt) else {
        return Err(HandleMgmtError::BadStructure);
    };

    let agent_address: IpAddress;
    match hdr.ip_version {
        zpr::L3Type::Ipv4 => {
            let Ok(agent_addr) = <[u8; 4]>::read_from_buf(pkt) else {
                return Err(HandleMgmtError::BadStructure);
            };
            agent_address = agent_addr.into();
        }
        zpr::L3Type::Ipv6 => {
            let Ok(agent_addr) = <[u8; 16]>::read_from_buf(pkt) else {
                return Err(HandleMgmtError::BadStructure);
            };
            agent_address = agent_addr.into();
        }

        _ => {
            return Err(HandleMgmtError::BadStructure);
        }
    }
    Ok(agent_address)
}

/// handle a Register Agent Address Response (RFC 6.5 § 6.3.10)
pub async fn handle_register_agent_address_response(
    asm: &Arc<Assembly>,
    _seq_num: zpr::SeqNum,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let ingress_link_id = pkt.metadata().ingress_link_id;
    let Ok(hdr) = zdp::ZdpRegisterAgentAddressResponseHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };
    let status = hdr.status_code;

    debug!(target: ZDP, "Received Register Agent Address Response for link {ingress_link_id} with status {status:?}");

    if asm
        .process_link_state_event(ingress_link_id, LinkEvent::ReceivedRegisterResponse(status))
        .is_err()
    {
        return Err((HandleMgmtError::LinkStateError, pkt));
    };
    Ok(())
}

/// handle a Bind Agent Address Request (RFC 6.5 § 6.3.11)
pub async fn handle_bind_agent_address_request(
    asm: &Arc<Assembly>,
    seq_num: zpr::SeqNum,
    mut pkt: Packet,
) -> HandleMgmtResult {
    let Ok(hdr) = zdp::ZdpBindAgentAddressRequestHeader::read_from_buf(&mut pkt) else {
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
            match super::dock::bind_agent_address(
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
                    // TODO: maybe tick a counter somewhere?
                    zdp::ZdpBindAgentAddressResponseHeader {
                        status_code: zdp::ResponseCode::Success,
                        info_len: 0,
                    }
                    .write_to_buf(&mut rsp_pkt)
                    .unwrap();

                    ingress_tether_id = ingress_tid;
                }

                Err(super::dock::BindAgentAddressError::PolicyError) => {
                    // send error to requestor
                    let message = "policy error";

                    zdp::ZdpBindAgentAddressResponseHeader {
                        status_code: zdp::ResponseCode::Other,
                        info_len: message.len() as u8,
                    }
                    .write_to_buf(&mut rsp_pkt)
                    .unwrap();

                    rsp_pkt.put(message.as_bytes());

                    ingress_tether_id = 0;
                }

                Err(super::dock::BindAgentAddressError::AddRouteError(
                    assembly::AddRouteError::PftFull,
                )) => {
                    // PFT full; respond with error message
                    // TODO: maybe tick a counter somewhere?
                    let message = "PFT full";

                    zdp::ZdpBindAgentAddressResponseHeader {
                        status_code: zdp::ResponseCode::Other,
                        info_len: message.len() as u8,
                    }
                    .write_to_buf(&mut rsp_pkt)
                    .unwrap();

                    rsp_pkt.put(message.as_bytes());

                    ingress_tether_id = 0;
                }

                Err(super::dock::BindAgentAddressError::AddRouteError(
                    assembly::AddRouteError::PeerGone,
                )) => {
                    // peer went away; don't bother responding
                    return Ok(());
                }

                Err(super::dock::BindAgentAddressError::AddRouteError(
                    assembly::AddRouteError::BindFailed(err),
                )) => {
                    // unable to bind next-hop; respond with error message
                    // TODO: maybe tick a counter somewhere?
                    let message = format!("unable to bind next-hop: {}", err);

                    zdp::ZdpBindAgentAddressResponseHeader {
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
                    zdp::ZdpBindAgentAddressResponseHeader {
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

                    zdp::ZdpBindAgentAddressResponseHeader {
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
        zdp::ZdpPacketType::BindAgentAddressResponse,
        ingress_tether_id,
        seq_num,
        rsp_pkt,
    )
    .await;

    Ok(())
}
