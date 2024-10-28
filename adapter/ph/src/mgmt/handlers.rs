//! Handlers for management requests.

use crate::adapter_tables;
use crate::assembly::{Assembly, PhMode};
use crate::config;
use crate::counters;
use crate::defs::*;
use crate::dock_tables;
use crate::packet::Packet;
use crate::zdp;
use bytes::{Buf, BufMut};
use tracing::info;
use zpr;
use zpr_ext::zerocopy::{FromBytesExt, IntoBytesExt};

pub enum HandleMgmtError {
    UnknownType(u8),
    UnexpectedMgmtResponse,
    BadStructure,
    UnknownKeyManagementType(u16),
    KeyManagementError(String),
}

impl From<HandleMgmtError> for counters::CounterType {
    fn from(err: HandleMgmtError) -> Self {
        match err {
            HandleMgmtError::UnknownType(_type) => Self::UnknownType,
            HandleMgmtError::UnexpectedMgmtResponse => Self::UnexpectedMgmtResponse,
            HandleMgmtError::BadStructure => Self::BadStructure,
            HandleMgmtError::UnknownKeyManagementType(_type) => Self::OtherError,
            HandleMgmtError::KeyManagementError(_desc) => Self::OtherError,
        }
    }
}

pub type HandleMgmtResult<'pktbuf> = Result<(), (HandleMgmtError, Packet<'pktbuf>)>;

/// handle a Report message (RFC 6.5 § 6.3.13)
pub async fn handle_report<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    mut pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    let Ok(hdr) = zdp::ZdpReportHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    // TODO handle protocol errors i.e. if the body is shorter
    let report_data_length: usize = hdr.report_data_length.into();
    pkt.advance(std::mem::size_of::<zdp::ZdpReportHeader>());
    if pkt.body().len() >= report_data_length {
        info!(
            "{}: {}",
            pkt.metadata().ingress_link_id,
            std::str::from_utf8(&pkt.body()[..report_data_length]).unwrap()
        );
    }
    asm.buffer_stack.put_buffer(pkt.destroy());
    Ok(())
}

/// handle a Discard message (RFC 6.5 § 6.3.1)
pub async fn handle_discard<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    // TODO print to debug log, when implemented
    info!(
        "{}: Discard message received from {}",
        asm.system_name,
        pkt.metadata().ingress_link_id
    );
    asm.buffer_stack.put_buffer(pkt.destroy());
    Ok(())
}

/// handle a Hello Request (RFC 6.5 § 6.3.4)
pub async fn handle_hello_request<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    seq_num: zpr::SeqNum,
    pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    let ingress_link_id = pkt.metadata().ingress_link_id;
    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);
    let hdr = rsp_pkt.alloc_zeroed_header::<zdp::ZdpHelloResponseHeader>();
    hdr.status = 0.into();

    info!("{}: Received HelloRequest", asm.system_name);

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

/// handle a Bind Agent Address Request (RFC 6.5 § 6.3.11)
pub async fn handle_bind_agent_address_request<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    seq_num: zpr::SeqNum,
    mut pkt: Packet<'pktbuf>,
) -> HandleMgmtResult<'pktbuf> {
    let Ok(hdr) = zdp::ZdpBindAgentAddressRequestHeader::read_from_buf(&mut pkt) else {
        return Err((HandleMgmtError::BadStructure, pkt));
    };

    // TODO: handle as node: enter into DFT
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

    let ingress_link_id = pkt.metadata().ingress_link_id;

    // recycle request buffer for response
    let mut rsp_pkt = Packet::new(pkt.destroy(), config::DEFAULT_MESSAGE_HEADROOM);

    let ingress_tether_id;

    match asm.ph_mode {
        PhMode::Node => {
            // TODO: request visa

            // HACK: for now, we assume a visa which forwards through to the other adapter
            // AND ALSO we manually issue a bind request out to that adapter

            let egress_link_id = ingress_link_id % 2 + 1;

            match super::requests::send_bind_agent_address_request(
                asm,
                egress_link_id,
                compression_mode,
                five_tuple,
            )
            .await
            {
                Ok(egress_tether_id) => {
                    // form PEP
                    // TODO: forwarding PEPs
                    let pep = dock_tables::DftPep {
                        next_hop: dock_tables::DftNextHop::Tether(egress_link_id, egress_tether_id),
                    };

                    match asm.peer_table.inspect(ingress_link_id, |peer_state| {
                        match peer_state.dft.insert(pep) {
                            Ok(tid) => {
                                // success; respond with tether ID
                                // TODO: maybe tick a counter somewhere?
                                zdp::ZdpBindAgentAddressResponseHeader {
                                    status_code:
                                        zdp::ZdpBindAgentAddressResponseHeader::STATUS_CODE_SUCCESS,
                                    info_len: 0,
                                }
                                .write_to_buf(&mut rsp_pkt)
                                .unwrap();

                                tid
                            }

                            Err(()) => {
                                // DFT full; respond with error message
                                // TODO: maybe tick a counter somewhere?
                                let message = "DFT full";

                                zdp::ZdpBindAgentAddressResponseHeader {
                                    status_code:
                                        zdp::ZdpBindAgentAddressResponseHeader::STATUS_CODE_OTHER,
                                    info_len: message.len() as u8,
                                }
                                .write_to_buf(&mut rsp_pkt)
                                .unwrap();

                                rsp_pkt.put(message.as_bytes());

                                0
                            }
                        }
                    }) {
                        Some(tid) => ingress_tether_id = tid,

                        None => {
                            // peer went away; don't bother responding
                            asm.buffer_stack.put_buffer(rsp_pkt.destroy());
                            return Ok(());
                        }
                    }

                    // WORKING: factor out message generation using Result<StreamId, Box<str>>
                }

                Err(err) => {
                    // unable to bind next-hop; respond with error message
                    // TODO: maybe tick a counter somewhere?
                    let message = format!("unable to bind next-hop: {}", err);

                    zdp::ZdpBindAgentAddressResponseHeader {
                        status_code: zdp::ZdpBindAgentAddressResponseHeader::STATUS_CODE_OTHER,
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

            // attempt to insert into DLT
            match asm.dlt.insert(pep) {
                Ok(tid) => {
                    // success; respond with tether ID
                    // TODO: maybe tick a counter somewhere?
                    zdp::ZdpBindAgentAddressResponseHeader {
                        status_code: zdp::ZdpBindAgentAddressResponseHeader::STATUS_CODE_SUCCESS,
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
                        status_code: zdp::ZdpBindAgentAddressResponseHeader::STATUS_CODE_OTHER,
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
        ingress_link_id,
        zdp::ZdpPacketType::BindAgentAddressResponse,
        ingress_tether_id,
        seq_num,
        rsp_pkt,
    )
    .await;

    Ok(())
}
