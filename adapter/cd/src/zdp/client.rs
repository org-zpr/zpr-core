use std::io;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use tokio::sync::mpsc;

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use ph::km::{KeyManager, KMSignal};
use ph::km_noise::KMNoise;
use ph::packet::Packet;
use ph::config;
use ph::zdp::*;
use ph::zpr;

use zerocopy::FromBytes;
use bytes::BufMut;


const HEADROOM: usize = 128;



const ZDP_KM_HDR_OFFSET: usize = ZDP_NON_PER_FLOW_MGMT_HEADER_OFFSET;
const ZDP_KM_DATA_OFFSET: usize = ZDP_KM_HDR_OFFSET + std::mem::size_of::<ZdpKeyManagementHeader>();

const ZDP_REPORT_HDR_OFFSET: usize = ZDP_NON_PER_FLOW_MGMT_HEADER_OFFSET;
const ZDP_REPORT_DATA_OFFSET: usize = ZDP_REPORT_HDR_OFFSET + std::mem::size_of::<ZdpReportHeader>();


#[derive(Debug, Clone)]
pub struct ZDPClient {
    addr: SocketAddr,
    dock_noise_pub_key: [u8; 32],
}

impl ZDPClient {
    pub fn new(addr: &SocketAddr, dock_noise_key: [u8; 32]) -> ZDPClient {
        ZDPClient {
            addr: addr.to_owned(),
            dock_noise_pub_key: dock_noise_key,
        }
    }

    // Dummy function for my testing only
    pub async fn run(&self, ctok: CancellationToken) -> io::Result<()> {
        let noise = match KMNoise::new(true, Some(self.dock_noise_pub_key.into()), None){
            Ok(n) => n,
            Err(e) => {
                info!("zdp/client - KMNoise::new failed: {}", e);
                return Err(io::Error::new(io::ErrorKind::Other, "KMNoise::new failed"));
            }
        };

        let mgr = KeyManager::new(Box::new(noise));
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();

        let socket = UdpSocket::bind(local_addr).await?;
        socket.connect(self.addr).await?;

        let s_recv = Arc::new(socket);
        let s_send = s_recv.clone();

        let (km_tx, mut km_rx) = mpsc::channel(16);
        let (km_sig_tx, mut km_sig_rx) = mpsc::channel(16);

        let km_ctok = ctok.clone();
        let mut mgr_cc = mgr.clone();
        tokio::spawn(async move {
            mgr_cc.start(km_ctok, km_tx, km_sig_tx).await.unwrap();
        });

        // Now loop -
        //   read from UDP, pass to KM
        //   write KM messages to UDP
        let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
        loop {
            tokio::select! {
                _ = ctok.cancelled() => {
                    info!("zdp/client - cancelled");
                    break;
                }

                Some(sig) = km_sig_rx.recv() => {
                    match sig {
                        KMSignal::SaIdChange { old, new } => {
                            if old == 0 && new > 0 {
                                info!("zdp/client - new SA established");
                                let mut pkt = Packet::new(&mut buf, 128);

                                let message = b"hello to you my dear node!";
                                let mlen = message.len() as u16;
                                let report_hdr = pkt.alloc_zeroed_header::<ZdpReportHeader>();
                                report_hdr.report_data_length =  mlen.into();

                                let zdp_hdr = pkt.alloc_zeroed_header::<ZdpBaseHeader>();
                                zdp_hdr.packet_type = ZdpPacketType::Report;
                                zdp_hdr.excess_length =  0;
                                zdp_hdr.sequence_number = 0.into();

                                // Do not at ZPI here, the SA_ID is added there by KM.

                                pkt.put(&message[..]);
                                match mgr.encrypt_transport(&mut pkt) {
                                    Ok(()) => {
                                        match s_send.send(&pkt.body()).await {
                                            Ok(sz) => {
                                                info!("zdp/client - sent {} byte transport message", sz);
                                            }
                                            Err(e) => {
                                                info!("zdp/client - send of transport message failed: {}", e);
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        info!("zdp/client - encrypt_transport failed: {}", e);
                                    }
                                }
                            }
                        },
                        _ => {}
                    }
                }

                Some(km_buf) = km_rx.recv() => {
                    // Construct a KM message packet.
                    // [ ZPI ]
                    // [ ZDP BASE HEADER, type=KM]
                    // ---- KM PACKET ---
                    //   type: noise
                    //   len: u16
                    //   PAYLOAD (from KM)
                    let mut pkt_buf = [0u8; config::PACKET_BUFFER_SIZE];
                    let mut pkt = Packet::new(&mut pkt_buf, HEADROOM);
                    pkt.put(&km_buf[..]);

                    let km_hdr = pkt.alloc_zeroed_header::<ZdpKeyManagementHeader>();
                    km_hdr.message_type = zpr::KM_ID_NOISE.into();
                    km_hdr.message_length = (km_buf.len() as u16).into();

                    let zdp_hdr = pkt.alloc_zeroed_header::<ZdpBaseHeader>();
                    zdp_hdr.packet_type = ZdpPacketType::KeyManagement;

                    pkt.alloc_zeroed_header::<ZdpZpiHeader>().zpi = 0;

                    match s_send.send(pkt.body()).await {
                        Ok(sz) => {
                            info!("zdp/client - sent {} byte KM message", sz);
                        }
                        Err(e) => {
                            info!("zdp/client - send of KM message failed: {}", e);
                        }
                    }
                }

                read_result = s_recv.recv(&mut buf) => {
                    // Demo code expects either a KM message or a transport encrypted message
                    // of the reporting type.
                    match read_result {
                        Ok(input_len) => {
                            info!("zdp/client - read {} bytes", input_len);

                            let zpi_hdr = ZdpZpiHeader::ref_from_prefix(&buf[0..input_len]);
                            if zpi_hdr.is_none() {
                                info!("zdp/server - error parsing ZPI header");
                                continue;
                            }
                            let zpi_hdr = zpi_hdr.unwrap();
                            match zpi_hdr.zpi {
                                0 => {
                                    let zdp_hdr = ZdpBaseHeader::ref_from_prefix(&buf[ZDP_BASE_HEADER_OFFSET..]);
                                    if zdp_hdr.is_none() {
                                        info!("zdp/server - error parsing ZDP header from ZPI=0 message");
                                        continue;
                                    }
                                    let zdp_hdr = zdp_hdr.unwrap();
                                    if zdp_hdr.packet_type != ZdpPacketType::KeyManagement {
                                        info!("zdp/server - expected KM packet, got {:?}", zdp_hdr.packet_type);
                                        continue;
                                    }
                                    let km_hdr = ZdpKeyManagementHeader::ref_from_prefix(&buf[ZDP_KM_HDR_OFFSET..]);
                                    if km_hdr.is_none() {
                                        info!("zdp/server - error parsing KM header from ZPI=0 message");
                                        continue;
                                    }
                                    let km_hdr = km_hdr.unwrap();
                                    if !km_hdr.is_noise() {
                                        info!("zdp/server - expected NOISE KM message, got {:?}", km_hdr.message_type.get());
                                        continue;
                                    }
                                    let km_msg_len = usize::from(km_hdr.message_length);
                                    if input_len < ZDP_KM_DATA_OFFSET + km_msg_len {
                                        info!("zdp/server - KM message truncated: expected {} got {}", ZDP_KM_DATA_OFFSET + km_msg_len, input_len);
                                        continue;
                                    }
                                    match mgr.handle_km_message(&buf[ZDP_KM_DATA_OFFSET..ZDP_KM_DATA_OFFSET+km_msg_len]).await {
                                        Ok(()) => {},
                                        Err(e) => {
                                            info!("zdp/client - handle_km_message failed: {}", e);
                                        }
                                    }
                                }
                                _ => {
                                    info!("zdp/client - received transport message");
                                    let mut pkt_buf = [0u8; config::PACKET_BUFFER_SIZE];
                                    let mut pkt = Packet::new(&mut pkt_buf, HEADROOM);
                                    pkt.put(&buf[0..input_len]);
                                    match mgr.decrypt_transport(&mut pkt) {
                                        Ok(()) => {
                                            // Demo code sends a ZDP message like
                                            //     [ZPI]
                                            //     [BASE HEADER type = report]
                                            //     [REPORT HEADER]
                                            //     <STRING DATA>
                                            let zpi_hdr = ZdpZpiHeader::ref_from_prefix(&pkt.body());
                                            if zpi_hdr.is_none() {
                                                info!("zdp/server - error parsing ZPI header from decrypted payload");
                                                continue;
                                            }
                                            let zdp_hdr = ZdpBaseHeader::ref_from_prefix(&pkt.body()[ZDP_BASE_HEADER_OFFSET..]);
                                            if zdp_hdr.is_none() {
                                                info!("zdp/server - error parsing ZDP header from decrypted payload");
                                                continue;
                                            }
                                            let zdp_hdr = zdp_hdr.unwrap();
                                            if zdp_hdr.packet_type != ZdpPacketType::Report {
                                                info!("zdp/server - expected REPORT packet, got {:?}", zdp_hdr.packet_type);
                                                continue;
                                            }
                                            let report_hdr = ZdpReportHeader::ref_from_prefix(&pkt.body()[ZDP_REPORT_HDR_OFFSET..]);
                                            if report_hdr.is_none() {
                                                info!("zdp/server - error parsing REPORT header from decrypted payload");
                                                continue;
                                            }
                                            let report_hdr = report_hdr.unwrap();
                                            let strlen = usize::from(report_hdr.report_data_length);
                                            if ZDP_REPORT_DATA_OFFSET + strlen > pkt.body().len() {
                                                info!("zdp/server - report data length exceeds packet length");
                                                continue;
                                            }
                                            match std::str::from_utf8(&pkt.body()[ZDP_REPORT_DATA_OFFSET..ZDP_REPORT_DATA_OFFSET+strlen]) {
                                                Ok(s) => {
                                                    info!("zdp/server - received report: *** {} ***", s);
                                                }
                                                Err(e) => {
                                                    info!("zdp/server - error parsing report data: {:?}", e);
                                                }
                                            };
                                        }

                                        Err(e) => {
                                            info!("zdp/client - decrypt_transport failed: {}", e);
                                        }
                                    }
                                }
                            };
                        }
                        Err(e) => {
                            info!("zdp/client - read failed: {}", e);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}


