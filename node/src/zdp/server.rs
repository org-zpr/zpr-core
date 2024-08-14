use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio::time;

use tracing::info;

use bytes::BufMut;

use ph::km::{KeyManager, KMSignal};
use ph::km_xor::XorKeyManager;
use ph::{config, zdp::*};
use ph::packet::Packet;

use zerocopy::FromBytes;


const HEADROOM: usize = 128;

const ZDP_BASE_HDR_OFFSET: usize = std::mem::size_of::<ZdpZpiHeader>();
const ZDP_REPORT_HDR_OFFSET: usize = ZDP_BASE_HDR_OFFSET + std::mem::size_of::<ZdpBaseHeader>();
const ZDP_REPORT_DATA_OFFSET: usize = ZDP_REPORT_HDR_OFFSET + std::mem::size_of::<ZdpReportHeader>();

#[derive(Debug, Clone)]
pub struct ZDPServer {
    addr: SocketAddr, // listen address, "host:port"
}

// Placeholder or demonstration code for a dock server component on a node.
// Here to help with testing the KM code.
impl ZDPServer {
    pub fn new(addr: &SocketAddr) -> ZDPServer {
        ZDPServer {
            addr: addr.to_owned(),
        }
    }

    pub async fn run(&self, ctok: CancellationToken) -> io::Result<()> {
        let socket = UdpSocket::bind(self.addr).await?;
        info!("ZDP server listening on {}", self.addr);
        let s_recv = Arc::new(socket);
        let s_send = s_recv.clone();

        let (km_tx, mut km_rx) = mpsc::channel(16);
        let (km_sig_tx, mut km_sig_rx) = mpsc::channel(16);

        let km_ctok = ctok.clone();

        // In real implemntation each client gets a KM instance.
        let mgr = KeyManager::new(Box::new(XorKeyManager::new(false)));
        let mut mgr_cc = mgr.clone();
        tokio::spawn(async move {
            mgr_cc.start(km_ctok, km_tx, km_sig_tx).await.unwrap();
        });

        // This dummy node only allows for one connection at a time.
        // We wait to recv some bytes.  We get an (unverified) source address.
        // Then we attempt to set up an SA using our key management system.
        let mut cur_client: Option<SocketAddr> = None;

        let mut interval = time::interval(Duration::from_secs(1));

        let mut sent_report = false;
        let mut transition_time: Option<time::Instant> = None;



        let mut input_buf = [0u8; config::PACKET_BUFFER_SIZE];

        loop {
            tokio::select! {
                _ = ctok.cancelled() => {
                    info!("ZDP Server cancelled");
                    break;
                }

                _ = interval.tick() => {
                    if let Some(tt) = transition_time {
                        if !sent_report && tt.elapsed() > Duration::from_secs(2) {
                            let mut buf = [0u8; config::PACKET_BUFFER_SIZE];
                            let mut pkt = Packet::new(&mut buf, 128);

                            let message = b"hello to you my darling client adapter!";
                            let mlen = message.len() as u16;
                            let report_hdr = pkt.alloc_zeroed_header::<ZdpReportHeader>();
                            report_hdr.report_data_length =  mlen.into();

                            let zdp_hdr = pkt.alloc_zeroed_header::<ZdpBaseHeader>();
                            zdp_hdr.packet_type = ZdpPacketType::Report;
                            zdp_hdr.excess_length =  0;
                            zdp_hdr.sequence_number = 0.into();

                            // Do not add ZPI here - SA_ID is added by KM.

                            pkt.put(&message[..]);
                            match mgr.encrypt_transport(&mut pkt) {
                                Ok(_) => {
                                    match s_send.send_to(&pkt.body(), cur_client.unwrap()).await {
                                        Ok(sz) => {
                                            info!("zdp/server - sent {} byte transport message", sz);
                                            sent_report = true;
                                        },
                                        Err(e) => {
                                            info!("zdp/server - error sending transport message: {:?}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    info!("zdp/server - error encrypting transport message: {:?}", e);
                                }
                            }
                        }
                    }
                }

                Some(sig) = km_sig_rx.recv() => {
                    // This is a signal from the KM.  We need to act on it.
                    match sig {
                        KMSignal::SaIdChange { old, new } => {
                            if old == 0 && new > 0 {
                                info!("SA has been established!");
                                // Becuase of the way the messages work, the node will transition into
                                // transport after recieving the handshake, but the adapter will not
                                // transition until it gets my response.  We may want an ACK message
                                // or something with these KM exchanges.
                                //
                                // For now I just use a timer to give adapter some time to react.
                                sent_report = false;
                                transition_time = Some(time::Instant::now());
                            }
                        }
                        _ => {}
                    }
                }

                Some(km_buf) = km_rx.recv() => {
                    // This is a raw KM message to send to this client (NOTE: the KM needs to be associated with the correct client!)
                    // Needs a ZDP header -- unless we are sending 'bare' KM messages.
                    if cur_client.is_none() {
                        info!("error: KM generated a message but we have no client to send to");
                        continue;
                    }
                    match s_send.send_to(&km_buf, cur_client.unwrap()).await {
                        Ok(sz) => {
                            info!("zdp/client - sent {} byte KM message", sz);
                        },
                        Err(e) => {
                            info!("zdp/server - error sending KM message: {:?}", e);
                        }
                    }
                }

                Ok((read_len, src)) = s_recv.recv_from(&mut input_buf) => {
                    info!("Received {} bytes from {}", read_len, src);
                    if cur_client.is_none() {
                        cur_client = Some(src);
                    } else if cur_client != Some(src) {
                        info!("Ignoring message from unknown source");
                        continue;
                    }

                    let zpi_hdr = ZdpZpiHeader::ref_from_prefix(&input_buf[0..read_len]);
                    if zpi_hdr.is_none() {
                        info!("zdp/server - error parsing ZPI header");
                        continue;
                    }
    ;                let zpi_hdr = zpi_hdr.unwrap();

                    // For this demo code all the UDP messages look like
                    //
                    //   [ZPI][PAYLOAD]
                    //
                    // If ZPI is 0 then it's a KM message. Else it's transport.
                    match zpi_hdr.zpi {
                        0 => {
                            info!("zdp/server - received KM message");
                            match mgr.handle_km_message(&input_buf[0..read_len]).await {
                                Ok(_) => {},
                                Err(e) => {
                                    info!("zdp/server - error handling KM message: {:?}", e);
                                    // TODO: Drop client? Reset KM?
                                }
                            };
                        }
                        _ => {
                            info!("zdp/server - received transport message");
                            // Not sure the correct way to use these packet things.  But here we just create yet another buffer.
                            let mut pkt_buf = [0u8; config::PACKET_BUFFER_SIZE];
                            let mut pkt = Packet::new(&mut pkt_buf, HEADROOM);
                            pkt.put(&input_buf[..read_len]);
                            match mgr.decrypt_transport(&mut pkt) {
                                Ok(_) => {
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
                                    let zdp_hdr = ZdpBaseHeader::ref_from_prefix(&pkt.body()[ZDP_BASE_HDR_OFFSET..]);
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
                                    info!("zdp/server - error decrypting transport message: {:?}", e);
                                }
                            }
                        }
                    };
                }
            }
        }

        Ok(())
    }
}

