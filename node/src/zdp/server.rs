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
use ph::km_noise::KMNoise;
use ph::config;
use ph::zdp::*;
use ph::packet::Packet;
use ph::zpr;

use zerocopy::FromBytes;

use snow;
use curve25519_dalek::montgomery::MontgomeryPoint;



const HEADROOM: usize = 128;

const ZDP_KM_HDR_OFFSET: usize = ZDP_NON_PER_FLOW_MGMT_HEADER_OFFSET;
const ZDP_KM_DATA_OFFSET: usize = ZDP_KM_HDR_OFFSET + std::mem::size_of::<ZdpKeyManagementHeader>();

const ZDP_REPORT_HDR_OFFSET: usize = ZDP_NON_PER_FLOW_MGMT_HEADER_OFFSET;
const ZDP_REPORT_DATA_OFFSET: usize = ZDP_REPORT_HDR_OFFSET + std::mem::size_of::<ZdpReportHeader>();


pub struct ZDPServer {
    addr: SocketAddr, // listen address, "host:port"
    noise_kp: snow::Keypair,
}

// Get public key from private key.
fn derive_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let point = MontgomeryPoint::mul_base_clamped(*private_key);
    point.to_bytes()
}

// Placeholder or demonstration code for a dock server component on a node.
// Here to help with testing the KM code.
impl ZDPServer {

    // Uses the NOISE KM so we need the private key here. A future implementation
    // could maybe just pass in a KeyManagerStateMachine implentation.
    pub fn new(addr: &SocketAddr, noise_private_key: &[u8; 32]) -> ZDPServer {
        let pubkey = derive_public_key(noise_private_key);
        let kp = snow::Keypair {
            private: noise_private_key.to_vec(),
            public: pubkey.to_vec()
        };
        ZDPServer {
            addr: addr.to_owned(),
            noise_kp: kp,
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

        let kp = snow::Keypair {
            private: self.noise_kp.private.clone(),
            public: self.noise_kp.public.clone(),
        };
        let noise = match KMNoise::new(false, None, Some(kp)) {
            Ok(n) => n,
            Err(e) => {
                info!("error creating noise km: {:?}", e);
                return Err(io::Error::new(io::ErrorKind::Other, "error creating noise"));
            }
        };

        // In real implemntation each client gets a KM instance.
        let mgr = KeyManager::new(Box::new(noise));
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
                    if cur_client.is_none() {
                        info!("error: KM generated a message but we have no client to send to");
                        continue;
                    }

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

                    match s_send.send_to(pkt.body(), cur_client.unwrap()).await {
                        Ok(sz) => {
                            info!("zdp/server - sent {} byte KM message", sz);
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

                    // If ZPI is 0 then it may be a KM message. Else it's transport.
                    match zpi_hdr.zpi {
                        0 => {
                            info!("zdp/server - received ZPI=0 message");

                            let zdp_hdr = ZdpBaseHeader::ref_from_prefix(&input_buf[ZDP_BASE_HEADER_OFFSET..]);
                            if zdp_hdr.is_none() {
                                info!("zdp/server - error parsing ZDP header from ZPI=0 message");
                                continue;
                            }
                            let zdp_hdr = zdp_hdr.unwrap();
                            if zdp_hdr.packet_type != ZdpPacketType::KeyManagement {
                                info!("zdp/server - expected KM packet, got {:?}", zdp_hdr.packet_type);
                                continue;
                            }
                            let km_hdr = ZdpKeyManagementHeader::ref_from_prefix(&input_buf[ZDP_KM_HDR_OFFSET..]);
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
                            if read_len < ZDP_KM_DATA_OFFSET + km_msg_len {
                                info!("zdp/server - KM message truncated: expected {} got {}", ZDP_KM_DATA_OFFSET + km_msg_len, read_len);
                                continue;
                            }
                            match mgr.handle_km_message(&input_buf[ZDP_KM_DATA_OFFSET..ZDP_KM_DATA_OFFSET+km_msg_len]).await {
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
