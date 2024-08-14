use std::io;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use tokio::sync::mpsc;

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use ph::config;
use ph::km::{KMSignal, KeyManager};
use ph::km_demo;
use ph::km_noise::KMNoise;
use ph::packet::Packet;
use ph::zdp::*;

use bytes::BufMut;
use zerocopy::FromBytes;

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
        let noise = match KMNoise::new(true, Some(self.dock_noise_pub_key.into()), None) {
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
                                let mut pkt_buf = [0u8; config::PACKET_BUFFER_SIZE];
                                let mut pkt = km_demo::build_zdp_report_packet(&mut pkt_buf, b"hello to you my dear node!");
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
                    let pkt = km_demo::build_zdp_km_noise_packet(&mut pkt_buf, &km_buf);
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
                                    info!("zdp/client - received ZPI=0 message");
                                    let km_payload = match km_demo::parse_km_payload(&buf) {
                                        Ok(p) => p,
                                        Err(e) => {
                                            info!("zdp/client - parse_km_payload failed: {}", e);
                                            continue;
                                        }
                                    };
                                    match mgr.handle_km_message(km_payload).await {
                                        Ok(()) => {},
                                        Err(e) => {
                                            info!("zdp/client - handle_km_message failed: {}", e);
                                        }
                                    }
                                }
                                _ => {
                                    info!("zdp/client - received transport message");
                                    let mut pkt_buf = [0u8; config::PACKET_BUFFER_SIZE];
                                    let mut pkt = Packet::new(&mut pkt_buf, km_demo::HEADROOM);
                                    pkt.put(&buf[0..input_len]);
                                    match mgr.decrypt_transport(&mut pkt) {
                                        Ok(()) => {
                                            // Demo code sends a ZDP message like
                                            //     [ZPI]
                                            //     [BASE HEADER type = report]
                                            //     [REPORT HEADER]
                                            //     <STRING DATA>
                                            match km_demo::parse_zdp_report_pkt(&pkt) {
                                                Ok(s) => {
                                                    info!("zdp/client - received report: *** {} ***", s);
                                                }
                                                Err(e) => {
                                                    info!("zdp/client - error parsing report: {}", e);
                                                }
                                            }
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
