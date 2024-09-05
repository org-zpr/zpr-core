use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time;
use tokio_util::sync::CancellationToken;

use tracing::info;

use bytes::BufMut;

use ph::config;
use ph::km;
use ph::km::{KmSignal, KeyManager};
use ph::km_noise::KmNoise;
use ph::packet::Packet;
use ph::zdp::*;

use ph::km_demo;

use zerocopy::FromBytes;

use curve25519_dalek::montgomery::MontgomeryPoint;
use snow;

const ZPI_FULL_ENC:u8 = 100;
const ZPI_TRANSIT_HMAC:u8 = 101;

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
            public: pubkey.to_vec(),
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
        let noise = match KmNoise::new(false, None, Some(kp), ZPI_FULL_ENC, ZPI_TRANSIT_HMAC) {
            Ok(n) => n,
            Err(e) => {
                info!("error creating noise km: {:?}", e);
                return Err(io::Error::new(io::ErrorKind::Other, "error creating noise"));
            }
        };

        // In real implemntation each client gets a KM instance.
        let mgr = KeyManager::new(1, Box::new(noise));
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
                                    let mut pkt =km_demo::build_zdp_report_packet(&mut buf, b"hello to you my darling client adapter!");
                                    let my_sa = mgr.get_transport_state().unwrap();
                                    pkt.body_mut()[0] = my_sa.send_zpis.encr;
                                    match km::encrypt_transport_zdp(&mut pkt, my_sa.codec.clone()) {
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

                        Some(linkmsg) = km_sig_rx.recv() => {
                            // This is a signal from the KM.  We need to act on it.
                            match linkmsg.msg {
                                KmSignal::SaIdChange { old, new } => {
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

                        Some(linkmsg) = km_rx.recv() => {
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
                            let pkt = km_demo::build_zdp_km_noise_packet(&mut pkt_buf, &linkmsg.msg);

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

                                    let km_payload = match km_demo::parse_km_payload(&input_buf[..read_len]) {
                                        Ok(p) => p,
                                        Err(e) => {
                                            info!("zdp/server - error parsing KM payload: {:?}", e);
                                            continue;
                                        }
                                    };
                                    match mgr.handle_km_message(km_payload).await {
                                        Ok(_) => {},
                                        Err(e) => {
                                            info!("zdp/server - error handling KM message: {:?}", e);
                                            // TODO: Drop client? Reset KM?
                                        }
                                    };
                                }
                                _ => {
                                    info!("zdp/server - received transport message");
                                    let my_sa = mgr.get_transport_state().unwrap();
                                    // Not sure the correct way to use these packet things.  But here we just create yet another buffer.
                                    let mut pkt_buf = [0u8; config::PACKET_BUFFER_SIZE];
                                    let mut pkt = Packet::new(&mut pkt_buf, km_demo::HEADROOM);
                                    pkt.put(&input_buf[..read_len]);
                                    let zpi = pkt.body()[0];
                                    if zpi == my_sa.recv_zpis.encr {
                                        info!("zdp/server - ZPI indicates encrypted transport message");
                                    } else if zpi == my_sa.recv_zpis.hmac {
                                        info!("zdp/server - ZPI indicates agent transit transport message, discarding");
                                        continue;
                                    } else {
                                        info!("zdp/server - unexpected ZPI on message {} (expected {:?})", zpi, my_sa.recv_zpis);
                                    }
                                    match km::decrypt_transport_zdp(&mut pkt, my_sa.codec.clone()) {
                                        Ok(_) => {
                                            // Demo code sends a ZDP message like
                                            //     [ZPI]
                                            //     [BASE HEADER type = report]
                                            //     [REPORT HEADER]
                                            //     <STRING DATA>
                                            match km_demo::parse_zdp_report_pkt(&pkt) {
                                                Ok(s) => {
                                                    info!("zdp/server - received report: *** {} ***", s);
                                                }
                                                Err(e) => {
                                                    info!("zdp/server - error parsing ZDP report packet: {}", e);
                                                    continue;
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
