//! KeyManager implementation using Noise protocol.
//!
//! Configured to use the "IK" pattern (see Noise paper).  This is same as what wireguard uses
//! and requires that initiators know the 25519 public key of the responder.  The idea here
//! is that an adapter wanting to connect to a remote node will have access to this key.
//! Maybe through a special DNS record.
//!
//! The key management messages are all handled by the noise protocol.
//!
//! Transport messages are encoded as follows:
//!
//! ```text
//!
//!    |------- n bytes --------|
//!    [ ZDP payload or message ]
//!
//!
//!    |--- 8 bytes ---||-------- n + 16 bytes ----------|
//!    [     nonce     ][ encrypted buffer               ]
//!
//!    So total extra space needed by encryption is 16 + 8 = 24 bytes.
//! ```
//!
//! Note that the encrypt/decrypt functions expect to operate on entire
//! buffer.  Caller is responsible for dealing with cases when only
//! part of the buffer is to be encrypted or decrypted.
//!
//!
//! Note you can create 32 byte noise keys with the `wg` command line tool on recent versions of linux.
//! For example, to generate a private key: `wg genkey`.  Then you can pass that private key
//! into `wg pubkey` to get the public key.  You can also generate keys using `openssl`, eg
//! `openssl genpkey -algorithm x25519` (but this generates 48 byte keys instead of 32, so
//! you will need to do some editing to get the expected size).


use crate::km::*;
use crate::zpr;
use bytes::{Bytes, BytesMut};
use curve25519_dalek::montgomery::MontgomeryPoint;
use std::time::Duration;
use tracing::error;
use openssl::rand::rand_bytes;
use zerocopy::{AsBytes, FromBytes, FromZeroes, Unaligned};


static PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";


const NOISE_NONCE_LEN: usize = 8;
const NOISE_PADLEN: usize = 16 + NOISE_NONCE_LEN; // 16 byte tag + 8 byte nonce


impl From<snow::Error> for KMError {
    fn from(e: snow::Error) -> KMError {
        KMError::MachineError(e.to_string())
    }
}

/// Not multi-thread safe.
/// TODO: Figure out how to make encryption/decryption parallelizable.
pub struct KMNoise {
    settings: KMSettings,
    state: KMSMState,
    initiate: bool,
    peer_pub_key: Option<Vec<u8>>, // required if initiator
    local_keypair: snow::Keypair,
    hs_state: Option<snow::HandshakeState>,
    t_state: Option<snow::TransportState>,
    recv_hmac_key: [u8; 32], // messages sent to us from peer will use this key (we create this)
    send_hmac_key: Option<[u8; 32]>,  // messages sent to peer will use this key (peers creates this)
    recv_zpis: ZPIPair,
    send_zpis: Option<ZPIPair>,
}

#[derive(FromZeroes, FromBytes, AsBytes, Unaligned)]
#[repr(packed)]
struct KeyMsg {
    pub zpi_full_encr: u8,
    pub zpi_transit_hmac: u8,
    pub hmac_key: [u8; 32],
}


impl KMNoise {
    /// Create the Noise KeyManager.
    ///
    /// This requires Noise keys.  Eventually (TODO) we will also pass certificates through here
    /// so that each side can check for certificate authority signautre.
    ///
    /// The ZPI stuff here is definately first pass. Currently there is no way to change the
    /// ZPI values.  The ZPIs passed in here are sent to the peer for use in messages sent to us.
    ///
    /// - `peer_pub_key` is required for initiator, and should match the `local_keypair` of the responder.
    /// - `local_keypair` is optional. If not provided, a new keypair will be generated.
    /// - `zpi_full_encr` is the ZPI peer should use for full encryption messages.
    /// - `zpi_transmit_hmac` is the ZPI peer should use for HMAC encrypted messages.
    pub fn new(
        initiate: bool,
        peer_pub_key: Option<Vec<u8>>,
        local_keypair: Option<snow::Keypair>,
        zpi_full_encr: u8,
        zpi_transmit_hmac: u8,
    ) -> Result<Self, KMError> {
        if initiate && peer_pub_key.is_none() {
            error!("noise: peer public key required for initiator");
            return Err(KMError::ConfigurationError);
        }

        let settings = KMSettings {
            zdp_km_type: zpr::KM_ID_NOISE,
            padlen: NOISE_PADLEN,
            alignment: 0,
            tick_interval: Duration::from_millis(500),
        };

        let kp: snow::Keypair;
        if let Some(kkp) = local_keypair {
            kp = kkp;
        } else {
            kp = snow::Builder::new(PATTERN.parse()?).generate_keypair()?;
        }
        Ok(KMNoise {
            settings,
            state: KMSMState::Configuring,
            initiate,
            peer_pub_key,
            local_keypair: kp,
            hs_state: None,
            t_state: None,
            recv_hmac_key: [0u8; 32], // we generate this and send to peer
            send_hmac_key: None, // we get this during handshake
            recv_zpis: ZPIPair{ encr: zpi_full_encr, hmac: zpi_transmit_hmac },
            send_zpis: None,
        })
    }

    pub fn get_recv_hmac_key(&self) -> [u8; 32] {
        self.recv_hmac_key
    }

    pub fn get_send_hmac_key(&self) -> Option<[u8; 32]> {
        self.send_hmac_key
    }

    /// Returns the ZPIs for sending, order is (ZPI_FULL_ENCRYPT, ZPI_TRANSIT_HMAC)
    pub fn get_send_zpis(&self) -> Option<ZPIPair> {
        self.send_zpis
    }
}

/// Helper function to derive public key from private key.
pub fn derive_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let point = MontgomeryPoint::mul_base_clamped(*private_key);
    point.to_bytes()
}

impl KeyManagerStateMachine for KMNoise {
    fn get_settings(&self) -> KMSettings {
        self.settings.clone()
    }

    fn get_state(&self) -> KMSMState {
        self.state.clone()
    }

    fn reset(&mut self) -> Result<Option<Bytes>, KMError> {
        self.state = KMSMState::Configuring;
        let np: snow::params::NoiseParams = match PATTERN.parse() {
            Ok(p) => p,
            Err(e) => {
                error!("noise: error parsing pattern: {:?}", e);
                self.state = KMSMState::Error;
                return Err(KMError::ConfigurationError);
            }
        };
        rand_bytes(&mut self.recv_hmac_key).unwrap(); // generate an HMAC key
        self.send_hmac_key = None;
        if self.initiate {
            let rpk = self.peer_pub_key.as_ref().unwrap();
            let mut initiator = match snow::Builder::new(np)
                .local_private_key(self.local_keypair.private.as_ref())
                .remote_public_key(rpk)
                .build_initiator()
            {
                Ok(i) => i,
                Err(e) => {
                    error!("noise: error building initiator: {:?}", e);
                    self.state = KMSMState::Error;
                    return Err(KMError::MachineError(format!(
                        "failed to build initiator: {}",
                        e
                    )));
                }
            };

            let mut buf = BytesMut::zeroed(1024);
            let km = KeyMsg {
                zpi_full_encr: self.recv_zpis.encr,
                zpi_transit_hmac: self.recv_zpis.hmac,
                hmac_key: self.recv_hmac_key,
            };
            let len = match initiator.write_message(km.as_bytes(), &mut buf) {
                Ok(l) => l,
                Err(e) => {
                    error!("noise: error writing handshake message: {:?}", e);
                    self.state = KMSMState::Error;
                    return Err(KMError::MachineError(format!(
                        "failed to write handshake message: {}",
                        e
                    )));
                }
            };
            buf.truncate(len);
            self.hs_state = Some(initiator);
            Ok(Some(buf.freeze()))
        } else {
            let responder = match snow::Builder::new(np)
                .local_private_key(self.local_keypair.private.as_ref())
                .build_responder()
            {
                Ok(r) => r,
                Err(e) => {
                    error!("noise: error building responder: {:?}", e);
                    self.state = KMSMState::Error;
                    return Err(KMError::MachineError(format!(
                        "failed to build responder: {}",
                        e
                    )));
                }
            };
            self.hs_state = Some(responder);
            Ok(None)
        }
    }

    fn handle_message(&mut self, message: &[u8]) -> Result<Option<Bytes>, KMError> {
        if self.state == KMSMState::Configuring {
            let mut hs: snow::HandshakeState;
            if self.hs_state.is_none() {
                error!("noise: handle_message called but no handshake state set up");
                return Err(KMError::InvalidState);
            }
            if self.hs_state.is_some() {
                hs = self.hs_state.take().unwrap();
                let mut payload = BytesMut::zeroed(1024);
                // Our IK pattern has two handshake messages. In each we expect to find a KeyMsg in the payload.
                match hs.read_message(&message[..], &mut payload) {
                    Ok(len) => {
                        // TODO: In future we plan to send the certificate over in the first handshake message buffer.
                        if len < std::mem::size_of::<KeyMsg>() {
                            error!("noise: handshake payload is too short: {}", len);
                            self.state = KMSMState::Error;
                            self.hs_state = Some(hs);
                            return Err(KMError::HandshakeError);
                        }
                        let km = match KeyMsg::ref_from_prefix(&payload[..len]) {
                            Some(k) => k,
                            None => {
                                error!("noise: error parsing KeyMsg handshake payload");
                                self.state = KMSMState::Error;
                                self.hs_state = Some(hs);
                                return Err(KMError::HandshakeError);
                            }
                        };
                        self.send_zpis = Some(ZPIPair{ encr: km.zpi_full_encr, hmac: km.zpi_transit_hmac });
                        self.send_hmac_key = Some(km.hmac_key);
                    }
                    Err(e) => {
                        error!("noise: error handling handhsake message: {:?}", e);
                        self.state = KMSMState::Error;
                        self.hs_state = Some(hs);
                        return Err(KMError::HandshakeError);
                    }
                };

                let mut hs_msg: Option<Bytes> = None;

                if !hs.is_handshake_finished() {
                    let payload = KeyMsg {
                        zpi_full_encr: self.recv_zpis.encr,
                        zpi_transit_hmac: self.recv_zpis.hmac,
                        hmac_key: self.recv_hmac_key,
                    };
                    let mut buf = BytesMut::zeroed(1024);
                    match hs.write_message(payload.as_bytes(), &mut buf) {
                        Ok(len) => {
                            buf.truncate(len);
                            hs_msg = Some(buf.freeze());
                        }
                        Err(e) => {
                            error!("noise: error writing handshake message: {:?}", e);
                            self.hs_state = Some(hs);
                            self.state = KMSMState::Error;
                            return Err(KMError::HandshakeError);
                        }
                    }
                }

                if hs.is_handshake_finished() {
                    let send_zpis = match self.send_zpis {
                        Some(z) => z,
                        None => {
                            error!("noise: handshake finished by no ZPIs received");
                            ZPIPair::new_zero()
                        }
                    };
                    let send_key = match self.send_hmac_key {
                        Some(h) => h,
                        None => {
                            error!("noise: XXX handshake finished by no HMAC key received");
                            [0u8; 32]
                        }
                    };
                    match hs.into_transport_mode() {
                        Ok(t) => {
                            self.t_state = Some(t);
                            self.state = KMSMState::Transport(KMTransportState::new(send_zpis, self.recv_zpis, send_key, self.recv_hmac_key));
                        }
                        Err(e) => {
                            error!("noise: error switching to transport mode: {:?}", e);
                            self.state = KMSMState::Error;
                            return Err(KMError::HandshakeError);
                        }
                    };
                }
                return Ok(hs_msg);
            }
        }
        Ok(None)
    }

    fn tick(&mut self) -> Result<Option<Bytes>, KMError> {
        // TODO: Timeout handling
        if self.state == KMSMState::Configuring {
            let hs: snow::HandshakeState;
            if self.hs_state.is_some() {
                hs = self.hs_state.take().unwrap();
                if hs.is_handshake_finished() {
                    let send_zpis = match self.send_zpis {
                        Some(z) => z,
                        None => {
                            error!("noise: handshake finished by no ZPIs received");
                            ZPIPair::new_zero()
                        }
                    };
                    let send_key = match self.send_hmac_key {
                        Some(h) => h,
                        None => {
                            error!("noise: handshake finished by no HMAC key received");
                            [0u8; 32]
                        }
                    };
                    match hs.into_transport_mode() {
                        Ok(t) => {
                            self.t_state = Some(t);
                            self.state = KMSMState::Transport(KMTransportState::new(send_zpis, self.recv_zpis, send_key, self.recv_hmac_key));
                            return Ok(None);
                        }
                        Err(e) => {
                            error!("noise: error switching to transport mode: {:?}", e);
                            self.state = KMSMState::Error;
                            return Err(KMError::HandshakeError);
                        }
                    }
                } else {
                    self.hs_state = Some(hs);
                }
            }
        }
        Ok(None)
    }

    fn encrypt_transport(
        self: &mut Self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, KMError> {
        let ts = match &mut self.t_state {
            Some(t) => t,
            None => {
                error!("noise: encrypt_transport called in wrong state");
                return Err(KMError::InvalidState);
            }
        };
        let nonce = ts.sending_nonce();
        message[..NOISE_NONCE_LEN].copy_from_slice(&nonce.to_be_bytes());
        match ts.write_message(payload, &mut message[NOISE_NONCE_LEN..]) {
            Ok(len) => {
                Ok(len + NOISE_NONCE_LEN)
            }
            Err(e) => {
                error!("noise: error encrypting message: {:?}", e);
                Err(KMError::EncryptionError)
            }
        }
    }

    fn decrypt_transport(
        self: &mut Self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, KMError> {
        let ts = match &mut self.t_state {
            Some(t) => t,
            None => {
                error!("noise: decrypt_transport called in wrong state");
                return Err(KMError::InvalidState);
            }
        };
        // nonce is first 8 bytes in the message.
        let plen = payload.len();
        if plen < NOISE_NONCE_LEN {
            error!("noise: message too short");
            return Err(KMError::EncryptionError);
        }
        let nonce: u64 = u64::from_be_bytes(payload[0..NOISE_NONCE_LEN].try_into().unwrap());

        ts.set_receiving_nonce(nonce);
        match ts.read_message(&payload[NOISE_NONCE_LEN..plen], message) {
            Ok(len) => Ok(len),
            Err(e) => {
                error!("noise: error decrypting message: {:?}", e);
                Err(KMError::EncryptionError)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use base64::prelude::*;
    use tokio::sync::mpsc;
    use tokio::task::yield_now;
    use tokio::time::timeout;
    use tokio_util::sync::CancellationToken;

    use crate::km;

    #[test]
    fn test_noise_handshake_manually() {
        let pat = PATTERN.parse().unwrap();
        let node_kp = match snow::Builder::new(pat).generate_keypair() {
            Ok(k) => k,
            Err(e) => {
                panic!("error generating keypair: {:?}", e);
            }
        };

        let mut initiator = KMNoise::new(true, Some(node_kp.public.to_vec()), None, 1, 2).unwrap();
        assert!(initiator.get_state() == KMSMState::Configuring);

        let mut responder = KMNoise::new(false, None, Some(node_kp), 3, 4).unwrap();
        assert!(responder.get_state() == KMSMState::Configuring);

        let handshake_msg_0 = match initiator.reset() {
            Ok(Some(m)) => m,
            Ok(None) => {
                panic!("expected handshake message");
            }
            Err(e) => {
                panic!("error resetting initiator: {:?}", e);
            }
        };
        assert!(
            handshake_msg_0.len() == 130,
            "unexpected handshake message-0 length, got {}",
            handshake_msg_0.len()
        );
        assert!(initiator.get_state() == KMSMState::Configuring);

        match responder.reset() {
            Ok(Some(_m)) => panic!("unexpected message from responder.reset!"),
            Ok(None) => {} // good
            Err(e) => {
                panic!("error resetting responder: {:?}", e);
            }
        };

        // -> e, es, s, ss
        let handshake_msg_1 = match responder.handle_message(&handshake_msg_0) {
            Ok(Some(m)) => m,
            Ok(None) => {
                panic!("expected handshake-1 message, got nothing!");
            }
            Err(e) => {
                panic!("responder handle_message failed on handshake-0: {:?}", e);
            }
        };
        assert!(
            handshake_msg_1.len() == 82,
            "unexpected handshake message-1 length, got {}",
            handshake_msg_1.len()
        );
        assert!(matches!(responder.get_state(), KMSMState::Transport{..}));

        // <- e, ee, se
        match initiator.handle_message(&handshake_msg_1) {
            Ok(Some(_)) => panic!("unexpected additional handshake message from initiator"),
            Ok(None) => {} // good
            Err(e) => {
                panic!("initiator.handle_message failed on handshake-1: {:?}", e);
            }
        };
        assert!(matches!(initiator.get_state(), KMSMState::Transport{..}));

        // Handshake complete, now we can encrypt/decrypt

        let plaintext = b"hello world";

        let mut out_buf = [0u8; 4096];
        let out_len = match initiator.encrypt_transport(plaintext, &mut out_buf) {
            Ok(l) => l,
            Err(e) => {
                panic!("error encrypting message: {:?}", e);
            }
        };

        let expect_ciphertext_len = plaintext.len() + NOISE_PADLEN;

        assert!(
            out_len == expect_ciphertext_len,
            "unexpected encrypted message length, got {}",
            out_len
        );

        let mut in_buf = [0u8; 4096];
        let in_len = match responder.decrypt_transport(&out_buf[..out_len], &mut in_buf) {
            Ok(l) => l,
            Err(e) => {
                panic!("error decrypting message: {:?}", e);
            }
        };

        assert!(
            in_len == plaintext.len(),
            "unexpected decrypted message length, got {}",
            in_len
        );
        assert!(
            in_buf[..in_len] == plaintext[..],
            "unexpected decrypted message content"
        );
    }

    // Just make sure that our b64 keys work with the code.
    #[test]
    fn test_noise_handshake_manually_static_node_key() {
        let nk_private_b64 = "AB2eP6zV7ve0A4eQgNVNXlAM2q0rYerCPXFMl+/ntUw=";
        let nk_private: [u8; 32] = match BASE64_STANDARD.decode(nk_private_b64) {
            Ok(d) => d.try_into().unwrap(),
            Err(e) => {
                panic!("error decoding base64: {:?}", e);
            }
        };
        let nk_public = derive_public_key(&nk_private);

        let node_kp = snow::Keypair {
            private: nk_private.into(),
            public: nk_public.into(),
        };

        let mut initiator = KMNoise::new(true, Some(node_kp.public.to_vec()), None, 1, 2).unwrap();
        assert!(initiator.get_state() == KMSMState::Configuring);

        let mut responder = KMNoise::new(false, None, Some(node_kp), 3, 4).unwrap();
        assert!(responder.get_state() == KMSMState::Configuring);

        let handshake_msg_0 = match initiator.reset() {
            Ok(Some(m)) => m,
            Ok(None) => {
                panic!("expected handshake message");
            }
            Err(e) => {
                panic!("error resetting initiator: {:?}", e);
            }
        };
        assert!(
            handshake_msg_0.len() == 130,
            "unexpected handshake message-0 length, got {}",
            handshake_msg_0.len()
        );
        assert!(initiator.get_state() == KMSMState::Configuring);

        match responder.reset() {
            Ok(Some(_m)) => panic!("unexpected message from responder.reset!"),
            Ok(None) => {} // good
            Err(e) => {
                panic!("error resetting responder: {:?}", e);
            }
        };

        // -> e, es, s, ss
        let handshake_msg_1 = match responder.handle_message(&handshake_msg_0) {
            Ok(Some(m)) => m,
            Ok(None) => {
                panic!("expected handshake-1 message, got nothing!");
            }
            Err(e) => {
                panic!("responder handle_message failed on handshake-0: {:?}", e);
            }
        };
        assert!(
            handshake_msg_1.len() == 82,
            "unexpected handshake message-1 length, got {}",
            handshake_msg_1.len()
        );
        assert!(matches!(responder.get_state(), KMSMState::Transport{..}));

        // <- e, ee, se
        match initiator.handle_message(&handshake_msg_1) {
            Ok(Some(_)) => panic!("unexpected additional handshake message from initiator"),
            Ok(None) => {} // good
            Err(e) => {
                panic!("initiator.handle_message failed on handshake-1: {:?}", e);
            }
        };
        assert!(matches!(initiator.get_state(), KMSMState::Transport{..}));

        // At this point each side should know the others hmac key, and the ZPIs should have been exchanged.

        assert!(initiator.get_recv_hmac_key() != [0u8; 32]);
        assert!(initiator.get_send_hmac_key().is_some()); // must have been recieved

        assert!(responder.get_recv_hmac_key() != [0u8; 32]);
        assert!(responder.get_send_hmac_key().is_some()); // must have been recieved

        assert!(initiator.get_recv_hmac_key() == responder.get_send_hmac_key().unwrap());
        assert!(responder.get_recv_hmac_key() == initiator.get_send_hmac_key().unwrap());

        assert!(initiator.get_send_zpis().is_some());
        let initiator_zpis = initiator.get_send_zpis().unwrap();
        assert!(initiator_zpis.encr == 3);
        assert!(initiator_zpis.hmac == 4);

        assert!(responder.get_send_zpis().is_some());
        let responder_zpis = responder.get_send_zpis().unwrap();
        assert!(responder_zpis.encr == 1);
        assert!(responder_zpis.hmac == 2);
    }

    #[tokio::test]
    async fn test_noise_handshake_via_km() {
        let pat = PATTERN.parse().unwrap();
        let node_kp = match snow::Builder::new(pat).generate_keypair() {
            Ok(k) => k,
            Err(e) => {
                panic!("error generating keypair: {:?}", e);
            }
        };

        let initiator = KMNoise::new(true, Some(node_kp.public.to_vec()), None, 1, 2).unwrap();
        let responder = KMNoise::new(false, None, Some(node_kp), 3, 4).unwrap();

        let adapter = km::KeyManager::new(Box::new(initiator));
        let node = km::KeyManager::new(Box::new(responder));

        let ctok = CancellationToken::new();

        let (n_km_tx, mut n_km_rx) = mpsc::channel(16);
        let (n_sig_tx, mut n_sig_rx) = mpsc::channel(16);
        let n_ctok = ctok.clone();

        let mut sp_node = node.clone();
        tokio::spawn(async move {
            let _ = sp_node.start(n_ctok, n_km_tx, n_sig_tx).await; // Start the node
        });

        let (a_km_tx, mut a_km_rx) = mpsc::channel(16);
        let (a_sig_tx, mut a_sig_rx) = mpsc::channel(16);
        let a_ctok = ctok.clone();

        let mut sp_adapter = adapter.clone();
        tokio::spawn(async move {
            let _ = sp_adapter.start(a_ctok, a_km_tx, a_sig_tx).await; // Start the adapter
        });

        yield_now().await;

        // Both adapter and node should reset.
        match timeout(Duration::from_secs(2), n_sig_rx.recv()).await {
            Ok(resp) => match resp {
                Some(sig) => {
                    match sig {
                        km::KMSignal::Reset => {} // ok!
                        _ => {
                            panic!("unexpected signal from node: {:?}", sig);
                        }
                    }
                }
                None => {
                    panic!("timed out or failed waiting for node state transition");
                }
            },
            Err(_) => {
                panic!("timed out waiting for node state transition");
            }
        }

        match timeout(Duration::from_secs(2), a_sig_rx.recv()).await {
            Ok(resp) => match resp {
                Some(sig) => {
                    match sig {
                        km::KMSignal::Reset => {} // ok!
                        _ => {
                            panic!("unexpected signal from adapter: {:?}", sig);
                        }
                    }
                }
                None => {
                    panic!("timed out or failed waiting for adapter state transition");
                }
            },
            Err(_) => {
                panic!("timed out waiting for adapter state transition");
            }
        }

        // Adapter, as the initiator will send a KM handshake message.
        match timeout(Duration::from_secs(2), a_km_rx.recv()).await {
            Ok(resp) => match resp {
                Some(msg) => {
                    // Node will process message and then should generate a handshake reply on its output channel.
                    let node_result = node.handle_km_message(&msg).await;
                    assert!(
                        node_result.is_ok(),
                        "node handle of adapter handshake initiation failed: {:?}",
                        node_result
                    );
                }
                None => {
                    panic!("timed out or failed waiting for initial handshake message");
                }
            },
            Err(_) => {
                panic!("timed out waiting for initial handshake message");
            }
        }

        // now I expect a message on the node output channel.
        match timeout(Duration::from_secs(2), n_km_rx.recv()).await {
            Ok(resp) => match resp {
                Some(msg) => {
                    let adapter_result = adapter.handle_km_message(&msg).await;
                    assert!(
                        adapter_result.is_ok(),
                        "adapter handle of node response failed: {:?}",
                        adapter_result
                    );
                }
                None => {
                    panic!("timed out or failed waiting for handshake message response from node");
                }
            },
            Err(_) => {
                panic!("timed out waiting for handshake message from node");
            }
        }

        // And node should have transitioned;
        match timeout(Duration::from_secs(2), n_sig_rx.recv()).await {
            Ok(resp) => match resp {
                Some(sig) => match sig {
                    km::KMSignal::SaIdChange { old, new } => {
                        assert!(new > 0, "new SA_ID is still zero!");
                        assert!(old == 0, "old SA_ID is not zero!");
                    }
                    _ => {
                        panic!("unexpected signal from node: {:?}", sig);
                    }
                },
                None => {
                    panic!("timed out or failed waiting for node state transition");
                }
            },
            Err(_) => {
                panic!("timed out waiting for node state transition");
            }
        }

        // We sent the nodes response to the adapter above, so it should also have transitioned now.
        match timeout(Duration::from_secs(2), a_sig_rx.recv()).await {
            Ok(resp) => match resp {
                Some(sig) => match sig {
                    km::KMSignal::SaIdChange { old, new } => {
                        assert!(new > 0, "new adapter SA_ID is still zero!");
                        assert!(old == 0, "old adapter SA_ID is not zero!");
                    }
                    _ => {
                        panic!("unexpected signal from adapter: {:?}", sig);
                    }
                },
                None => {
                    panic!("timed out or failed waiting for adapter state transition");
                }
            },
            Err(_) => {
                panic!("timed out waiting for adapter state transition");
            }
        }

        // Both should hve same SA-ID
        assert!(
            adapter.get_sa_id() == node.get_sa_id(),
            "SA-ID mismatch: adapter={}, node={}",
            adapter.get_sa_id(),
            node.get_sa_id()
        );

        // ZPIs should be exchanged.
        assert!(ZPIPair::new(3, 4) == adapter.get_send_zpis(), "adapter send ZPIs mismatch: {:?}", adapter.get_send_zpis());
        assert!(ZPIPair::new(1, 2) == adapter.get_recv_zpis());
        assert!(ZPIPair::new(1, 2) == node.get_send_zpis(), "node send ZPIs mismatch: {:?}", node.get_send_zpis());
        assert!(ZPIPair::new(3, 4) == node.get_recv_zpis());

        // HMAC keys created
        assert!(adapter.get_recv_hmac_key() != [0u8; 32]);
        assert!(adapter.get_send_hmac_key() != [0u8; 32]);
        assert!(node.get_recv_hmac_key() != [0u8; 32]);
        assert!(node.get_send_hmac_key() != [0u8; 32]);

        ctok.cancel()
    }
}
