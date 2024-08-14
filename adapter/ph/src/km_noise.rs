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
//!    |-------- n + 16 bytes ----------||--- 8 bytes ---|
//!    [ encrypted buffer               ][     nonce     ]
//!
//!    So total extra space needed by encryption is 16 + 8 = 24 bytes.
//! ```
//!
//! Note that we do not handle padding here. If padding is desireable
//! caller needs to apply padding before calling encrypt.
//!
//! Note that the encrypt/decrypt functions expect to operate on entire
//! buffer.  Caller is responsible for dealing with cases when only
//! part of the buffer is to be encrypted or decrypted.
//!
//!
//! Note you can create noise keys with the `wg` command line tool on recent versions of linux.
//! For example, to generate a private key: `wg genkey`.  Then you can pass that private key
//! into `wg pubkey` to get the public key.

use crate::km::*;
use bytes::{Bytes, BytesMut};
use curve25519_dalek::montgomery::MontgomeryPoint;
use std::time::Duration;
use tracing::{error, info};

static PATTERN: &'static str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

const NOISE_PADLEN: usize = 24; // 16 byte tag + 8 byte nonce

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
}

impl KMNoise {
    /// Create the Noise KeyManager.
    ///
    /// This requires Noise keys.  Eventually (TODO) we will also pass certificates through here
    /// so that each side can check for certificate authority signautre.
    ///
    /// - `peer_pub_key` is required for initiator, and should match the `local_keypair` of the responder.
    /// - `local_keypair` is optional. If not provided, a new keypair will be generated.
    pub fn new(
        initiate: bool,
        peer_pub_key: Option<Vec<u8>>,
        local_keypair: Option<snow::Keypair>,
    ) -> Result<Self, KMError> {
        if initiate && peer_pub_key.is_none() {
            error!("noise: peer public key required for initiator");
            return Err(KMError::ConfigurationError);
        }

        let settings = KMSettings {
            zdp_km_type: 2,
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
        })
    }
}

/// Helper function to derive public key from private key.
pub fn derive_public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let point = MontgomeryPoint::mul_base_clamped(*private_key);
    point.to_bytes()
}

impl KeyManagerStateMachine for KMNoise {
    fn get_settings(&self) -> KMSettings {
        return self.settings.clone();
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
        if self.initiate {
            let rpk = self.peer_pub_key.as_ref().unwrap();
            let mut initiator = match snow::Builder::new(np)
                .local_private_key(self.local_keypair.private.as_ref())
                .remote_public_key(&rpk)
                .build_initiator()
            {
                Ok(i) => i,
                Err(e) => {
                    error!("noise: error building initiator: {:?}", e);
                    self.state = KMSMState::Error;
                    return Err(KMError::MachineError(format!(
                        "failed to build initiator: {}",
                        e.to_string()
                    )));
                }
            };

            let mut buf = BytesMut::zeroed(1024);
            let len = match initiator.write_message(&b"todo:cert here"[..], &mut buf) {
                Ok(l) => l,
                Err(e) => {
                    error!("noise: error writing handshake message: {:?}", e);
                    self.state = KMSMState::Error;
                    return Err(KMError::MachineError(format!(
                        "failed to write handshake message: {}",
                        e.to_string()
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
                        e.to_string()
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
                let mut buf = BytesMut::zeroed(1024);
                match hs.read_message(&message[..], &mut buf) {
                    Ok(len) => {
                        // TODO: In future we plan to send the certificate over in the first handshake message buffer.
                        info!(
                            "noise: got {} byte payload in handshake message, ignoring",
                            len
                        );
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
                    let mut buf = BytesMut::zeroed(1024);
                    match hs.write_message(&[], &mut buf) {
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
                    match hs.into_transport_mode() {
                        Ok(t) => {
                            self.t_state = Some(t);
                            self.state = KMSMState::Transport;
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
                    match hs.into_transport_mode() {
                        Ok(t) => {
                            self.t_state = Some(t);
                            self.state = KMSMState::Transport;
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
        match ts.write_message(payload, message) {
            Ok(len) => {
                message[len..len + 8].copy_from_slice(&nonce.to_be_bytes());
                Ok(len + 8)
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
        // nonce is last 8 bytes in the message.
        let plen = payload.len();
        if plen < 8 {
            error!("noise: message too short");
            return Err(KMError::EncryptionError);
        }
        let nonce: u64 = u64::from_be_bytes(payload[plen - 8..].try_into().unwrap());

        ts.set_receiving_nonce(nonce);
        match ts.read_message(&payload[..plen - 8], message) {
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

        let mut initiator = KMNoise::new(true, Some(node_kp.public.to_vec()), None).unwrap();
        assert!(initiator.get_state() == KMSMState::Configuring);

        let mut responder = KMNoise::new(false, None, Some(node_kp)).unwrap();
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
            handshake_msg_0.len() == 110,
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
            handshake_msg_1.len() == 48,
            "unexpected handshake message-1 length, got {}",
            handshake_msg_1.len()
        );
        assert!(responder.get_state() == KMSMState::Transport);

        // <- e, ee, se
        match initiator.handle_message(&handshake_msg_1) {
            Ok(Some(_)) => panic!("unexpected additional handshake message from initiator"),
            Ok(None) => {} // good
            Err(e) => {
                panic!("initiator.handle_message failed on handshake-1: {:?}", e);
            }
        };
        assert!(initiator.get_state() == KMSMState::Transport);

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

        let mut initiator = KMNoise::new(true, Some(node_kp.public.to_vec()), None).unwrap();
        assert!(initiator.get_state() == KMSMState::Configuring);

        let mut responder = KMNoise::new(false, None, Some(node_kp)).unwrap();
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
            handshake_msg_0.len() == 110,
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
            handshake_msg_1.len() == 48,
            "unexpected handshake message-1 length, got {}",
            handshake_msg_1.len()
        );
        assert!(responder.get_state() == KMSMState::Transport);

        // <- e, ee, se
        match initiator.handle_message(&handshake_msg_1) {
            Ok(Some(_)) => panic!("unexpected additional handshake message from initiator"),
            Ok(None) => {} // good
            Err(e) => {
                panic!("initiator.handle_message failed on handshake-1: {:?}", e);
            }
        };
        assert!(initiator.get_state() == KMSMState::Transport);
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

        let initiator = KMNoise::new(true, Some(node_kp.public.to_vec()), None).unwrap();
        let responder = KMNoise::new(false, None, Some(node_kp)).unwrap();

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

        // Finally, both should hve same SA-ID
        assert!(
            adapter.get_sa_id() == node.get_sa_id(),
            "SA-ID mismatch: adapter={}, node={}",
            adapter.get_sa_id(),
            node.get_sa_id()
        );

        ctok.cancel()
    }
}
