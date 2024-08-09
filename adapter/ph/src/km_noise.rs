use std::time::Duration;
use bytes::{BufMut, Bytes, BytesMut};
use tracing::{error, info};
use crate::km::*;


static PATTERN: &'static str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";


/// Not multi-thread safe.
/// TODO: Figure out how to make encryption/decryption parallelizable.
pub struct KMNoise {
    settings: KMSettings,
    state: KMSMState,
    initiate: bool,
    peer_pub_key: Vec<u8>,
    local_keypair: snow::Keypair,
    hs_state: Option<snow::HandshakeState>,
    t_state: Option<snow::TransportState>,
}

impl KMNoise {
    // TODO: pass in the local RSA cert which we will send over in handshake, or response.
    pub fn new(initiate: bool, peer_pub_key: &[u8], local_keypair: Option<snow::Keypair>) -> Result<Self, snow::error::Error> {
        let settings = KMSettings {
            zdp_km_type: 2,
            padlen: 16 + 8, // 16 byte tag plus 8 byte nonce
            alignment: 0, // probably should be set to something...
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
            peer_pub_key: peer_pub_key.to_vec(),
            local_keypair: kp,
            hs_state: None,
            t_state: None,
        })
    }
}


// 
// ENCRYPTION
//
//    payload = [plaintext to be encrypted]
//
//    message = [ciphertext including tag | nonce (8 bytes)]
//


impl KeyManagerStateMachine for KMNoise {

    fn get_settings(&self) -> KMSettings {
        return self.settings.clone();
    }

    fn get_state(&self) -> KMSMState {
        self.state.clone()
    }

    // TODO: Remove `initiate` from the reset function. Leave up to statemachine ctor.
    fn reset(&mut self, _initiate: bool) -> Result<Option<Bytes>, KMError> {
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
            let mut initiator = match snow::Builder::new(np)
                .local_private_key(self.local_keypair.private.as_ref())
                .remote_public_key(self.peer_pub_key.as_ref())
                .build_initiator() {
                Ok(i) => i,
                Err(e) => {
                    error!("noise: error building initiator: {:?}", e);
                    self.state = KMSMState::Error;
                    return Err(KMError::ConfigurationError);
                }
            };

            let mut buf = BytesMut::with_capacity(1024);
            let _len = match initiator.write_message(&b"todo:cert here"[..], &mut buf) {
                Ok(l) => l,
                Err(e) => {
                    error!("noise: error writing handshake message: {:?}", e);
                    self.state = KMSMState::Error;
                    return Err(KMError::HandshakeError);
                }
            };

            self.hs_state = Some(initiator);
            Ok(Some(buf.freeze()))
        } else {
            let responder = match snow::Builder::new(np)
                .local_private_key(self.local_keypair.private.as_ref())
                .build_responder() {
                Ok(r) => r,
                Err(e) => {
                    error!("noise: error building responder: {:?}", e);
                    self.state = KMSMState::Error;
                    return Err(KMError::ConfigurationError);
                }
            };
            self.hs_state = Some(responder);
            Ok(None)
        }
    }

    // TODO: Need ability to return error
    fn handle_message(&mut self, message: &[u8]) -> Result<Option<Bytes>, KMError> {
        if self.state == KMSMState::Configuring {

            let mut hs: snow::HandshakeState;
            if self.hs_state.is_some() {
                hs = self.hs_state.take().unwrap();
                let mut buf = BytesMut::with_capacity(1024);
                match hs.read_message(&message[..], &mut buf) {
                    Ok(len) => {
                        // TODO: In future we plan to send the certificate over in the first handshake message buffer.
                        info!("noise: got {} byte payload in handshake message, ignoring", len);
                    }
                    Err(e) => {
                        error!("noise: error handling handhsake message: {:?}", e);
                        self.state = KMSMState::Error;                        
                        self.hs_state = Some(hs);
                        return Err(KMError::HandshakeError);
                    }
                };

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
                    };
                }

                // Else, we have more handshaking to do:
                let mut buf = BytesMut::with_capacity(1024);
                match hs.write_message(&[], &mut buf) {
                    Ok(_) => {
                        self.hs_state = Some(hs);                        
                        return Ok(Some(buf.freeze()));
                    }
                    Err(e) => {
                        error!("noise: error writing handshake message: {:?}", e);
                        self.hs_state = Some(hs);                                                
                        self.state = KMSMState::Error;
                        return Err(KMError::HandshakeError);
                    }
                }
            }
        }
        Ok(None)
    }

    fn tick(&mut self) -> Result<Option<Bytes>, KMError> {
        // TODO: There is more to do here:
        //  - check for timeout and restart handshake if necessary
        //  - check if we may have more handshake messages to send
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
                // message.put_u64(nonce); // presumably this writes at the end...
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
        if message.len() < 8 {
            error!("noise: message too short");
            return Err(KMError::EncryptionError);
        }
        let nonce: u64 = u64::from_be_bytes(message[message.len() - 8..].try_into().unwrap());

        ts.set_receiving_nonce(nonce);
        match ts.read_message(payload, &mut message[..message.len() - 8]) {
            Ok(len) => Ok(len),
            Err(e) => {
                error!("noise: error decrypting message: {:?}", e);
                Err(KMError::EncryptionError)
            }
        }
    }

    

}


