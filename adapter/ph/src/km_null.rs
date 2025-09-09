//! KeyManager NULL implementation, used for debugging purposes
//! to see the contents of packets while traversing ZPR

use crate::km::*;
use bytes::Bytes;
use std::sync::Arc;
use std::time;
use std::time::Duration;

pub struct NullKeyManager {
    state: KmSMState,
    settings: KmSettings,
    hello_t: time::Instant,
    initiate: bool,
}

impl NullKeyManager {
    pub fn new(initiate: bool) -> NullKeyManager {
        NullKeyManager {
            state: KmSMState::Configuring,
            settings: KmSettings {
                zdp_km_type: zpr::KM_ID_NULL,
                padlen: 0,
                alignment: 0,
                tick_interval: Duration::from_millis(1000),
            },
            hello_t: time::Instant::now(),
            initiate,
        }
    }
}

struct NullCodec;

impl Codec for NullCodec {
    fn encrypt_transport_stateless(
        self: &Self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, EncryptionError> {
        for i in 0..payload.len() {
            message[i] = payload[i];
        }
        Ok(payload.len())
    }

    fn decrypt_transport_stateless(
        self: &Self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, DecryptionError> {
        for i in 0..payload.len() {
            message[i] = payload[i];
        }
        Ok(message.len())
    }
}

impl KeyManagerStateMachine for NullKeyManager {
    fn get_settings(&self) -> KmSettings {
        self.settings.clone()
    }

    fn get_state(&self) -> KmSMState {
        self.state.clone()
    }

    fn reset(&mut self) -> Result<Option<Bytes>, KmError> {
        self.state = KmSMState::Configuring;
        if self.initiate {
            let handshake = Bytes::from_static(&[0, 255, 0, 12, 1, 2, 3, 4, 5, 6, 7, 8]); // TYPE | LEN | PAYLOAD
            self.hello_t = time::Instant::now();
            Ok(Some(handshake))
        } else {
            Ok(None)
        }
    }

    fn handle_message(&mut self, _message: &[u8]) -> Result<Option<Bytes>, KmError> {
        if self.state == KmSMState::Configuring {
            let codec = Arc::new(NullCodec {});
            self.state = KmSMState::Transport(KmTransportSA::new_with_codec(codec));
            if !self.initiate {
                // Did not initiate, so send a reply back.
                let handshake_reply = Bytes::from_static(&[0, 255, 0, 12, 8, 7, 6, 5, 4, 3, 2, 1]); // TYPE | LEN | PAYLOAD
                return Ok(Some(handshake_reply));
            }
        }
        Ok(None)
    }

    fn tick(&mut self) -> Result<Option<Bytes>, KmError> {
        if self.state == KmSMState::Configuring
            && self.initiate
            && self.hello_t.elapsed() > Duration::from_secs(5)
        {
            // too long, send another hello.
            let handshake = Bytes::from_static(&[0, 255, 0, 12, 1, 2, 3, 4, 5, 6, 7, 8]); // TYPE | LEN | PAYLOAD
            self.hello_t = time::Instant::now();
            return Ok(Some(handshake));
        }
        Ok(None)
    }
}
