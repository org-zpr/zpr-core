//! Demonstration implementation of a [KeyManagerStateMachine] which does an unchecked
//! "key exchange" and then uses XOR for encryption with a hard coded key.

use crate::km::*;
use crate::zpr;
use bytes::Bytes;
use std::time;
use std::time::Duration;
use std::sync::Arc;

pub struct XorKeyManager {
    state: KMSMState,
    settings: KMSettings,
    hello_t: time::Instant,
    initiate: bool,
}

impl XorKeyManager {
    pub fn new(initiate: bool) -> XorKeyManager {
        XorKeyManager {
            state: KMSMState::Configuring,
            settings: KMSettings {
                zdp_km_type: zpr::KM_ID_EXPERIMENTAL,
                padlen: 2, // we need 2 extra bytes
                alignment: 0,
                tick_interval: Duration::from_millis(1000),
            },
            hello_t: time::Instant::now(),
            initiate,
        }
    }
}

struct XorCodec;

impl Codec for XorCodec {
    // Write payload "encrypted" into `message`.
    // Adds a 2 byte SIZE field at the front of the message.
    fn encrypt_transport_stateless(
        self: &Self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, KMError> {
        let sz = payload.len() + 2; // SIZE includes the 2 byte size field.
        if sz > u16::MAX as usize {
            return Err(KMError::EncryptionError);
        }
        let szbytes = (sz as u16).to_be_bytes();
        message[0..2].copy_from_slice(&szbytes); // write SIZE as u16 to front of buffer

        // Secret encrypto function:
        for i in 0..payload.len() {
            message[i + 2] = payload[i] ^ 0x7a;
        }
        Ok(sz)
    }

    // "Decrypt" the payload, write cleartext to `message`.
    fn decrypt_transport_stateless(
        self: &Self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, KMError> {
        let buf_sz = payload.len();
        if buf_sz < 2 {
            return Err(KMError::EncryptionError);
        }
        let msg_sz: u16 = u16::from_be_bytes([payload[0], payload[1]]);
        if buf_sz < msg_sz as usize {
            return Err(KMError::EncryptionError);
        }
        if msg_sz < 2 {
            return Err(KMError::EncryptionError);
        }
        let msg_len: usize = (msg_sz - 2) as usize;

        // Secret decrypto function:
        for i in 0..msg_len {
            message[i] = payload[i + 2] ^ 0x7a;
        }
        Ok(msg_len)
    }
}

impl KeyManagerStateMachine for XorKeyManager {
    fn get_settings(&self) -> KMSettings {
        self.settings.clone()
    }

    fn get_state(&self) -> KMSMState {
        self.state.clone()
    }

    fn reset(&mut self) -> Result<Option<Bytes>, KMError> {
        self.state = KMSMState::Configuring;
        if self.initiate {
            let handshake = Bytes::from_static(&[0, 255, 0, 12, 1, 2, 3, 4, 5, 6, 7, 8]); // TYPE | LEN | PAYLOAD
            self.hello_t = time::Instant::now();
            Ok(Some(handshake))
        } else {
            Ok(None)
        }
    }

    fn handle_message(&mut self, _message: &[u8]) -> Result<Option<Bytes>, KMError> {
        if self.state == KMSMState::Configuring {
            let codec = Arc::new(XorCodec{});
            self.state = KMSMState::Transport(KMTransportState::new_empty_with_codec(codec));
            if !self.initiate {
                // Did not initiate, so send a reply back.
                let handshake_reply = Bytes::from_static(&[0, 255, 0, 12, 8, 7, 6, 5, 4, 3, 2, 1]); // TYPE | LEN | PAYLOAD
                return Ok(Some(handshake_reply));
            }
        }
        Ok(None)
    }

    fn tick(&mut self) -> Result<Option<Bytes>, KMError> {
        if self.state == KMSMState::Configuring && self.initiate && self.hello_t.elapsed() > Duration::from_secs(5) {
            // too long, send another hello.
            let handshake = Bytes::from_static(&[0, 255, 0, 12, 1, 2, 3, 4, 5, 6, 7, 8]); // TYPE | LEN | PAYLOAD
            self.hello_t = time::Instant::now();
            return Ok(Some(handshake));
        }
        Ok(None)
    }

}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let mut buf = [0u8; 64];
        let payload = Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let codec = XorCodec{};
        let sz = codec.encrypt_transport_stateless(&payload, &mut buf).unwrap();
        assert_eq!(sz, 12);
        let mut decbuf = [0u8; 64];
        let decsz = codec.decrypt_transport_stateless(&buf[0..sz], &mut decbuf).unwrap();
        assert_eq!(decsz, 10);
        assert_eq!(&decbuf[0..decsz], &payload[..]);
    }
}
