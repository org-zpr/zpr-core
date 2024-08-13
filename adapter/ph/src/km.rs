// km.rs - Key Management for ZDP

//! An API for a Key Management protocol to be used to set up and maintain a
//! security association (SA) with a peer.  In ZPR adapters set up SAs with
//! their docks.  And nodes set up SAs on their links to other nodes.
//!
//! The [KeyManager] is runs a state machine, dispatching to an implementation
//! of a [KeyManagerStateMachine] which does the actual work of creating and
//! parsing key management ZDP messages.

use tokio::sync::mpsc;
use tokio::time;
use tokio_util::sync::CancellationToken;

use std::mem;
use std::time::Duration;

use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};

use bytes::Bytes;

use zerocopy::FromBytes;

use tracing::{error, info};

use crate::config;
use crate::packet::Packet;
use crate::zdp::{ZdpBaseHeader, ZdpPacketType, ZdpPerFlowHeader};
use crate::zpr;

/*
        According to 6.2.8 the key management packets can run in native mode
        when running over a an IP substrate.


         non per-flow management packet

         0    1    ZPI   (for KM this is always set 0)
         1    1    TYPE  (KM = 0x81)    sec. 6.2.8
         2    1    excess len (0)
         3    2    seqnum
         5    x    MANAGEMENT_DATA (km packet)
         x    x    PADDING
         x    x    MAC    (w/ ZPI=0 this is just internet checksum)


         The managemnt data looks like:

         0    2    TYPE       0=none, 1=ikeV2, 2=noise
         2    2    LENGTH     includes type and length
         4    x    KM_PACKET


         ZDP management packets (non-km) are fully encrypted, so we
         can pass full buffer to the transport encrypt/decrypt.

         0    1    ZPI
         1    n    payload (encrypted by KM transport routine)


         ZDP transit packets are more complicated.

         0    1    ZPI
         1    n    ZPR header (encrypted by KM transport routine)
         n+1  m    agent data (d2d-sa + data + micv) -- not encrypted by KM transport

         In order to properly decrypt a transit packet, the KM routine should
         put the encrypted length on the front of the buffer AND protect that with AEAD.
         So something like:

         encr_len = u16::from_be_bytes(payload[0], payload[1]);
         plaintext = decrypt_aead(payload[2..encr_len+2], [ZPI, payload[0], payload[1]]);

         Those two bytes need to be taken into consideration when computing padding.
*/

/// Stateful key manager for ZDP.  Requires an instance of a [KeyManagerStateMachine] to do the actual work.
#[derive(Debug, Clone)]
pub struct KeyManager<'mgr> {
    shared: Arc<KMShared<'mgr>>,
}

#[derive(Debug)]
struct KMShared<'mgr> {
    state: Mutex<KMState<'mgr>>,
}

struct KMState<'mgr> {
    // Warning - have no idea what I'm doing with lifetimes.
    // What I'm trying to assert here is that the impl of KeyManagerStateMachine must live as long as the KeyManager it is passed to.
    statemachine: Box<dyn KeyManagerStateMachine + 'mgr>,
    kmsettings: KMSettings,

    sa_id: zpr::SaId, // current SA identifier

    // TODO: Can we get this channel outside of the mutex?
    mgmt_tx: Option<mpsc::Sender<Bytes>>, // Internal queue for key management messages to be processed.
}

impl fmt::Debug for KMState<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KMState {{ sa_id: {} }}", self.sa_id)
    }
}

/// KeyManager maintains an SA with its peer.
///
/// Note that this is written prior to implementing the actual key management algorithm. So
/// some of the abstractions here may not be quite right -- yet.
impl KeyManager<'_> {
    /// `statemachine` is the key management algorithm.
    pub fn new<'a>(statemachine: Box<dyn KeyManagerStateMachine>) -> KeyManager<'a> {
        let settings = statemachine.get_settings();

        KeyManager {
            shared: Arc::new(KMShared {
                state: Mutex::new(KMState {
                    statemachine,
                    kmsettings: settings,
                    sa_id: 0,
                    mgmt_tx: None,
                }),
            }),
        }
    }

    pub fn get_sa_id(&self) -> u8 {
        let state = self.shared.state.lock().unwrap();
        state.sa_id
    }

    // For testing
    #[allow(dead_code)]
    fn set_sa_id(&self, sa_id: u8) {
        let mut state = self.shared.state.lock().unwrap();
        state.sa_id = sa_id;
    }

    /// Encrypt a ZDP message for transport.  Key Management messages should not be sent here.
    /// This overwrites the plaintext ZDP header at least.
    /// For everything except transit packets, this also overwrites the payload.
    ///
    /// For all packets, there must be enough padding included in the body length to
    /// accomodate any expansion caused by encryption.
    ///
    /// For transit packets the padding space must be between the ZDP header and the
    /// agent data bits.
    ///
    /// `message` is expected to be a ZDP message wihout a ZPI value.  We add a ZPI
    /// value to the front of the message -- note that the value we add is just the
    /// SA_ID.  It's up to caller to mix in the configuration ID value.
    pub fn encrypt_transport(&self, message: &mut Packet) -> io::Result<()> {
        let base_hdr =
            ZdpBaseHeader::ref_from_prefix(message.body()).expect("too-short ZDP message");
        if message.headroom_available() < 1 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "insufficient headroom",
            ));
        }

        let encr: Box<dyn TransportEncr>;
        let sa_id: u8;
        {
            let state = self.shared.state.lock().unwrap();
            if state.statemachine.get_state() != KMSMState::Transport {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "SA not in transport state",
                ));
            }
            if state.sa_id == 0 {
                // programming error
                panic!("SA_ID is zero");
            }
            encr = state.statemachine.get_transport_encryptor();
            sa_id = state.sa_id;
        }

        // The assumption here is that caller has already built in space of any padding required by key manager protocol.
        let encr_len: usize;
        match base_hdr.packet_type {
            ZdpPacketType::KeyManagement => {
                // Programmer error
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Key Management packets should not be sent here",
                ));
            }
            ZdpPacketType::TransitPacket => {
                // So the data to be encrypted is ZDP header plus stream ID.  Padding is still assumed to after that.
                encr_len = mem::size_of::<ZdpBaseHeader>() + mem::size_of::<ZdpPerFlowHeader>();
            }
            _ => {
                encr_len = message.body().len();
            }
        }

        // TODO: Ability to encrypt in place. Not sure how to accomplish. At very least we could use our own buffer pool.
        let mut encr_buf = [0u8; config::PACKET_BUFFER_SIZE];

        // TODO: Pass sa_id into encrypt/decrypt
        match encr.encrypt_transport(sa_id, &message.body()[0..encr_len], &mut encr_buf) {
            Ok(len) => {
                // Copy the encrypted data back into the message -- there should be sufficient room for it since
                // caller should know our required padding space and alignment.
                message.body_mut()[0..len].copy_from_slice(&encr_buf[0..len]);

                // Now we need to push a our SA id onto the front.
                // (Note ZPI should be part of integrity protected data)
                let zpi_buf = message.alloc_zeroed_headroom(1);
                zpi_buf[0] = sa_id;
            }
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("encrypt failed: {}", e),
                ));
            }
        }
        Ok(())
    }

    /// The message here must start with the ZPI value.
    /// We assume that packet ZPI value has been clensed of the config ID and is only the SA_ID.
    /// Key Management packets should not be sent here.
    /// Does not remove the ZPI/SA_ID value.
    pub fn decrypt_transport(&self, message: &mut Packet) -> io::Result<()> {
        if message.body().len() < 1 {
            return Err(io::Error::new(io::ErrorKind::Other, "message too short"));
        }
        let encr: Box<dyn TransportEncr>;
        let sa_id: u8;
        {
            let state = self.shared.state.lock().unwrap();
            if message.body()[0] == 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "ZPI value is 0"));
            }
            if state.sa_id != message.body()[0] {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "SA_ID mismatch: expect {}, found {}",
                        state.sa_id,
                        message.body()[0]
                    ),
                ));
            }
            if state.statemachine.get_state() != KMSMState::Transport {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "SA not in transport state",
                ));
            }
            encr = state.statemachine.get_transport_encryptor();
            sa_id = state.sa_id;
        }

        // TODO: Ability to decrypt in place. Not sure how to accomplish.  At very least we could use our own buffer pool.
        let mut decr_buf = [0u8; config::PACKET_BUFFER_SIZE];

        // TODO: pass sa_id into decrypt
        match encr.decrypt_transport(sa_id, &message.body()[1..], &mut decr_buf) {
            Ok(len) => {
                // Copy the decrypted data back into the message.
                // Note at this point the "padding" space on the message is probably filled with leftover ciphertext.
                message.body_mut()[1..len + 1].copy_from_slice(&decr_buf[0..len]);
            }
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("decrypt failed: {}", e),
                ));
            }
        }
        Ok(())
    }

    /// Pass in a full Key Management payload from our peer here (should not include ZDP header).
    /// This waits until space available in our KM message queue.
    ///
    /// We copy the payload into our own buffer for processing asynchronously. Caller should free buffer.
    pub async fn handle_km_message(&self, message: &[u8]) -> io::Result<()> {
        let tx: mpsc::Sender<Bytes>;
        {
            let state = self.shared.state.lock().unwrap();
            match state.mgmt_tx {
                Some(ref t) => {
                    tx = t.clone();
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "KeyManager not running",
                    ));
                }
            }
        }
        let km_buf = Bytes::copy_from_slice(message);
        match tx.send(km_buf.into()).await {
            Ok(_) => Ok(()),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to enqueue inbound KM message",
            )),
        }
    }

    /// Pass in a full Key Management payload from our peer here (should not include ZDP header).
    /// This will fail if there is no space in queue.
    ///
    /// We copy the payload into our own buffer for processing asynchronously. Caller should free buffer.
    pub fn try_handle_km_message(&self, message: &[u8]) -> io::Result<()> {
        let tx: mpsc::Sender<Bytes>;
        {
            let state = self.shared.state.lock().unwrap();
            match state.mgmt_tx {
                Some(ref t) => {
                    tx = t.clone();
                }
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "KeyManager not running",
                    ));
                }
            }
        }
        let km_buf = Bytes::copy_from_slice(message);
        match tx.try_send(km_buf.into()) {
            Ok(_) => Ok(()),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "failed to enqueue inbound KM message",
            )),
        }
    }


    /// Blocking run loop for the key manager.  This runs the key management algorithm
    /// state machine handing KM messages in and out.
    ///
    /// Use the CancellationToken to stop the run loop.
    ///
    /// `km_buffers_out` will be filled with outbound ZDP Key Management messages for our peer. These are
    /// just the payloads.  The caller is responsible for adding the ZPI header, if required.
    ///
    /// If `initiate` is true, the key manager will initiate a new handshake.  In the adapter-dock
    /// scenario, the adapter should be the initiator and the node should not.
    pub async fn start(
        &mut self,
        initiate: bool,
        ctok: CancellationToken,
        km_buffers_out: mpsc::Sender<Bytes>,
    ) -> io::Result<()> {
        let (km_tx, mut km_rx) = mpsc::channel(16);
        let tick_interval: Duration;
        {
            let mut state = self.shared.state.lock().unwrap();
            state.mgmt_tx = Some(km_tx);
            tick_interval = state.kmsettings.tick_interval;
        }

        let mut interval = time::interval(tick_interval);

        let handshake: Option<Bytes>;
        {
            let mut state = self.shared.state.lock().unwrap();
            handshake = state.statemachine.reset(initiate);
        }
        if let Some(handshake) = handshake {
            match km_buffers_out.send(handshake).await {
                Ok(_) => {}
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        "failed to enqueue outbound KM message",
                    ))
                }
            }
        };

        let mut prev_state: KMSMState;
        let mut next_state: KMSMState;

        loop {
            {
                let state = self.shared.state.lock().unwrap();
                prev_state = state.statemachine.get_state();
            }

            match prev_state {
                KMSMState::Error => {
                    // If error, send reset and loop again
                    let resp: Option<Bytes>;
                    {
                        let mut state = self.shared.state.lock().unwrap();
                        resp = state.statemachine.reset(initiate);
                    }
                    if let Some(resp) = resp {
                        match km_buffers_out.send(resp).await {
                            Ok(_) => {}
                            Err(_) => {
                                error!("failed to enqueue outbound KM message")
                            }
                        }
                    }
                }

                _ => {
                    tokio::select! {
                        _ = ctok.cancelled() => {
                            break;
                        }

                        Some(inmsg) = km_rx.recv() => {
                            let resp: Option<Bytes>;
                            {
                                let mut state = self.shared.state.lock().unwrap();
                                resp = state.statemachine.handle_message(&inmsg);
                            }
                            if let Some(resp) = resp {
                                match km_buffers_out.send(resp).await {
                                    Ok(_) => {},
                                    Err(_) => {
                                        error!("failed to enqueue outbound KM message")
                                    }
                                }
                            }
                        }

                        _ = interval.tick() => {
                            let resp: Option<Bytes>;
                            {
                                let mut state = self.shared.state.lock().unwrap();
                                resp = state.statemachine.tick();
                            }
                            if let Some(resp) = resp {
                                match km_buffers_out.send(resp).await {
                                    Ok(_) => {},
                                    Err(_) => {
                                        error!("failed to enqueue oubound KM message")
                                    }
                                }
                            }
                        }
                    }
                }
            };

            {
                let state = self.shared.state.lock().unwrap();
                next_state = state.statemachine.get_state();
            }

            if next_state != prev_state {
                // state transition
                info!("KM state transition {:?} -> {:?}", prev_state, next_state);

                if next_state == KMSMState::Transport {
                    let mut state = self.shared.state.lock().unwrap();
                    state.sa_id += 1;
                    if state.sa_id == 0 {
                        state.sa_id = 1;
                    }
                    info!("KM: New SA_ID: {}", state.sa_id);
                }
            } else if next_state == KMSMState::Error {
                error!("KM: stuck in error state");
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Key Manager in error state",
                ));
                // TODO: Maybe use a timer and keep trying to reset?
            }
        }

        Ok(())
    }
}

/// Generic encryption error (to be fleshed out later).
pub struct EncryptionError;

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EncryptionError")
    }
}

/// The state of the [KeyManagerStateMachine].
///
/// State transitions:
///
///
/// ```text
///      *
///      ↓
/// Configuring -> Transport
///      ↓ ↑          ↓
///     Error <-------+
///```
///
/// Not accounting for "rekeying" -- for now assuming that can happen
/// internally and machine can just stay in transport state.
#[derive(Debug, Clone, PartialEq)]
pub enum KMSMState {
    Configuring,
    Transport,
    Error,
}

/// A set of constant settings for a particular [KeyManagerStateMachine].  Used
/// to configure the running of the [KeyManager].
#[derive(Debug, Clone)]
pub struct KMSettings {
    /// The ZDP defined type value for this Key Management system.
    pub zdp_km_type: zpr::KmId,

    /// Number of additional bytes required to encrypt a payload for transport.
    pub padlen: usize,

    /// If non-zero, then `payload`+`padlen` must be a multiple of `alignment`.
    pub alignment: u8,

    /// How often the statement runloop should call into [KeyManagerStateMachine::tick].
    pub tick_interval: Duration,
}

/// Interface for a thing which can encrypt and decrypt ZDP trasport payloads.
/// Not to be used for Key Management messages.
pub trait TransportEncr: Send + Sync {
    /// Encrypt `payload` into `message`.
    ///
    /// `sa_id` is the Security Association ID in use.
    fn encrypt_transport(
        self: &Self,
        sa_id: u8,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, EncryptionError>;

    /// Decrypt `payload` into `message`
    ///
    /// `sa_id` is the Security Association ID in use.
    fn decrypt_transport(
        self: &Self,
        sa_id: u8,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, EncryptionError>;
}

/// Interface to a Key Management protocol.
pub trait KeyManagerStateMachine: Send + Sync {
    /// These do not change (TODO: is there a way to state that in rust?)
    fn get_settings(self: &Self) -> KMSettings;

    /// State can only change through handle_message, tick, or reset.
    fn get_state(self: &Self) -> KMSMState;

    /// Reset state machine and optionally initiate a new handshake.
    /// Must clear error state.
    fn reset(self: &mut Self, initiate: bool) -> Option<Bytes>;

    /// Process an inbound KM message.
    /// May produce an output message.
    /// May transition internal state.
    fn handle_message(self: &mut Self, message: &[u8]) -> Option<Bytes>;

    /// Optional outbound KM message
    /// May transition internal state
    fn tick(self: &mut Self) -> Option<Bytes>;

    /// The encrypt/decrypt should not alter internal state of SA. So any state needed
    /// must be part of the message. Not sure about this assumption -- but hoping to
    /// avoid locking whole machine during encrypt/decrypt.
    fn get_transport_encryptor(self: &Self) -> Box<dyn TransportEncr>;
}

/// Placeholder code -- will be removed once we have a real key manager implementation.
pub struct SillyKeyManager {
    state: KMSMState,
    settings: KMSettings,
    hello_t: time::Instant,
    initiate: bool,
}

impl SillyKeyManager {
    pub fn new() -> SillyKeyManager {
        SillyKeyManager {
            state: KMSMState::Configuring,
            settings: KMSettings {
                zdp_km_type: zpr::KM_ID_EXPERIMENTAL,
                padlen: 2,        // we need 2 extra bytes
                alignment: 0,
                tick_interval: Duration::from_millis(1000),
            },
            hello_t: time::Instant::now(),
            initiate: false,
        }
    }
}

struct SillyEncr;

impl TransportEncr for SillyEncr {
    // Copy payload into message with a SIZE preamble.
    fn encrypt_transport(
        self: &Self,
        _sa_id: u8,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, EncryptionError> {
        let sz = payload.len() + 2; // SIZE includes the 2 byte size field.
        if sz > std::u16::MAX as usize {
            return Err(EncryptionError);
        }
        let szbytes = (sz as u16).to_be_bytes();
        message[0..3].copy_from_slice(&szbytes); // write SIZE as u16 to front of buffer
        message[2..sz].copy_from_slice(payload); // then copy rest of payload
        Ok(sz)
    }

    // Check and remove the SIZE preamble, return the payload
    fn decrypt_transport(
        self: &Self,
        _sa_id: u8,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, EncryptionError> {
        let buf_sz = payload.len();
        if buf_sz < 2 {
            return Err(EncryptionError);
        }
        let msg_sz: u16 = u16::from_be_bytes([payload[0], payload[1]]);
        if buf_sz < msg_sz as usize {
            return Err(EncryptionError);
        }
        let msg_len: usize = (msg_sz - 2) as usize;
        message[..msg_len].copy_from_slice(&payload[2..]);
        Ok(msg_len)
    }
}

impl KeyManagerStateMachine for SillyKeyManager {
    fn get_settings(&self) -> KMSettings {
        return self.settings.clone();
    }

    fn get_state(&self) -> KMSMState {
        self.state.clone()
    }

    fn reset(&mut self, initiate: bool) -> Option<Bytes> {
        self.initiate = initiate;
        self.state = KMSMState::Configuring;
        if initiate {
            let handshake = Bytes::from_static(&[0, 255, 0, 12, 1, 2, 3, 4, 5, 6, 7, 8]); // TYPE | LEN | PAYLOAD
            self.hello_t = time::Instant::now();
            Some(handshake)
        } else {
            None
        }
    }

    fn handle_message(&mut self, _message: &[u8]) -> Option<Bytes> {
        if self.state == KMSMState::Configuring {
            self.state = KMSMState::Transport;
            if !self.initiate {
                // Did not initiate, so send a reply back.
                let handshake_reply = Bytes::from_static(&[0, 255, 0, 12, 8, 7, 6, 5, 4, 3, 2, 1]); // TYPE | LEN | PAYLOAD
                return Some(handshake_reply);
            }
        }
        None
    }

    fn tick(&mut self) -> Option<Bytes> {
        if self.state == KMSMState::Configuring {
            if self.initiate && self.hello_t.elapsed() > Duration::from_secs(5) {
                // too long, send another hello.
                let handshake = Bytes::from_static(&[0, 255, 0, 12, 1, 2, 3, 4, 5, 6, 7, 8]); // TYPE | LEN | PAYLOAD
                self.hello_t = time::Instant::now();
                return Some(handshake);
            }
        }
        None
    }

    fn get_transport_encryptor(self: &Self) -> Box<dyn TransportEncr> {
        return Box::new(SillyEncr {});
    }
}

#[cfg(test)]
mod test {
    use tokio::task::yield_now;
    use tokio::time::sleep;
    // use zerocopy::AsBytes;
    use zpr_ext::zerocopy::*;

    use crate::config::PACKET_BUFFER_SIZE;
    use crate::zdp::ZdpZpiHeader;

    use super::*;

    struct TestKM {
        state: KMSMState,
        shared: Arc<TestKMShared>,
    }

    struct TestKMShared {
        state: Mutex<TestKMInternals>,
    }
    struct TestKMInternals {
        initiator: Option<bool>,
        reset_count: u8,
        handle_count: u8,
        tick_count: u8,
    }

    struct TestEncr;

    impl TransportEncr for TestEncr {
        fn encrypt_transport(
            self: &Self,
            _sa_id: u8,
            payload: &[u8],
            message: &mut [u8],
        ) -> Result<usize, EncryptionError> {
            message[0..payload.len()].copy_from_slice(payload);
            Ok(payload.len())
        }

        fn decrypt_transport(
            self: &Self,
            _sa_id: u8,
            payload: &[u8],
            message: &mut [u8],
        ) -> Result<usize, EncryptionError> {
            message[0..payload.len()].copy_from_slice(payload);
            Ok(payload.len())
        }
    }

    impl TestKM {
        pub fn new(initial_state: KMSMState) -> TestKM {
            TestKM {
                state: initial_state,
                shared: Arc::new(TestKMShared {
                    state: Mutex::new(TestKMInternals {
                        initiator: None,
                        reset_count: 0,
                        handle_count: 0,
                        tick_count: 0,
                    }),
                }),
            }
        }
    }

    impl KeyManagerStateMachine for TestKM {
        fn get_settings(&self) -> KMSettings {
            KMSettings {
                zdp_km_type: zpr::KM_ID_EXPERIMENTAL,
                padlen: 8,
                alignment: 8,
                tick_interval: Duration::from_millis(200),
            }
        }

        fn get_state(&self) -> KMSMState {
            return self.state.clone();
        }

        fn reset(&mut self, initiate: bool) -> Option<Bytes> {
            let mut internals = self.shared.state.lock().unwrap();
            internals.initiator = Some(initiate);
            internals.reset_count += 1;
            self.state = KMSMState::Configuring;
            None
        }

        fn handle_message(&mut self, _message: &[u8]) -> Option<Bytes> {
            let mut internals = self.shared.state.lock().unwrap();
            internals.handle_count += 1;
            None
        }

        fn tick(&mut self) -> Option<Bytes> {
            let mut internals = self.shared.state.lock().unwrap();
            internals.tick_count += 1;
            None
        }

        fn get_transport_encryptor(self: &Self) -> Box<dyn TransportEncr> {
            Box::new(TestEncr {})
        }
    }

    #[tokio::test]
    async fn test_km_sends_initiator_msg() {
        let kmb = Box::new(TestKM::new(KMSMState::Configuring));
        let kinternals = kmb.shared.clone();
        let mut km = KeyManager::new(kmb);
        let ctok = CancellationToken::new();
        let (tx, mut _rx) = mpsc::channel(4);

        let sp_ctok = ctok.clone();
        tokio::spawn(async move {
            let _ = km.start(true, sp_ctok, tx).await;
        });

        yield_now().await;

        // Upon startup this should call reset with initiate.
        assert!(kinternals.state.lock().unwrap().reset_count == 1);
        assert!(kinternals.state.lock().unwrap().initiator == Some(true));

        ctok.cancel()
    }

    #[tokio::test]
    async fn test_km_ticks() {
        let kmb = Box::new(TestKM::new(KMSMState::Configuring));
        let kinternals = kmb.shared.clone();
        let mut km = KeyManager::new(kmb);
        let ctok = CancellationToken::new();
        let (tx, mut _rx) = mpsc::channel(4);

        let sp_ctok = ctok.clone();
        tokio::spawn(async move {
            let _ = km.start(true, sp_ctok, tx).await;
        });

        sleep(Duration::from_millis(900)).await;
        // Our tick interval is 200ms so we should have ticked a number of times.

        // Upon startup this should call reset with initiate.
        assert!(kinternals.state.lock().unwrap().tick_count > 3);
        ctok.cancel()
    }

    #[tokio::test]
    async fn test_km_passes_inbound_msg() {
        let kmb = Box::new(TestKM::new(KMSMState::Configuring));
        let kinternals = kmb.shared.clone();
        let km = KeyManager::new(kmb);

        let ctok = CancellationToken::new();
        let (tx, mut _rx) = mpsc::channel(4);

        let sp_ctok = ctok.clone();
        let mut sp_km = km.clone();
        tokio::spawn(async move {
            let _ = sp_km.start(true, sp_ctok, tx).await;
        });
        yield_now().await;

        let msg = Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]);
        match km.handle_km_message(&msg).await {
            Ok(_) => {}
            Err(e) => {
                panic!("handle_km_message failed: {}", e);
            }
        }
        yield_now().await;

        assert!(kinternals.state.lock().unwrap().handle_count == 1);
        ctok.cancel()
    }


    #[tokio::test]
    async fn test_km_passes_inbound_msg_no_buffer() {
        let kmb = Box::new(TestKM::new(KMSMState::Configuring));
        let kinternals = kmb.shared.clone();
        let km = KeyManager::new(kmb);

        let ctok = CancellationToken::new();
        let (tx, mut _rx) = mpsc::channel(4);

        let sp_ctok = ctok.clone();
        let mut sp_km = km.clone();
        tokio::spawn(async move {
            let _ = sp_km.start(true, sp_ctok, tx).await;
        });
        yield_now().await;

        let msg = Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]);
        match km.try_handle_km_message(&msg) {
            Ok(_) => {}
            Err(e) => {
                panic!("handle_km_message failed: {}", e);
            }
        }
        yield_now().await;

        assert!(kinternals.state.lock().unwrap().handle_count == 1);
        ctok.cancel()
    }

    #[tokio::test]
    async fn test_km_encrypt_transport_non_transit() {
        let kmb = Box::new(TestKM::new(KMSMState::Transport));
        let km = KeyManager::new(kmb);

        // No need to start the machine since encrypt only cares about transport state and SA_ID.
        km.set_sa_id(33);

        let hdr = ZdpBaseHeader {
            packet_type: ZdpPacketType::EchoRequest,
            excess_length: 0u8,
            sequence_number: 0u16.into(),
        };
        let mut buf = [0u8; PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, 64);
        //let hbytes = hdr.as_bytes();
        //pkt.body_mut()[0..hbytes.len()].copy_from_slice(&hbytes);
        hdr.write_to_buf(&mut pkt);

        match km.encrypt_transport(&mut pkt) {
            Ok(_) => {}
            Err(e) => {
                panic!("encrypt_transport failed: {}", e);
            }
        }

        // The encrypt function writes a SA_ID to first byte.
        assert!(pkt.body()[0] == 33);

        let encr_hdr =
            ZdpBaseHeader::ref_from_prefix(&pkt.body()[1..]).expect("failed to read back header");

        assert!(encr_hdr.packet_type == hdr.packet_type);
        assert!(encr_hdr.excess_length == hdr.excess_length);
        assert!(encr_hdr.sequence_number == hdr.sequence_number);
    }

    #[tokio::test]
    async fn test_km_decrypt_transport_non_transit() {
        let kmb = Box::new(TestKM::new(KMSMState::Transport));
        let km = KeyManager::new(kmb);

        // No need to start the machine since encrypt only cares about transport state and SA_ID.
        km.set_sa_id(33);

        let zpi_hdr = ZdpZpiHeader { zpi: 33 };

        let hdr = ZdpBaseHeader {
            packet_type: ZdpPacketType::EchoRequest,
            excess_length: 22u8,
            sequence_number: 19u16.into(),
        };
        let mut buf = [0u8; PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, 64);
        hdr.write_to_buf(&mut pkt);
        *pkt.alloc_zeroed_header::<ZdpZpiHeader>() = zpi_hdr;

        assert!(pkt.body()[0] == 33); // sanity check

        match km.decrypt_transport(&mut pkt) {
            Ok(_) => {}
            Err(e) => {
                panic!("decrypt_transport failed: {}", e);
            }
        }

        // The decrypt function leaves the ZPI alone
        assert!(pkt.body()[0] == 33);

        let encr_hdr =
            ZdpBaseHeader::ref_from_prefix(&pkt.body()[1..]).expect("failed to read back header");

        assert!(encr_hdr.packet_type == hdr.packet_type);
        assert!(encr_hdr.excess_length == hdr.excess_length);
        assert!(encr_hdr.sequence_number == hdr.sequence_number);
    }
}
