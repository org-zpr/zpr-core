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

use std::time::Duration;

use std::fmt;
use std::sync::{Arc, Mutex};

use bytes::{BufMut, Bytes};

use zerocopy::FromBytes;

use tracing::{error, info};

use crate::config;
use crate::packet::Packet;
use crate::zdp::{ZdpBaseHeader, ZdpPacketType, ZdpZpiHeader};
use crate::zpr;

#[derive(Debug)]
pub enum KMError {
    ConfigurationError,
    InvalidState,
    InvalidPacketType,
    EncryptionError,
    HandshakeError,
    NoHeadroom,
    ShortPacket,
    SaIdZero,
    SaIdMismatch,
    EnqueueFailed,
    MachineError(String),
    IoError(std::io::Error),
}

impl fmt::Display for KMError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KMError::InvalidState => {
                write!(f, "InvalidState")
            }
            KMError::EncryptionError => {
                write!(f, "EncryptionError")
            }
            KMError::HandshakeError => {
                write!(f, "HandshakeError")
            }
            KMError::ConfigurationError => {
                write!(f, "ConfigurationError")
            }
            KMError::MachineError(ref s) => {
                write!(f, "MachineError: {}", s)
            }
            KMError::IoError(ref e) => {
                write!(f, "IoError: {}", e)
            }
            KMError::InvalidPacketType => {
                write!(f, "InvalidPacketType")
            }
            KMError::NoHeadroom => {
                write!(f, "NoHeadroom")
            }
            KMError::ShortPacket => {
                write!(f, "ShortPacket")
            }
            KMError::SaIdZero => {
                write!(f, "SaIdZero")
            }
            KMError::SaIdMismatch => {
                write!(f, "SaIdMismatch")
            }
            KMError::EnqueueFailed => {
                write!(f, "EnqueueFailed")
            }
        }
    }
}

impl From<std::io::Error> for KMError {
    fn from(e: std::io::Error) -> KMError {
        KMError::IoError(e)
    }
}

// Copying of off std::io::Result
pub type KMResult<T> = Result<T, KMError>;

/// Signals emitted by the KeyManager (see the [KeyManager::start] method).
#[derive(Debug)]
pub enum KMSignal {
    /// After [KeyManagerStateMachine::reset] is called.
    Reset,

    /// If the state machine transitions into the error state.
    Error,

    /// When the SA_ID changes.
    SaIdChange { old: zpr::SaId, new: zpr::SaId },
}

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
    /// For all packets, there must be enough space remaining in the packet buffer to
    /// accomodate expansion caused by encryption.
    ///
    /// Note that we encrypt body.len() bytes from body index 0.  Body length will expand by
    /// the PADLEN indicated in the KM algorithm.
    ///
    /// We also write into the headroom of the packet:
    ///
    /// ```text
    ///     00     ZPI
    ///     01,02  LENGTH of encrypted payload
    /// ```
    ///
    /// TODO: Not sure this works at all for transit packet encryption -- if we are doing that.
    ///
    /// `message` is expected to be a ZDP message wihout a ZPI value.  We add a ZPI
    /// value to the front of the message -- note that the value we add is just the
    /// SA_ID.  It's up to caller to mix in the configuration ID value.
    pub fn encrypt_transport(&self, message: &mut Packet) -> KMResult<()> {
        let base_hdr =
            ZdpBaseHeader::ref_from_prefix(message.body()).expect("too-short ZDP message");
        if message.headroom_available() < 1 {
            return Err(KMError::NoHeadroom);
        }

        let mut state = self.shared.state.lock().unwrap();
        if state.statemachine.get_state() != KMSMState::Transport {
            return Err(KMError::InvalidState);
        }
        if state.sa_id == 0 {
            return Err(KMError::SaIdZero);
        }

        // The assumption here is that caller has already built in space of any padding required by key manager protocol.
        let encr_len: usize = match base_hdr.packet_type {
            ZdpPacketType::KeyManagement => {
                // Programmer error
                return Err(KMError::InvalidPacketType);
            }
            ZdpPacketType::TransitPacket => {
                panic!("Transit packet encryption not implemented");
            }
            _ => message.body().len(),
        };

        // TODO: Ability to encrypt in place. Not sure how to accomplish. At very least we could use our own buffer pool.
        let mut encr_buf = [0u8; config::PACKET_BUFFER_SIZE];
        match state
            .statemachine
            .encrypt_transport(&message.body()[0..encr_len], &mut encr_buf)
        {
            Ok(len) => {
                info!(
                    "noise: encrypt input {} bytes, output {} bytes",
                    encr_len, len
                );
                // Copy the encrypted data back into the message -- there should be sufficient room for it since
                // caller should know our required padding space and alignment.

                message.shrink_by(message.body().len()); // remove body
                message.put(&encr_buf[0..len]); // write a new body

                // Now write our headroom info:
                let head_buf = message.alloc_zeroed_headroom(3); // ZPI + LEN
                head_buf[0] = state.sa_id;

                let szbytes = (len as u16).to_be_bytes();
                head_buf[1..3].copy_from_slice(&szbytes);
            }
            Err(e) => {
                return Err(KMError::MachineError(e.to_string()));
            }
        }
        Ok(())
    }

    /// The message here must start with the ZPI value.
    /// We assume that packet ZPI value has been clensed of the config ID and is only the SA_ID.
    /// Key Management packets should not be sent here.
    /// Does not remove the ZPI/SA_ID value.
    pub fn decrypt_transport(&self, message: &mut Packet) -> KMResult<()> {
        if message.body().len() < 3 {
            // ZPI + LEN
            return Err(KMError::ShortPacket);
        }
        let mut state = self.shared.state.lock().unwrap();
        if message.body()[0] == 0 {
            return Err(KMError::SaIdZero);
        }
        if state.sa_id != message.body()[0] {
            return Err(KMError::SaIdMismatch);
        }
        if state.statemachine.get_state() != KMSMState::Transport {
            return Err(KMError::InvalidState);
        }

        // TODO: Ability to decrypt in place. Not sure how to accomplish.  At very least we could use our own buffer pool.
        let mut decr_buf = [0u8; config::PACKET_BUFFER_SIZE];

        // read the size of the encrypted payload.  Size follows the ZPI/SA_ID value:
        let encr_len: usize = u16::from_be_bytes([message.body()[1], message.body()[2]]) as usize;

        if encr_len + 3 > message.body().len() {
            return Err(KMError::ShortPacket);
        }

        match state
            .statemachine
            .decrypt_transport(&message.body()[3..3 + encr_len], &mut decr_buf)
        {
            Ok(len) => {
                info!(
                    "noise: decrypt input {} bytes, output {} bytes",
                    message.body().len(),
                    len
                );
                // Copy the decrypted data back into the message -- do not overwrite ZPI.
                message.shrink_by(message.body().len()); // remove body
                message.put(&decr_buf[0..len]); // write a new body

                message.alloc_zeroed_header::<ZdpZpiHeader>().zpi = state.sa_id;
            }
            Err(e) => {
                return Err(KMError::MachineError(e.to_string()));
            }
        }
        Ok(())
    }

    /// Pass in a full Key Management payload from our peer here (should not include ZDP header).
    /// This waits until space available in our KM message queue.
    ///
    /// We copy the payload into our own buffer for processing asynchronously. Caller should free buffer.
    pub async fn handle_km_message(&self, message: &[u8]) -> KMResult<()> {
        let tx: mpsc::Sender<Bytes>;
        {
            let state = self.shared.state.lock().unwrap();
            match state.mgmt_tx {
                Some(ref t) => {
                    tx = t.clone();
                }
                None => {
                    return Err(KMError::InvalidState);
                }
            }
        }
        let km_buf = Bytes::copy_from_slice(message);
        match tx.send(km_buf).await {
            Ok(_) => Ok(()),
            Err(_) => Err(KMError::EnqueueFailed),
        }
    }

    /// Pass in a full Key Management payload from our peer here (should not include ZDP header).
    /// This will fail if there is no space in queue.
    ///
    /// We copy the payload into our own buffer for processing asynchronously. Caller should free buffer.
    pub fn try_handle_km_message(&self, message: &[u8]) -> KMResult<()> {
        let tx: mpsc::Sender<Bytes>;
        {
            let state = self.shared.state.lock().unwrap();
            match state.mgmt_tx {
                Some(ref t) => {
                    tx = t.clone();
                }
                None => {
                    return Err(KMError::InvalidState);
                }
            }
        }
        let km_buf = Bytes::copy_from_slice(message);
        match tx.try_send(km_buf) {
            Ok(_) => Ok(()),
            Err(_) => Err(KMError::EnqueueFailed),
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
    /// `km_signals_out` will be recieve signals from the machine.
    pub async fn start(
        &mut self,
        ctok: CancellationToken,
        km_buffers_out: mpsc::Sender<Bytes>,
        km_signals_out: mpsc::Sender<KMSignal>,
    ) -> KMResult<()> {
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
            handshake = match state.statemachine.reset() {
                Ok(h) => h,
                Err(e) => return Err(KMError::MachineError(e.to_string())),
            };
        }
        match km_signals_out.send(KMSignal::Reset).await {
            Ok(_) => {}
            Err(_) => {
                error!("failed to enqueue reset signal")
            }
        }
        if let Some(handshake) = handshake {
            match km_buffers_out.send(handshake).await {
                Ok(_) => {}
                Err(_) => return Err(KMError::EnqueueFailed),
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
                    match km_signals_out.send(KMSignal::Error).await {
                        Ok(_) => {}
                        Err(_) => {
                            error!("failed to enqueue error signal, aborting");
                            return Err(KMError::EnqueueFailed);
                        }
                    }
                    let resp: Option<Bytes>;
                    {
                        let mut state = self.shared.state.lock().unwrap();
                        resp = match state.statemachine.reset() {
                            Ok(h) => h,
                            Err(e) => {
                                return Err(KMError::MachineError(e.to_string()));
                            }
                        };
                    }
                    match km_signals_out.send(KMSignal::Reset).await {
                        Ok(_) => {}
                        Err(_) => {
                            error!("failed to enqueue reset signal, aborting");
                            return Err(KMError::EnqueueFailed);
                        }
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
                                resp = match state.statemachine.handle_message(&inmsg) {
                                    Ok(h) => h,
                                    Err(e) => {
                                        error!("failed to handle key manager message: {}", e);
                                        None
                                    }
                                };
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
                                resp = match state.statemachine.tick() {
                                    Ok(h) => h,
                                    Err(e) => {
                                        error!("failed to tick key manager: {}", e);
                                        None
                                    }
                                };
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
                info!("KM state transition {:?} -> {:?}", prev_state, next_state);
                if next_state == KMSMState::Transport {
                    let prev_id: zpr::SaId;
                    let cur_id: zpr::SaId;
                    {
                        let mut state = self.shared.state.lock().unwrap();
                        prev_id = state.sa_id;
                        state.sa_id += 1;
                        if state.sa_id == 0 {
                            state.sa_id = 1;
                        }
                        cur_id = state.sa_id;
                    }
                    info!("KM: New SA_ID: {}", cur_id);
                    match km_signals_out
                        .send(KMSignal::SaIdChange {
                            old: prev_id,
                            new: cur_id,
                        })
                        .await
                    {
                        Ok(_) => {}
                        Err(_) => {
                            error!("failed to enqueue SaIdChange signal")
                        }
                    }
                }
            } else if next_state == KMSMState::Error {
                error!("KM: stuck in error state");
                return Err(KMError::MachineError(String::from("stuck in error state")));
                // TODO: Maybe use a timer and keep trying to reset?
            }
        }

        Ok(())
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
    /// Note that the KM itself adds 2 bytes for a length field.
    pub padlen: usize,

    /// If non-zero, then `payload`+`padlen` must be a multiple of `alignment`.
    pub alignment: u8,

    /// How often the statement runloop should call into [KeyManagerStateMachine::tick].
    pub tick_interval: Duration,
}

/// Interface to a Key Management protocol.
pub trait KeyManagerStateMachine: Send + Sync {
    /// These do not change (TODO: is there a way to state that in rust?)
    fn get_settings(self: &Self) -> KMSettings;

    /// State can only change through handle_message, tick, or reset.
    fn get_state(self: &Self) -> KMSMState;

    /// Reset state machine. This is always called as the state machine is
    /// started (prior to first tick).  If this is the initiator this should initiate a
    /// new handshake message.
    /// Must clear error state.
    fn reset(self: &mut Self) -> Result<Option<Bytes>, KMError>;

    /// Process an inbound KM message.
    /// May produce an output message.
    /// May transition internal state.
    fn handle_message(self: &mut Self, message: &[u8]) -> Result<Option<Bytes>, KMError>;

    /// Optional outbound KM message
    /// May transition internal state
    /// If this returns error, internal state should be error too.
    fn tick(self: &mut Self) -> Result<Option<Bytes>, KMError>;

    /// Encrypt `payload` into `message`.
    ///
    /// `sa_id` is the Security Association ID in use.
    fn encrypt_transport(
        self: &mut Self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, KMError>;

    /// Decrypt `payload` into `message`
    ///
    /// `sa_id` is the Security Association ID in use.
    fn decrypt_transport(
        self: &mut Self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, KMError>;
}

#[cfg(test)]
mod test {
    use tokio::task::yield_now;
    use tokio::time::sleep;
    use zpr_ext::zerocopy::*;

    use crate::config::PACKET_BUFFER_SIZE;

    use super::*;

    #[allow(dead_code)]
    struct TestKM {
        state: KMSMState,
        shared: Arc<TestKMShared>,
        initiator: bool,
    }

    struct TestKMShared {
        state: Mutex<TestKMInternals>,
    }
    struct TestKMInternals {
        reset_count: u8,
        handle_count: u8,
        tick_count: u8,
    }

    impl TestKM {
        pub fn new(initiate: bool, initial_state: KMSMState) -> TestKM {
            TestKM {
                state: initial_state,
                shared: Arc::new(TestKMShared {
                    state: Mutex::new(TestKMInternals {
                        reset_count: 0,
                        handle_count: 0,
                        tick_count: 0,
                    }),
                }),
                initiator: initiate,
            }
        }
    }

    impl KeyManagerStateMachine for TestKM {
        fn get_settings(&self) -> KMSettings {
            KMSettings {
                zdp_km_type: zpr::KM_ID_EXPERIMENTAL,
                padlen: 0,
                alignment: 0,
                tick_interval: Duration::from_millis(200),
            }
        }

        fn get_state(&self) -> KMSMState {
            return self.state.clone();
        }

        fn reset(&mut self) -> Result<Option<Bytes>, KMError> {
            let mut internals = self.shared.state.lock().unwrap();
            internals.reset_count += 1;
            self.state = KMSMState::Configuring;
            Ok(None)
        }

        fn handle_message(&mut self, _message: &[u8]) -> Result<Option<Bytes>, KMError> {
            let mut internals = self.shared.state.lock().unwrap();
            internals.handle_count += 1;
            Ok(None)
        }

        fn tick(&mut self) -> Result<Option<Bytes>, KMError> {
            let mut internals = self.shared.state.lock().unwrap();
            internals.tick_count += 1;
            Ok(None)
        }

        fn encrypt_transport(
            self: &mut Self,
            payload: &[u8],
            message: &mut [u8],
        ) -> Result<usize, KMError> {
            message[0..payload.len()].copy_from_slice(payload);
            Ok(payload.len())
        }

        fn decrypt_transport(
            self: &mut Self,
            payload: &[u8],
            message: &mut [u8],
        ) -> Result<usize, KMError> {
            message[0..payload.len()].copy_from_slice(payload);
            Ok(payload.len())
        }
    }

    #[tokio::test]
    async fn test_km_sends_initiator_msg() {
        let kmb = Box::new(TestKM::new(true, KMSMState::Configuring));
        let kinternals = kmb.shared.clone();
        let mut km = KeyManager::new(kmb);
        let ctok = CancellationToken::new();
        let (tx, mut _rx) = mpsc::channel(4);
        let (sig_tx, mut _sig_rx) = mpsc::channel(4);

        let sp_ctok = ctok.clone();
        tokio::spawn(async move {
            let _ = km.start(sp_ctok, tx, sig_tx).await;
        });

        yield_now().await;

        // Upon startup this should call reset with initiate.
        assert!(kinternals.state.lock().unwrap().reset_count == 1);

        ctok.cancel()
    }

    #[tokio::test]
    async fn test_km_ticks() {
        let kmb = Box::new(TestKM::new(true, KMSMState::Configuring));
        let kinternals = kmb.shared.clone();
        let mut km = KeyManager::new(kmb);
        let ctok = CancellationToken::new();
        let (tx, mut _rx) = mpsc::channel(4);
        let (sig_tx, mut _sig_rx) = mpsc::channel(4);

        let sp_ctok = ctok.clone();
        tokio::spawn(async move {
            let _ = km.start(sp_ctok, tx, sig_tx).await;
        });

        sleep(Duration::from_millis(900)).await;
        // Our tick interval is 200ms so we should have ticked a number of times.

        // Upon startup this should call reset with initiate.
        assert!(kinternals.state.lock().unwrap().tick_count > 3);
        ctok.cancel()
    }

    #[tokio::test]
    async fn test_km_passes_inbound_msg() {
        let kmb = Box::new(TestKM::new(true, KMSMState::Configuring));
        let kinternals = kmb.shared.clone();
        let km = KeyManager::new(kmb);

        let ctok = CancellationToken::new();
        let (tx, mut _rx) = mpsc::channel(4);
        let (sig_tx, mut _sig_rx) = mpsc::channel(4);

        let sp_ctok = ctok.clone();
        let mut sp_km = km.clone();
        tokio::spawn(async move {
            let _ = sp_km.start(sp_ctok, tx, sig_tx).await;
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
        let kmb = Box::new(TestKM::new(true, KMSMState::Configuring));
        let kinternals = kmb.shared.clone();
        let km = KeyManager::new(kmb);

        let ctok = CancellationToken::new();
        let (tx, mut _rx) = mpsc::channel(4);
        let (sig_tx, mut _sig_rx) = mpsc::channel(4);

        let sp_ctok = ctok.clone();
        let mut sp_km = km.clone();
        tokio::spawn(async move {
            let _ = sp_km.start(sp_ctok, tx, sig_tx).await;
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
        let kmb = Box::new(TestKM::new(true, KMSMState::Transport));
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

        // Rest of input is after the length...
        let encr_hdr =
            ZdpBaseHeader::ref_from_prefix(&pkt.body()[3..]).expect("failed to read back header");

        assert!(encr_hdr.packet_type == hdr.packet_type);
        assert!(encr_hdr.excess_length == hdr.excess_length);
        assert!(encr_hdr.sequence_number == hdr.sequence_number);
    }

    #[tokio::test]
    async fn test_km_decrypt_transport_non_transit() {
        let kmb = Box::new(TestKM::new(true, KMSMState::Transport));
        let km = KeyManager::new(kmb);

        // No need to start the machine since encrypt only cares about transport state and SA_ID.
        km.set_sa_id(33);

        let mut buf = [0u8; PACKET_BUFFER_SIZE];
        let mut pkt = Packet::new(&mut buf, 64);

        let hdr = ZdpBaseHeader {
            packet_type: ZdpPacketType::EchoRequest,
            excess_length: 0u8,
            sequence_number: 0u16.into(),
        };
        //let hbytes = hdr.as_bytes();
        //pkt.body_mut()[0..hbytes.len()].copy_from_slice(&hbytes);
        hdr.write_to_buf(&mut pkt);
        match km.encrypt_transport(&mut pkt) {
            Ok(_) => {}
            Err(e) => {
                panic!("encrypt_transport failed: {}", e);
            }
        }

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
