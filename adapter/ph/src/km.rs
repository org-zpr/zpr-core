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

use std::future::Future;
use std::time::Duration;

use std::fmt;
use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use bytes::{BufMut, Bytes};

use zerocopy::FromBytes;

use tracing::{error, info};

use crate::config;
use crate::packet::Packet;
use crate::zdp::{ZdpBaseHeader, ZdpPacketType, ZdpZpiHeader};
use crate::zpr;

#[derive(Debug)]
#[allow(dead_code)]
pub enum KMError {
    ConfigurationError,
    InvalidState,
    InvalidPacketType,
    HandshakeError,
    NoHeadroom,
    ShortPacket,
    SaIdZero,
    SaIdMismatch,
    EnqueueFailed,
    MachineError(String),
    IoError(std::io::Error),
}

#[derive(Debug)]
pub enum EncryptionError {
    /// Unspecified error occurred in the encryption implementation.  The string arg is an error description.
    InternalError(String),

    /// Message is too large for the encryption implementation to handle.
    MessageTooLarge,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum DecryptionError {
    /// Unspecified error occurred in the decryption implementation.  The string arg is an error description.
    InternalError(String),

    /// Message is too short to be decrypted.
    MessageTooShort,

    /// Message is malformed in some way.
    ParseError,

    /// Unable to decrypt the message due to wrong key or some other cipher issue.
    DecryptFailed,
}

impl fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            DecryptionError::InternalError(ref s) => {
                write!(f, "InternalError: {}", s)
            }
            DecryptionError::MessageTooShort => {
                write!(f, "MessageTooShort")
            }
            DecryptionError::ParseError => {
                write!(f, "ParseError")
            }
            DecryptionError::DecryptFailed => {
                write!(f, "DecryptFailed")
            }
        }
    }
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EncryptionError::InternalError(ref s) => {
                write!(f, "InternalError: {}", s)
            }
            EncryptionError::MessageTooLarge => {
                write!(f, "MessageTooLarge")
            }
        }
    }
}

impl fmt::Display for KMError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            KMError::InvalidState => {
                write!(f, "InvalidState")
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

    /// When the SA_ID changes.  Note that if new is zero then the SA is no longer established.
    SaIdChange { old: zpr::SaId, new: zpr::SaId },

    /// When a security association is established.
    SaEstablished(KMTransportSA),
}

/// Encapsulates all the "state" set up by an SA.
#[derive(Clone)]
pub struct KMTransportSA {
    /// The SA identifier is mostly just a marker used internally.  If re-keying occurs or
    /// the identifier will increment.  A zero value indicates that the SA is not established.
    ///
    /// Note that when this is used by implementations of [KeyManagerStateMachine] the `sa_id`
    /// field is not set.  Only the [KeyManager] is setting an ID on the association.
    pub sa_id: zpr::SaId,

    /// These are the ZPIs which we have given to our peer to use for sending us messages.
    pub recv_zpis: ZPIPair,

    /// These are the ZPIs which our peer has given us to use for sending messages.
    pub send_zpis: ZPIPair,

    /// This is the key, shared with our peer, which we should use for sending HMAC messages to the peer.
    pub send_hmac_key: [u8; 32],

    /// The is the key, shared with our peer, which our peer will use to send HMAC messages to us.
    pub recv_hmac_key: [u8; 32],

    /// This is a pointer to the encode/decode functions associated with the current SA.
    pub codec: Arc<dyn Codec>,
}

// Does not check the codec.
impl PartialEq for KMTransportSA {
    fn eq(&self, other: &Self) -> bool {
        self.send_zpis == other.send_zpis
            && self.recv_zpis == other.recv_zpis
            && self.send_hmac_key == other.send_hmac_key
            && self.recv_hmac_key == other.recv_hmac_key
    }
}

// Our debug formatter omits the codec.
impl fmt::Debug for KMTransportSA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "KMTransportSA {{ sa_id: {}, send_zpis: {:?}, recv_zpis: {:?}, send_hmac_key: {:?}, recv_hmac_key: {:?} }}",
            self.sa_id, self.send_zpis, self.recv_zpis, self.send_hmac_key, self.recv_hmac_key
        )
    }
}

impl fmt::Display for KMTransportSA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.sa_id == 0 {
            return write!(f, "KMTransportSA {{ sa_id: 0 }}");
        }
        Debug::fmt(self, f)
    }
}

/// The Key Manager emits messages on two queues, and both use this general structure.
/// The `msg` field is either going to be a [KMSignal] or a payload for a Key Management
/// ZDP message which will be in a [Bytes].
pub struct KMLinkMsg<T> {
    pub link_id: zpr::LinkId,
    pub msg: T,
}

impl<T> KMLinkMsg<T> {
    pub fn new(link_id: zpr::LinkId, msg: T) -> KMLinkMsg<T> {
        KMLinkMsg { link_id, msg }
    }
}

/// Stateful key manager for ZDP.  Requires an instance of a [KeyManagerStateMachine] to do the actual work.
/// One of these is needed on every adap-node or node-node link.
#[derive(Debug, Clone)]
pub struct KeyManager<'mgr> {
    shared: Arc<KMShared<'mgr>>,
}

#[derive(Debug)]
struct KMShared<'mgr> {
    state: Mutex<KMState<'mgr>>,
}

struct KMState<'mgr> {
    // Lifetime hint here asserts that the impl of KeyManagerStateMachine must live as long as the KeyManager it is passed to.
    statemachine: Box<dyn KeyManagerStateMachine + 'mgr>,
    link_id: zpr::LinkId,
    kmsettings: KMSettings,
    sa_id: zpr::SaId,                     // current SA identifier
    mgmt_tx: Option<mpsc::Sender<Bytes>>, // Internal queue for key management messages to be processed.
    ts: KMTransportSA,
}

impl fmt::Debug for KMState<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "KMState {{ link_id: {}, sa_id: {} }}",
            self.link_id, self.sa_id
        )
    }
}

impl KeyManager<'_> {
    /// A new KeyManager for a link.
    /// - `statemachine` is the key management algorithm.
    pub fn new<'a>(
        link_id: zpr::LinkId,
        statemachine: Box<dyn KeyManagerStateMachine>,
    ) -> KeyManager<'a> {
        let settings = statemachine.get_settings();

        KeyManager {
            shared: Arc::new(KMShared {
                state: Mutex::new(KMState {
                    statemachine,
                    link_id,
                    kmsettings: settings,
                    sa_id: 0,
                    mgmt_tx: None,
                    ts: Default::default(),
                }),
            }),
        }
    }

    /// If we are in a transport state, this returns the details.
    /// Note that this is also sent "for free" with the SaEstablished signal.
    #[allow(dead_code)]
    pub fn get_transport_state(&self) -> Option<KMTransportSA> {
        let state = self.shared.state.lock().unwrap();
        if state.sa_id == 0 {
            return None;
        }
        Some(KMTransportSA {
            sa_id: state.sa_id,
            recv_zpis: state.ts.recv_zpis,
            send_zpis: state.ts.send_zpis,
            send_hmac_key: state.ts.send_hmac_key,
            recv_hmac_key: state.ts.recv_hmac_key,
            codec: state.ts.codec.clone(),
        })
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
    #[allow(dead_code)]
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
        km_buffers_out: mpsc::Sender<KMLinkMsg<Bytes>>,
        km_signals_out: mpsc::Sender<KMLinkMsg<KMSignal>>,
    ) -> KMResult<()> {
        let (km_tx, mut km_rx) = mpsc::channel(16);
        let tick_interval: Duration;
        let link_id;
        {
            let mut state = self.shared.state.lock().unwrap();
            state.mgmt_tx = Some(km_tx);
            tick_interval = state.kmsettings.tick_interval;
            link_id = state.link_id;
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
        match km_signals_out
            .send(KMLinkMsg::new(link_id, KMSignal::Reset))
            .await
        {
            Ok(_) => {}
            Err(_) => {
                error!("failed to enqueue reset signal")
            }
        }
        if let Some(handshake) = handshake {
            match km_buffers_out
                .send(KMLinkMsg::new(link_id, handshake))
                .await
            {
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
                    match km_signals_out
                        .send(KMLinkMsg::new(link_id, KMSignal::Error))
                        .await
                    {
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
                    match km_signals_out
                        .send(KMLinkMsg::new(link_id, KMSignal::Reset))
                        .await
                    {
                        Ok(_) => {}
                        Err(_) => {
                            error!("failed to enqueue reset signal, aborting");
                            return Err(KMError::EnqueueFailed);
                        }
                    }
                    if let Some(resp) = resp {
                        match km_buffers_out.send(KMLinkMsg::new(link_id, resp)).await {
                            Ok(_) => {}
                            Err(_) => {
                                error!("failed to enqueue outbound KM message");
                                return Err(KMError::EnqueueFailed);
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
                                match km_buffers_out.send(KMLinkMsg::new(link_id, resp)).await {
                                    Ok(_) => {},
                                    Err(_) => {
                                        error!("failed to enqueue outbound KM message");
                                        return Err(KMError::EnqueueFailed);
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
                                match km_buffers_out.send(KMLinkMsg::new(link_id, resp)).await {
                                    Ok(_) => {},
                                    Err(_) => {
                                        error!("failed to enqueue oubound KM message");
                                        return Err(KMError::EnqueueFailed);
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
                match next_state {
                    KMSMState::Transport(ts) => {
                        let prev_id: zpr::SaId;
                        let cur_id: zpr::SaId;
                        let mut my_sa = ts.clone();
                        {
                            let mut state = self.shared.state.lock().unwrap();
                            prev_id = state.sa_id;
                            state.sa_id += 1;
                            if state.sa_id == 0 {
                                state.sa_id = 1;
                            }
                            cur_id = state.sa_id;
                            // Capture the SA and update the SA_ID.
                            my_sa.sa_id = cur_id;
                            state.ts = my_sa.clone();
                        }
                        info!("KM: New SA_ID: {}", cur_id);
                        match self
                            .send_signal(
                                &km_signals_out,
                                link_id,
                                KMSignal::SaIdChange {
                                    old: prev_id,
                                    new: cur_id,
                                },
                            )
                            .await
                        {
                            Ok(_) => {}
                            Err(_) => {
                                error!("failed to enqueue SaIdChange signal");
                                return Err(KMError::EnqueueFailed);
                            }
                        }
                        match self
                            .send_signal(&km_signals_out, link_id, KMSignal::SaEstablished(my_sa))
                            .await
                        {
                            Ok(_) => {}
                            Err(_) => {
                                error!("failed to enqueue SaIdEstablished signal");
                                return Err(KMError::EnqueueFailed);
                            }
                        }
                    }
                    _ => {}
                }
            } else if next_state == KMSMState::Error {
                error!("KM: stuck in error state");
                return Err(KMError::MachineError(String::from("stuck in error state")));
                // TODO: Maybe use a timer and keep trying to reset?
            }
        }

        Ok(())
    }

    // Helper to reduce verbosity slightly
    fn send_signal<'a>(
        &self,
        chan: &'a mpsc::Sender<KMLinkMsg<KMSignal>>,
        link_id: zpr::LinkId,
        signal: KMSignal,
    ) -> impl Future<Output = Result<(), mpsc::error::SendError<KMLinkMsg<KMSignal>>>> + 'a {
        chan.send(KMLinkMsg::new(link_id, signal))
    }
}

impl KMTransportSA {
    pub fn new(
        send_zpis: ZPIPair,
        recv_zpis: ZPIPair,
        send_key: [u8; 32],
        recv_key: [u8; 32],
        codec: Arc<dyn Codec>,
    ) -> KMTransportSA {
        KMTransportSA {
            sa_id: 0,
            send_zpis,
            recv_zpis,
            send_hmac_key: send_key,
            recv_hmac_key: recv_key,
            codec,
        }
    }

    #[allow(dead_code)]
    pub fn new_with_codec(codec: Arc<dyn Codec>) -> KMTransportSA {
        KMTransportSA {
            sa_id: 0,
            send_zpis: ZPIPair::new_zero(),
            recv_zpis: ZPIPair::new_zero(),
            send_hmac_key: [0u8; 32],
            recv_hmac_key: [0u8; 32],
            codec,
        }
    }

    /// With ZPIs but empty keys.
    #[allow(dead_code)]
    pub fn new_with_zpis(send_zpis: ZPIPair, recv_zpis: ZPIPair) -> KMTransportSA {
        KMTransportSA {
            sa_id: 0,
            send_zpis,
            recv_zpis,
            send_hmac_key: [0u8; 32],
            recv_hmac_key: [0u8; 32],
            codec: Arc::new(UnimplCodec::new()),
        }
    }
}

impl Default for KMTransportSA {
    fn default() -> Self {
        Self {
            sa_id: 0,
            send_zpis: ZPIPair::new_zero(),
            recv_zpis: ZPIPair::new_zero(),
            send_hmac_key: [0u8; 32],
            recv_hmac_key: [0u8; 32],
            codec: Arc::new(UnimplCodec::new()),
        }
    }
}

/// Helper function which is ZDP aware.  Does some error checking and leaves the ZPI
/// in place.
#[allow(dead_code)]
pub fn encrypt_transport_zdp(message: &mut Packet, codec: Arc<dyn Codec>) -> KMResult<()> {
    if message.body().len()
        < std::mem::size_of::<ZdpZpiHeader>() + std::mem::size_of::<ZdpBaseHeader>()
    {
        return Err(KMError::ShortPacket);
    }
    let base_hdr =
        ZdpBaseHeader::ref_from_prefix(&message.body()[1..]).expect("too-short ZDP message");

    let encr_len: usize = match base_hdr.packet_type {
        ZdpPacketType::TransitPacket => {
            return Err(KMError::InvalidPacketType);
        }
        _ => message.body().len() - 1,
    };

    let mut encr_buf = [0u8; config::PACKET_BUFFER_SIZE];

    match codec.encrypt_transport_stateless(&message.body()[1..encr_len + 1], &mut encr_buf) {
        Ok(len) => {
            // Copy the encrypted data back into the message -- there should be sufficient room for it since
            // caller should know our required padding space and alignment.
            message.shrink_by(encr_len); // remove body
            message.put(&encr_buf[0..len]); // write a new body
        }
        Err(e) => {
            return Err(KMError::MachineError(e.to_string()));
        }
    }
    Ok(())
}

/// Helper function which is ZDP arare.  Does some error checking and leaves the ZPI in place.
#[allow(dead_code)]
pub fn decrypt_transport_zdp(message: &mut Packet, codec: Arc<dyn Codec>) -> KMResult<()> {
    if message.body().len() < 1 {
        return Err(KMError::ShortPacket);
    }

    let encr_len = message.body().len() - 1;
    if encr_len == 0 {
        // empty?
        return Ok(());
    }

    // TODO: Ability to decrypt in place. Not sure how to accomplish.  At very least we could use our own buffer pool.
    let mut decr_buf = [0u8; config::PACKET_BUFFER_SIZE];

    match codec.decrypt_transport_stateless(&message.body()[1..encr_len + 1], &mut decr_buf) {
        Ok(len) => {
            // Copy the decrypted data back into the message -- do not overwrite ZPI.
            message.shrink_by(encr_len); // remove body
            message.put(&decr_buf[0..len]); // write a new body
        }
        Err(e) => {
            return Err(KMError::MachineError(e.to_string()));
        }
    }
    Ok(())
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
/// Not (yet) accounting for "rekeying".
///
#[derive(Debug, Clone, PartialEq)]
pub enum KMSMState {
    Configuring,
    Transport(KMTransportSA),
    Error,
}

/// This "codec" must be implemented by a [KeyManagerStateMachine] to handle the actual
/// encryption and decryption of payloads.  Note that these functions simple encrypt
/// and decrypt entire buffers.  It is up to implemnentor to make sure that things like
/// "ZPI" are left alone.
pub trait Codec: Send + Sync {
    /// Encrypt `payload` into `message`.
    fn encrypt_transport_stateless(
        self: &Self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, EncryptionError>;

    /// Decrypt `payload` into `message`
    fn decrypt_transport_stateless(
        self: &Self,
        payload: &[u8],
        message: &mut [u8],
    ) -> Result<usize, DecryptionError>;
}

/// An implementation of Codec that just throws errors for all operations.
pub struct UnimplCodec;
impl UnimplCodec {
    pub fn new() -> UnimplCodec {
        UnimplCodec {}
    }
}

impl Codec for UnimplCodec {
    /// Function is not implemented so always returns an error.
    fn encrypt_transport_stateless(
        self: &Self,
        _payload: &[u8],
        _message: &mut [u8],
    ) -> Result<usize, EncryptionError> {
        Err(EncryptionError::InternalError(String::from(
            "encrypt not implemented",
        )))
    }

    /// Function is not implemented so always returns an error.
    fn decrypt_transport_stateless(
        self: &Self,
        _payload: &[u8],
        _message: &mut [u8],
    ) -> Result<usize, DecryptionError> {
        Err(DecryptionError::InternalError(String::from(
            "decrypt not implemented",
        )))
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ZPIPair {
    /// ZPI for full message encryption.
    pub encr: u8,

    /// ZPI for header hmac only.
    pub hmac: u8,
}

impl ZPIPair {
    pub fn new_zero() -> ZPIPair {
        ZPIPair { encr: 0, hmac: 0 }
    }
    pub fn new(encr: u8, hmac: u8) -> ZPIPair {
        ZPIPair { encr, hmac }
    }
}

/// A set of constant settings for a particular [KeyManagerStateMachine].  Used
/// to configure the running of the [KeyManager].
#[derive(Debug, Clone)]
#[allow(dead_code)]
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

    struct CopyCodec;

    impl Codec for CopyCodec {
        fn encrypt_transport_stateless(
            self: &Self,
            payload: &[u8],
            message: &mut [u8],
        ) -> Result<usize, EncryptionError> {
            message[0..payload.len()].copy_from_slice(payload);
            Ok(payload.len())
        }

        fn decrypt_transport_stateless(
            self: &Self,
            payload: &[u8],
            message: &mut [u8],
        ) -> Result<usize, DecryptionError> {
            message[0..payload.len()].copy_from_slice(payload);
            Ok(payload.len())
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
    }

    #[tokio::test]
    async fn test_km_sends_initiator_msg() {
        let kmb = Box::new(TestKM::new(true, KMSMState::Configuring));
        let kinternals = kmb.shared.clone();
        let mut km = KeyManager::new(1, kmb);
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
        let mut km = KeyManager::new(1, kmb);
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
        let km = KeyManager::new(1, kmb);

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
        let km = KeyManager::new(1, kmb);

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
        let codec = Arc::new(CopyCodec {});

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
        pkt.alloc_zeroed_header::<ZdpZpiHeader>().zpi = 0x33;
        let orig_len = pkt.body().len();
        assert!(orig_len == 1 + std::mem::size_of::<ZdpBaseHeader>());

        match encrypt_transport_zdp(&mut pkt, codec.clone()) {
            Ok(_) => {}
            Err(e) => {
                panic!("encrypt_transport failed: {}", e);
            }
        }

        assert!(
            pkt.body().len() == orig_len,
            "body length changed: expected {}, got {}",
            orig_len,
            pkt.body().len()
        );
        let encr_hdr =
            ZdpBaseHeader::ref_from_prefix(&pkt.body()[1..]).expect("failed to read back header");

        assert!(encr_hdr.packet_type == hdr.packet_type);
        assert!(encr_hdr.excess_length == hdr.excess_length);
        assert!(encr_hdr.sequence_number == hdr.sequence_number);
    }

    #[tokio::test]
    async fn test_km_decrypt_transport_non_transit() {
        let codec = Arc::new(CopyCodec {});

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
        pkt.alloc_zeroed_header::<ZdpZpiHeader>().zpi = 33;
        let orig_len = pkt.body().len();
        assert!(orig_len == 1 + std::mem::size_of::<ZdpBaseHeader>());

        match encrypt_transport_zdp(&mut pkt, codec.clone()) {
            Ok(_) => {}
            Err(e) => {
                panic!("encrypt_transport failed: {}", e);
            }
        }
        assert!(pkt.body()[0] == 33); // encrypt does not touch ZPI
        match decrypt_transport_zdp(&mut pkt, codec.clone()) {
            Ok(_) => {}
            Err(e) => {
                panic!("decrypt_transport failed: {}", e);
            }
        }
        assert!(pkt.body()[0] == 33); // decrypt does not touch ZPI
        assert!(
            pkt.body().len() == orig_len,
            "body length changed: expected {}, got {}",
            orig_len,
            pkt.body().len()
        );

        let encr_hdr =
            ZdpBaseHeader::ref_from_prefix(&pkt.body()[1..]).expect("failed to read back header");

        assert!(encr_hdr.packet_type == hdr.packet_type);
        assert!(encr_hdr.excess_length == hdr.excess_length);
        assert!(encr_hdr.sequence_number == hdr.sequence_number);
    }
}
