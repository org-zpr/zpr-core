// km.rs - Key Management for ZDP

//! An API for a Key Management protocol to be used to set up and maintain a
//! security association (SA) with a peer.  In ZPR adapters set up SAs with
//! their docks.  And nodes set up SAs on their links to other nodes.
//!
//! The [KeyManager] is runs a state machine, dispatching to an implementation
//! of a [KeyManagerStateMachine] which does the actual work of creating and
//! parsing key management ZDP messages.

use crate::config;
use crate::logging::targets::KEY_MGMT;
use crate::packet::Packet;
use crate::zdp::{ZdpBaseHeader, ZdpPacketType, ZdpZpiHeader};
use bytes::{BufMut, Bytes};
use openssl::x509::{X509, X509NameRef};
use std::fmt;
use std::fmt::Debug;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::time;
use tokio_util::sync::CancellationToken;
use tracing::*;
use zerocopy::FromBytes;
use zpr::packet_info::{KmId, LinkId, SaId};

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum KmError {
    #[error("ConfigurationError")]
    ConfigurationError,
    #[error("InvalidState")]
    InvalidState,
    #[error("InvalidPacketType")]
    InvalidPacketType,
    #[error("HandshakeError")]
    HandshakeError,
    #[error("CertExchangeError")]
    CertExchangeError,
    #[error("NoHeadroom")]
    NoHeadroom,
    #[error("ShortPacket")]
    ShortPacket,
    #[error("SaIdZero")]
    SaIdZero,
    #[error("SaIdMismatch")]
    SaIdMismatch,
    #[error("EnqueueFailued")]
    EnqueueFailed,
    #[error("MachineError: {0}")]
    MachineError(String),
    #[error("IoError: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Error)]
pub enum EncryptionError {
    /// Unspecified error occurred in the encryption implementation.  The string arg is an error description.
    #[error("InternalError: {0}")]
    InternalError(String),

    /// Message is too large for the encryption implementation to handle.
    #[error("MessageTooLarge")]
    MessageTooLarge,

    /// Message is malformed in some way.
    #[error("ParseError")]
    ParseError,
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum DecryptionError {
    /// Unspecified error occurred in the decryption implementation.  The string arg is an error description.
    #[error("InternalError: {0}")]
    InternalError(String),

    /// Message is too short to be decrypted.
    #[error("MessageTooShort")]
    MessageTooShort,

    /// Message is malformed in some way.
    #[error("ParseError")]
    ParseError,

    /// Unable to decrypt the message due to wrong key or some other cipher issue.
    #[error("DecryptFailed")]
    DecryptFailed,
}

/// The key exchange process always swaps certificates, but they may or may not
/// be signed by our trusted CA. In particular, adapters may create self-signed
/// certificates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerCertificate {
    Verified(X509),
    Unverified(X509),
}

impl PeerCertificate {
    pub fn get_cert(&self) -> &X509 {
        match self {
            PeerCertificate::Verified(cert) => cert,
            PeerCertificate::Unverified(cert) => cert,
        }
    }
    pub fn subject_name(&self) -> &X509NameRef {
        match self {
            PeerCertificate::Verified(cert) => cert.subject_name(),
            PeerCertificate::Unverified(cert) => cert.subject_name(),
        }
    }
}

// Copying of off std::io::Result
pub type KmResult<T> = Result<T, KmError>;

/// Signals emitted by the KeyManager (see the [KeyManager::start] method).
#[derive(Debug)]
pub enum KmSignal {
    /// After [KeyManagerStateMachine::reset] is called.
    Reset,

    /// If the state machine transitions into the error state.
    Error,

    /// When the SA_ID changes.  Note that if new is zero then the SA is no longer established.
    SaIdChange { old: SaId, new: SaId },

    /// When a security association is established.
    SaEstablished(KmTransportSA),

    /// Sent during a clean shutdown of the KeyManager (when the CancellationToken is cancelled).
    Termination,
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

impl fmt::Display for ZPIPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(encr: {}, hmac: {})", self.encr, self.hmac)
    }
}

/// Encapsulates all the "state" set up by an SA.
#[derive(Clone)]
pub struct KmTransportSA {
    /// The SA identifier is mostly just a marker used internally.  If re-keying occurs or
    /// the identifier will increment.  A zero value indicates that the SA is not established.
    ///
    /// Note that when this is used by implementations of [KeyManagerStateMachine] the `sa_id`
    /// field is not set.  Only the [KeyManager] is setting an ID on the association.
    pub sa_id: SaId,

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

    /// If we got a certificate from our peer, it is stored here.
    pub peer_cert: Option<PeerCertificate>,
}

// Does not check the codec.
impl PartialEq for KmTransportSA {
    fn eq(&self, other: &Self) -> bool {
        self.send_zpis == other.send_zpis
            && self.recv_zpis == other.recv_zpis
            && self.send_hmac_key == other.send_hmac_key
            && self.recv_hmac_key == other.recv_hmac_key
    }
}

// Our debug formatter omits the codec.
impl fmt::Debug for KmTransportSA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let cert_str = match &self.peer_cert {
            Some(c) => {
                format!("{:?}", c.subject_name())
            }
            None => "None".to_string(),
        };
        write!(
            f,
            "KMTransportSA {{ sa_id: {}, send_zpis: {}, recv_zpis: {}, send_hmac_key: {:02x?}, recv_hmac_key: {:02x?}, peer_cert: {}}}",
            self.sa_id,
            self.send_zpis,
            self.recv_zpis,
            self.send_hmac_key,
            self.recv_hmac_key,
            cert_str
        )
    }
}

impl fmt::Display for KmTransportSA {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.sa_id == 0 {
            return write!(f, "KMTransportSA {{ sa_id: 0 }}");
        }
        Debug::fmt(self, f)
    }
}

/// The Key Manager emits messages on two queues, and both use this general structure.
/// The `msg` field is either going to be a [KmSignal] or a payload for a Key Management
/// ZDP message which will be in a [Bytes].
pub struct KmLinkMsg<T> {
    pub link_id: LinkId,
    pub msg: T,
}

impl<T> KmLinkMsg<T> {
    pub fn new(link_id: LinkId, msg: T) -> KmLinkMsg<T> {
        KmLinkMsg { link_id, msg }
    }
}

/// Stateful key manager for ZDP.  Requires an instance of a [KeyManagerStateMachine] to do the actual work.
/// One of these is needed on every adap-node or node-node link.
#[derive(Debug, Clone)]
pub struct KeyManager {
    shared: Arc<KmShared>,
}

#[derive(Debug)]
struct KmShared {
    state: Mutex<KmState>,
}

struct KmState {
    statemachine: Box<dyn KeyManagerStateMachine>,
    link_id: LinkId,
    kmsettings: KmSettings,
    sa_id: SaId, // current SA identifier
    ts: KmTransportSA,
    restart_request: bool,
    error_signaled: bool,
}

impl fmt::Debug for KmState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "KMState {{ link_id: {}, sa_id: {} }}",
            self.link_id, self.sa_id
        )
    }
}

impl KeyManager {
    /// A new KeyManager for a link.
    /// - `statemachine` is the key management algorithm.
    pub fn new(link_id: LinkId, statemachine: Box<dyn KeyManagerStateMachine>) -> KeyManager {
        let settings = statemachine.get_settings();

        KeyManager {
            shared: Arc::new(KmShared {
                state: Mutex::new(KmState {
                    statemachine,
                    link_id,
                    kmsettings: settings,
                    sa_id: 0,
                    ts: Default::default(),
                    restart_request: false,
                    error_signaled: false,
                }),
            }),
        }
    }

    /// If we are in a transport state, this returns the details.
    /// Note that this is also sent "for free" with the SaEstablished signal.
    #[allow(dead_code)]
    pub fn get_transport_state(&self) -> Option<KmTransportSA> {
        let state = self.shared.state.lock().unwrap();
        if state.sa_id == 0 {
            return None;
        }
        Some(KmTransportSA {
            sa_id: state.sa_id,
            recv_zpis: state.ts.recv_zpis,
            send_zpis: state.ts.send_zpis,
            send_hmac_key: state.ts.send_hmac_key,
            recv_hmac_key: state.ts.recv_hmac_key,
            codec: state.ts.codec.clone(),
            peer_cert: state.ts.peer_cert.clone(),
        })
    }

    /// Indicate that the KM state machine should restart out of the error state.
    /// For an initiator type link, this will trigger generation of a new handshake message.
    ///
    /// [KmError::InvalidState] is returned if state machine is not in error state.
    pub fn restart(&self) -> KmResult<()> {
        let mut state = self.shared.state.lock().unwrap();
        if state.statemachine.get_state() != KmSMState::Error {
            return Err(KmError::InvalidState);
        }
        state.restart_request = true;
        Ok(())
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
    ///
    /// `km_messages_in` for incomming key management messages (key management payloads).
    pub async fn start(
        &mut self,
        ctok: CancellationToken,
        km_buffers_out: mpsc::Sender<KmLinkMsg<Bytes>>,
        km_signals_out: mpsc::Sender<KmLinkMsg<KmSignal>>,
        mut km_messages_in: mpsc::Receiver<Bytes>,
        km_impl: KmId,
    ) -> KmResult<()> {
        let tick_interval: Duration;
        let link_id;
        {
            let state = self.shared.state.lock().unwrap();
            tick_interval = state.kmsettings.tick_interval;
            link_id = state.link_id;
        }

        let mut interval = time::interval(tick_interval);

        self.start_state_machine_internal(link_id, &km_signals_out, &km_buffers_out)
            .await
            .or_else(|e| {
                error!(target: KEY_MGMT, "failed to start state machine: {}", e);
                Err(e)
            })?;

        let mut prev_state: KmSMState;
        let mut next_state: KmSMState;

        loop {
            {
                let state = self.shared.state.lock().unwrap();
                prev_state = state.statemachine.get_state();
            }

            tokio::select! {
                _ = ctok.cancelled() => {
                    match self.send_signal(&km_signals_out, link_id, KmSignal::Termination).await {
                        Ok(_) => {}
                        Err(_) => {}
                    };
                    break;
                }

                Some(inmsg) = km_messages_in.recv() => {
                    match self.dispatch_km_message(inmsg, link_id, &km_buffers_out, km_impl).await {
                        Ok(_) => {}
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }

                _ = interval.tick() => {
                    match self.tick_statemachine(link_id, &km_buffers_out, &km_signals_out, &prev_state).await {
                        Ok(_) => {}
                        Err(e) => {
                            return Err(e);
                        }
                    }
                }
            }

            {
                let state = self.shared.state.lock().unwrap();
                next_state = state.statemachine.get_state();
            }

            if next_state != prev_state {
                match self
                    .handle_state_transition(prev_state, next_state, link_id, &km_signals_out)
                    .await
                {
                    Ok(_) => {}
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Kick off the [KeyManagerStateMachine] by calling its reset method.
    /// As a side effect this also sends the [KmSignal::Reset] signal out our signal channel.
    /// If the state machine produces a handshake message as a result of reset, then that
    /// is sent our our message channel.
    async fn start_state_machine_internal(
        &self,
        link_id: LinkId,
        km_signals_out: &mpsc::Sender<KmLinkMsg<KmSignal>>,
        km_buffers_out: &mpsc::Sender<KmLinkMsg<Bytes>>,
    ) -> KmResult<()> {
        let handshake: Option<Bytes>;
        {
            let mut state = self.shared.state.lock().unwrap();
            handshake = match state.statemachine.reset() {
                Ok(h) => h,
                Err(e) => return Err(KmError::MachineError(e.to_string())),
            };
        }

        match self
            .send_signal(&km_signals_out, link_id, KmSignal::Reset)
            .await
        {
            Ok(_) => {}
            Err(_) => {
                error!(target: KEY_MGMT, "failed to enqueue reset signal")
            }
        };

        if let Some(handshake) = handshake {
            match km_buffers_out
                .send(KmLinkMsg::new(link_id, handshake))
                .await
            {
                Ok(_) => {}
                Err(_) => return Err(KmError::EnqueueFailed),
            }
        };

        Ok(())
    }

    // Helper to reduce verbosity slightly
    fn send_signal<'a>(
        &self,
        chan: &'a mpsc::Sender<KmLinkMsg<KmSignal>>,
        link_id: LinkId,
        signal: KmSignal,
    ) -> impl Future<Output = Result<(), mpsc::error::SendError<KmLinkMsg<KmSignal>>>> + 'a {
        chan.send(KmLinkMsg::new(link_id, signal))
    }

    /// Calls the state machine's tick method and sends any resulting message.
    async fn tick_statemachine(
        &self,
        link_id: LinkId,
        km_buffers_out: &mpsc::Sender<KmLinkMsg<Bytes>>,
        km_signals_out: &mpsc::Sender<KmLinkMsg<KmSignal>>,
        cur_state: &KmSMState,
    ) -> KmResult<()> {
        let mut resp: Option<Bytes> = None;
        let mut did_reset = false;

        if *cur_state == KmSMState::Error {
            {
                let mut state = self.shared.state.lock().unwrap();
                if state.restart_request {
                    resp = match state.statemachine.reset() {
                        Ok(h) => {
                            did_reset = true;
                            h
                        }
                        Err(e) => {
                            return Err(KmError::MachineError(e.to_string()));
                        }
                    };
                    state.restart_request = false;
                }
            }
            if let Some(r) = resp {
                match km_buffers_out.send(KmLinkMsg::new(link_id, r)).await {
                    Ok(_) => {}
                    Err(_) => {
                        error!(target: KEY_MGMT, "failed to enqueue outbound KM message");
                        return Err(KmError::EnqueueFailed);
                    }
                }
            }
            if did_reset {
                match self
                    .send_signal(km_signals_out, link_id, KmSignal::Reset)
                    .await
                {
                    Ok(_) => {}
                    Err(_) => {
                        error!(target: KEY_MGMT, "failed to enqueue reset signal, aborting");
                        return Err(KmError::EnqueueFailed);
                    }
                }
            }
        }

        // Unless we did a reset, tick machine, even during error.
        if !did_reset {
            let resp: Option<Bytes>;
            {
                let mut state = self.shared.state.lock().unwrap();
                resp = match state.statemachine.tick() {
                    Ok(h) => h,
                    Err(e) => {
                        warn!(target: KEY_MGMT, "error during tick processing: {}", e);
                        None
                    }
                };
            }
            if let Some(r) = resp {
                match km_buffers_out.send(KmLinkMsg::new(link_id, r)).await {
                    Ok(_) => {}
                    Err(_) => {
                        error!(target: KEY_MGMT, "failed to enqueue oubound KM message");
                        return Err(KmError::EnqueueFailed);
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_state_transition(
        &self,
        prev_state: KmSMState,
        next_state: KmSMState,
        link_id: LinkId,
        km_signals_out: &mpsc::Sender<KmLinkMsg<KmSignal>>,
    ) -> KmResult<()> {
        debug!(target: KEY_MGMT, "state transition {:?} -> {:?}", prev_state, next_state);
        if matches!(prev_state, KmSMState::Error) {
            // We transitioned out of error state -- clear error related settings.
            let mut state = self.shared.state.lock().unwrap();
            state.error_signaled = false;
            state.restart_request = false;
        }
        match next_state {
            KmSMState::Transport(ts) => {
                let prev_id: SaId;
                let cur_id: SaId;
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
                debug!(target: KEY_MGMT, "New SA_ID: {}", cur_id);
                match self
                    .send_signal(
                        &km_signals_out,
                        link_id,
                        KmSignal::SaIdChange {
                            old: prev_id,
                            new: cur_id,
                        },
                    )
                    .await
                {
                    Ok(_) => {}
                    Err(_) => {
                        error!(target: KEY_MGMT, "failed to enqueue SaIdChange signal");
                        return Err(KmError::EnqueueFailed);
                    }
                }
                match self
                    .send_signal(&km_signals_out, link_id, KmSignal::SaEstablished(my_sa))
                    .await
                {
                    Ok(_) => {}
                    Err(_) => {
                        error!(target: KEY_MGMT, "failed to enqueue SaIdEstablished signal");
                        return Err(KmError::EnqueueFailed);
                    }
                }
            }
            KmSMState::Error => {
                let needs_error_signal: bool;
                {
                    let state = self.shared.state.lock().unwrap();
                    needs_error_signal = !state.error_signaled;
                }
                if needs_error_signal {
                    match self
                        .send_signal(km_signals_out, link_id, KmSignal::Error)
                        .await
                    {
                        Ok(_) => {}
                        Err(_) => {
                            error!(target: KEY_MGMT, "failed to enqueue error signal, aborting");
                            return Err(KmError::EnqueueFailed);
                        }
                    }
                    {
                        let mut state = self.shared.state.lock().unwrap();
                        state.error_signaled = true;
                    }
                }
            }
            KmSMState::Configuring => {}
        };
        Ok(())
    }

    /// Deliver a Key Management Payload to the state machine implemntation, forwarding out
    /// a response message if there is one.
    async fn dispatch_km_message(
        &self,
        inmsg: Bytes,
        link_id: LinkId,
        km_buffers_out: &mpsc::Sender<KmLinkMsg<Bytes>>,
        km_impl: KmId,
    ) -> KmResult<()> {
        let resp: Option<Bytes>;
        {
            let mut state = self.shared.state.lock().unwrap();
            resp = match state.statemachine.handle_message(&inmsg, km_impl) {
                Ok(h) => h,
                Err(e) => {
                    error!(target: KEY_MGMT, "failed to handle key manager message: {e}");
                    None
                }
            };
        }
        if let Some(r) = resp {
            match km_buffers_out.send(KmLinkMsg::new(link_id, r)).await {
                Ok(_) => {}
                Err(_) => {
                    error!(target: KEY_MGMT, "failed to enqueue outbound KM message");
                    return Err(KmError::EnqueueFailed);
                }
            }
        }
        Ok(())
    }
}

impl KmTransportSA {
    pub fn new(
        send_zpis: ZPIPair,
        recv_zpis: ZPIPair,
        send_key: [u8; 32],
        recv_key: [u8; 32],
        codec: Arc<dyn Codec>,
        peer_cert: Option<PeerCertificate>,
    ) -> KmTransportSA {
        KmTransportSA {
            sa_id: 0,
            send_zpis,
            recv_zpis,
            send_hmac_key: send_key,
            recv_hmac_key: recv_key,
            codec,
            peer_cert,
        }
    }

    #[allow(dead_code)]
    pub fn new_with_codec(codec: Arc<dyn Codec>) -> KmTransportSA {
        KmTransportSA {
            sa_id: 0,
            send_zpis: ZPIPair::new_zero(),
            recv_zpis: ZPIPair::new_zero(),
            send_hmac_key: [0u8; 32],
            recv_hmac_key: [0u8; 32],
            codec,
            peer_cert: None,
        }
    }

    /// With ZPIs but empty keys.
    #[allow(dead_code)]
    pub fn new_with_zpis(send_zpis: ZPIPair, recv_zpis: ZPIPair) -> KmTransportSA {
        KmTransportSA {
            sa_id: 0,
            send_zpis,
            recv_zpis,
            send_hmac_key: [0u8; 32],
            recv_hmac_key: [0u8; 32],
            codec: Arc::new(UnimplCodec::new()),
            peer_cert: None,
        }
    }
}

impl Default for KmTransportSA {
    fn default() -> Self {
        Self {
            sa_id: 0,
            send_zpis: ZPIPair::new_zero(),
            recv_zpis: ZPIPair::new_zero(),
            send_hmac_key: [0u8; 32],
            recv_hmac_key: [0u8; 32],
            codec: Arc::new(UnimplCodec::new()),
            peer_cert: None,
        }
    }
}

/// Helper function which is ZDP aware.  Does some error checking and leaves the ZPI
/// in place.
#[allow(dead_code)]
pub fn encrypt_transport_zdp(message: &mut Packet, codec: Arc<dyn Codec>) -> KmResult<()> {
    if message.body().len()
        < std::mem::size_of::<ZdpZpiHeader>() + std::mem::size_of::<ZdpBaseHeader>()
    {
        return Err(KmError::ShortPacket);
    }
    let (base_hdr, _) =
        ZdpBaseHeader::ref_from_prefix(&message.body()[1..]).expect("too-short ZDP message");

    let encr_len: usize = match base_hdr.packet_type {
        ZdpPacketType::TransitPacket => {
            return Err(KmError::InvalidPacketType);
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
            return Err(KmError::MachineError(e.to_string()));
        }
    }
    Ok(())
}

/// Helper function which is ZDP aware.  Does some error checking and leaves the ZPI in place.
#[allow(dead_code)]
pub fn decrypt_transport_zdp(message: &mut Packet, codec: Arc<dyn Codec>) -> KmResult<()> {
    if message.body().len() < 1 {
        return Err(KmError::ShortPacket);
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
            return Err(KmError::MachineError(e.to_string()));
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
/// Note that moving from Error back to Configuring requires a an external call to [KeyManager::restart].
/// Not (yet) accounting for "rekeying".
///
#[derive(Debug, Clone, PartialEq)]
pub enum KmSMState {
    Configuring,
    Transport(KmTransportSA),
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

/// A set of constant settings for a particular [KeyManagerStateMachine].  Used
/// to configure the running of the [KeyManager].
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct KmSettings {
    /// The ZDP defined type value for this Key Management system.
    pub zdp_km_type: KmId,

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
    fn get_settings(self: &Self) -> KmSettings;

    /// State can only change through handle_message, tick, or reset.
    fn get_state(self: &Self) -> KmSMState;

    /// Reset state machine. This is always called as the state machine is
    /// started (prior to first tick).  If this is the initiator this should initiate a
    /// new handshake message.
    /// Must clear error state.
    fn reset(self: &mut Self) -> Result<Option<Bytes>, KmError>;

    /// Process an inbound KM message.
    /// May produce an output message.
    /// May transition internal state.
    fn handle_message(
        self: &mut Self,
        message: &[u8],
        km_impl: KmId,
    ) -> Result<Option<Bytes>, KmError>;

    /// Optional outbound KM message
    /// May transition internal state
    /// If this returns error, internal state should be error too.
    fn tick(self: &mut Self) -> Result<Option<Bytes>, KmError>;
}

#[cfg(test)]
mod test {
    use crate::config::PACKET_BUFFER_SIZE;
    use tokio::task::yield_now;
    use tokio::time::sleep;
    use zpr::packet_info::{KM_ID_EXPERIMENTAL, KM_ID_NOISE};
    use zpr_ext::zerocopy::*;

    use super::*;

    #[allow(dead_code)]
    struct TestKM {
        state: KmSMState,
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
        pub fn new(initiate: bool, initial_state: KmSMState) -> TestKM {
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
        fn get_settings(&self) -> KmSettings {
            KmSettings {
                zdp_km_type: KM_ID_EXPERIMENTAL,
                padlen: 0,
                alignment: 0,
                tick_interval: Duration::from_millis(200),
            }
        }

        fn get_state(&self) -> KmSMState {
            return self.state.clone();
        }

        fn reset(&mut self) -> Result<Option<Bytes>, KmError> {
            let mut internals = self.shared.state.lock().unwrap();
            internals.reset_count += 1;
            self.state = KmSMState::Configuring;
            Ok(None)
        }

        fn handle_message(
            &mut self,
            _message: &[u8],
            _km_impl: KmId,
        ) -> Result<Option<Bytes>, KmError> {
            let mut internals = self.shared.state.lock().unwrap();
            internals.handle_count += 1;
            Ok(None)
        }

        fn tick(&mut self) -> Result<Option<Bytes>, KmError> {
            let mut internals = self.shared.state.lock().unwrap();
            internals.tick_count += 1;
            Ok(None)
        }
    }

    #[tokio::test]
    async fn test_km_sends_initiator_msg() {
        let kmb = Box::new(TestKM::new(true, KmSMState::Configuring));
        let kinternals = kmb.shared.clone();
        let mut km = KeyManager::new(1, kmb);
        let ctok = CancellationToken::new();
        let (tx, mut _rx) = mpsc::channel(4);
        let (sig_tx, mut _sig_rx) = mpsc::channel(4);

        let (_km_tx, km_rx) = mpsc::channel(16);
        let sp_ctok = ctok.clone();
        tokio::spawn(async move {
            let _ = km.start(sp_ctok, tx, sig_tx, km_rx, KM_ID_NOISE).await;
        });

        yield_now().await;

        // Upon startup this should call reset with initiate.
        assert!(kinternals.state.lock().unwrap().reset_count == 1);

        ctok.cancel()
    }

    #[tokio::test]
    async fn test_km_ticks() {
        let kmb = Box::new(TestKM::new(true, KmSMState::Configuring));
        let kinternals = kmb.shared.clone();
        let mut km = KeyManager::new(1, kmb);
        let ctok = CancellationToken::new();
        let (tx, mut _rx) = mpsc::channel(4);
        let (sig_tx, mut _sig_rx) = mpsc::channel(4);

        let (_km_tx, km_rx) = mpsc::channel(16);

        let sp_ctok = ctok.clone();
        tokio::spawn(async move {
            let _ = km.start(sp_ctok, tx, sig_tx, km_rx, KM_ID_NOISE).await;
        });

        sleep(Duration::from_millis(900)).await;
        // Our tick interval is 200ms so we should have ticked a number of times.

        // Upon startup this should call reset with initiate.
        assert!(kinternals.state.lock().unwrap().tick_count > 3);
        ctok.cancel()
    }

    #[tokio::test]
    async fn test_km_passes_inbound_msg() {
        let kmb = Box::new(TestKM::new(true, KmSMState::Configuring));
        let kinternals = kmb.shared.clone();
        let km = KeyManager::new(1, kmb);

        let ctok = CancellationToken::new();
        let (tx, mut _rx) = mpsc::channel(4);
        let (sig_tx, mut _sig_rx) = mpsc::channel(4);

        let sp_ctok = ctok.clone();
        let mut sp_km = km.clone();

        let (km_tx, km_rx) = mpsc::channel(16);
        tokio::spawn(async move {
            let _ = sp_km.start(sp_ctok, tx, sig_tx, km_rx, KM_ID_NOISE).await;
        });
        yield_now().await;

        let msg = Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]);
        km_tx.send(msg).await.unwrap();
        yield_now().await;

        assert!(kinternals.state.lock().unwrap().handle_count == 1);
        ctok.cancel()
    }

    #[tokio::test]
    async fn test_km_passes_inbound_msg_no_buffer() {
        let kmb = Box::new(TestKM::new(true, KmSMState::Configuring));
        let kinternals = kmb.shared.clone();
        let km = KeyManager::new(1, kmb);

        let ctok = CancellationToken::new();
        let (tx, mut _rx) = mpsc::channel(4);
        let (sig_tx, mut _sig_rx) = mpsc::channel(4);

        let sp_ctok = ctok.clone();
        let mut sp_km = km.clone();
        let (km_tx, km_rx) = mpsc::channel(16);
        tokio::spawn(async move {
            let _ = sp_km.start(sp_ctok, tx, sig_tx, km_rx, KM_ID_NOISE).await;
        });
        yield_now().await;

        let msg = Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7, 8]);
        km_tx.send(msg).await.unwrap();
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
        };
        let buf = Box::new([0u8; PACKET_BUFFER_SIZE]);
        let mut pkt = Packet::new(buf, 64);
        //let hbytes = hdr.as_bytes();
        //pkt.body_mut()[0..hbytes.len()].copy_from_slice(&hbytes);
        hdr.write_to_buf(&mut pkt).unwrap();
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
        let encr_hdr = ZdpBaseHeader::ref_from_prefix(&pkt.body()[1..])
            .expect("failed to read back header")
            .0;

        assert!(encr_hdr.packet_type == hdr.packet_type);
        assert!(encr_hdr.excess_length == hdr.excess_length);
    }

    #[tokio::test]
    async fn test_km_decrypt_transport_non_transit() {
        let codec = Arc::new(CopyCodec {});

        let buf = Box::new([0u8; PACKET_BUFFER_SIZE]);
        let mut pkt = Packet::new(buf, 64);

        let hdr = ZdpBaseHeader {
            packet_type: ZdpPacketType::EchoRequest,
            excess_length: 0u8,
        };
        //let hbytes = hdr.as_bytes();
        //pkt.body_mut()[0..hbytes.len()].copy_from_slice(&hbytes);
        hdr.write_to_buf(&mut pkt).unwrap();
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

        let encr_hdr = ZdpBaseHeader::ref_from_prefix(&pkt.body()[1..])
            .expect("failed to read back header")
            .0;

        assert!(encr_hdr.packet_type == hdr.packet_type);
        assert!(encr_hdr.excess_length == hdr.excess_length);
    }
}
