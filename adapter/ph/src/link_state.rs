use crate::assembly::Assembly;
use crate::auth::{self, DecodedBlob, ZdpAuthCodeBlob, ZdpSelfSignedBlob, AUTH_KEY_SIZE_BYTES};
use crate::config;
use crate::counters::CounterType;
use crate::km::ZPIPair;
use crate::km_multiplexor;
use crate::logging::targets::LINK_STATE;
use crate::mgmt;
use crate::net_defs::IpAddress;
use crate::sample_ring::SampleRing;
use crate::special_peers;
use crate::special_peers::SpecialPeerName;
use crate::visa_mgmt;
use crate::zdp::{self, ResponseCode, TerminateReason};

use openssl::x509::X509;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::sync::broadcast;
use tokio::time::MissedTickBehavior;
use tracing::*;
use zpr::{LinkId, ZPI_ENCRYPTED_HEADER_FLAG};

/// State machine for links and docking sessions

// Node-to-Node
// +--------------+       +----------+       +--------+
// | UNCONFIGURED |--CD-->| INACTIVE |--ST-->| KEYING |
// +--------------+       +----------+       +--------+
//     ^                       ^               | |  |
//     |                       |   +------KDe--+ |  +--KDu--------+
//     |                       CC  |       C    KDo               |
//     |                       |   V             V                V
//     |                   +---------+  HDe  +----------+     +----------+
//     |                   | CLOSING |<--C---| HELLOING |     | HELLOING |
//     |                   +---------+       +----------+     | SILENT   |
//     R                       ^                  |   |       +----------+
//     |                       |                 HDo HDu          |    |
//     |                       C                  |   |          HDu   C
//     |                       |                  |   +------+   HDo  HDe
//     |                       |                  V          V    V     |
//     |                       | KDe, C, KF   +--------+    +--------+  |
//     |                       +----------+---| ACTIVE |--->| ACTIVE |  |
//     |                                  |   +--------+ KDu| Silent |  |
//     +<-R-[ANY STATE]                   |            +--------+  |
//     |                                  |                |       |
// +-------+                              |                C       |
// | ERROR |<-- Error -- [ANY STATE]      |                |       |
// +-------+                              +----------------+-------+

// Node-to-Adapter
// NOTE: The LISTENING state, just like the UNCONFIGURED state, is implicit
// +--------------+       +-----------+                    +--------+
// | UNCONFIGURED |--CD-->| LISTENING |---------------RKM->| KEYING |
// +--------------+       +-----------+                    +--------+
//     ^                    ^                                | |  |
//     |                    | +------KDe---------------------+ |  +--KDu--+
//     |                   CC |       C                       KDo         |
//     |                    | |                             +--+          |
//     |                    | V                             V             V
//     |              +---------+              HDe   +----------+  +----------+
//     |              | CLOSING |<---------------C---| HELLOING |  | HELLOING |
//     |              +---------+                    +----------+  | SILENT   |
//     R                  ^                               |   |    +----------+
//     |                  |                              HDo HDu        |    |
//     |                  C             +-----------------+   |      HDo,HDu C
//     |                  |             |             +-------+<--------+   HDe
//     |                  |             V             |                      |
//     |                  |        +-------------+  +-------------+          |
//     |                  +<-RADe--| REGISTER AA |  | REGISTER AA |          |
//     |                  |   C    +-------------+  |    SILENT   |-----C--->+
//     |                  |              |    |     +-------------+          |
//     |                  |             RADo  RADu     |                     |
//     |                  |              |    |       RAD                    |
//     |              +---+              |    +-----+  |                     |
//     |              |                  V          V  V                     |
//     |              | KDe, RADe, C +--------+    +--------+                |
//     |              +----------+---| ACTIVE |--->| ACTIVE |                |
//     |                 KF      |   +--------+KDu,| Silent |                |
//     +<-R-[ANY STATE]           \           RADu +--------+                |
//     |                           \                   |                     |
// +-------+                        \                  C                     |
// | ERROR |<-- Error - [ANY STATE]  \                 |                     |
// +-------+                          +----------------+---------------------+

// Adapter-to-Node
// +--------------+       +----------+                     +--------+
// | UNCONFIGURED |--CD-->| INACTIVE |---------ST--------->| KEYING |
// +--------------+       +----------+                     +--------+
//     ^                   ^                                 | |  |
//     |                   |  +------KDe---------------------+ |  +--KDu-----+
//     |                   CC |       C                       KDo            |
//     |                   |  |                                |             |
//     |                   |  V                                V             V
//     |              +---------+             HDe   +----------+  +----------+
//     |              | CLOSING |<-------------C----| HELLOING |  | HELLOING |
//     |              +---------+                   +----------+  | SILENT   |
//     R                  ^                              |   |    +----------+
//     |                  |                             HDo HDu        |    |
//     |                  C            +-----------------+   |      HDu,HDo C
//     |                  |            |             +-------+<--------+   HDe
//     |                  |            V             |                      |
//     |                  |       +-------------+  +-------------+          |
//     |                  +<-RADe-| REGISTER AA |  | REGISTER AA |          |
//     |                  |   C   +-------------+  |    SILENT   |----C---->+
//     |                  |             |    |     +-------------+          |
//     |                  |            RADo  RADu     |                     |
//     |             +----+             |    |       RAD                    |
//     |             |                  |    +-----+  |                     |
//     |             |                  V          V  V                     |
//     |             | KDe, RADe, C +--------+    +--------+                |
//     |             +----------+---| ACTIVE |--->| ACTIVE |                |
//     |                  KF    |   +--------+KDu,| Silent |                |
//     +<-R-[ANY STATE]          \           RADu +--------+                |
//     |                          \                   |                     |
// +-------+                       \                  C                     |
// | ERROR |<- Error - [ANY STATE]  \                 |                     |
// +-------+                         +----------------+---------------------+

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum LinkState {
    Inactive,
    Keying,
    Helloing,
    Closing,
    Resetting,
    Active,
    RegisterAA, // aka acquiring ZPR address
    WaitForInitAuth,
    WaitForAcquireZprAddress,
    Error,
}

#[allow(dead_code)]
#[derive(Clone, Debug, strum::IntoStaticStr)]
pub enum LinkEvent {
    Start,
    KeyingDone,
    ReceivedHelloRequest(IpAddress), // Actors ZPR address - TODO: implement AAAs
    AssignedAAA(IpAddress),          // Assigned AAA address for this link
    ReceivedHelloResponse(ResponseCode, IpAddress, Option<Vec<SocketAddr>>), // (response code, AAA address, ASA addresses)
    SentHelloResponse,

    ReceivedInitAuth((bool, Option<auth::ZdpInitAuthenticationPayload>)), // (bootstrap_flag, challenge)
    ReceivedInitAuthResponse(ResponseCode),

    ReceivedAcquireZprAddressRequest(Option<Vec<IpAddress>>, String), // (requested_addrs, auth_blob)
    ReceivedAcquireResponse(ResponseCode),

    ReceivedGrantZprAddressRequest(Option<Vec<IpAddress>>), // granted_addrs, None means failure.
    ReceivedGrantResponse(ResponseCode),

    AuthenticationSuccess(auth::ZdpAuthCodeBlob), // From an authentication service
    AuthenticationFailure,                        // From an authentication service

    ReceivedEchoResponse { sequence_number: u16 },
    ReceivedAuthorizeResponse, // from visa service
    ReceivedKeepAliveResponse,
    ReceivedTerminateRequest(TerminateReason),
    ReceivedTerminateResponse(ResponseCode),
    ReceivedTerminateIndication(TerminateReason),
    SentTerminate,
    Close(TerminateReason),
    CloseDone,
    Error,
    Timeout { logical_clock: u64 },
}

#[derive(Error, Debug)]
pub enum LinkStateError {
    #[error("Got unexpected event {1} on state {0:?}")]
    UnexpectedTransition(LinkState, &'static str),
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
    #[error("Link {0} does not exist in peer table")]
    NotFound(LinkId),
    #[error("This operation is not supported yet")]
    OperationNotSupportedYet,
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum LinkType {
    Internal,
    AdapterToNode,
    NodeToNode, // Currently unsupported
    NodeToAdapter,
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum LinkStatus {
    Up,
    Down,
}

/// Lives in a [LinkStateWrapper]
pub struct LinkData {
    echo_success: u64, // Echo requests received response
    echo_timeout: u64, // Echo requests timed out
    // TODO: configurable keep-alive period
    // For now, keep-alives are attempted every 3 seconds
    // Assuming no loss, 100 samples will store 5 minutes of latency data
    latency_data: SampleRing<Duration, 100>,
    asa_addresses: Option<Vec<SocketAddr>>, // Addresses of ASA servers told to us by our peer, if any
    aaa_address: Option<IpAddress>,         // AAA address assigned this link (if any)
}

impl LinkData {
    pub fn new() -> Self {
        Self {
            echo_success: 0,
            echo_timeout: 0,
            latency_data: SampleRing::new(Duration::ZERO),
            asa_addresses: None,
            aaa_address: None,
        }
    }
}

pub struct LinkStateMachine {
    id: LinkId,
    state: LinkState,
    status: LinkStatus,
    silent: bool,
    actor_addresses: Vec<IpAddress>,
    last_state_change: std::time::Instant,
    /// used to prevent A/B/A errors with timeouts
    logical_clock: u64,
    timeout_handle: Option<tokio::task::AbortHandle>,
    /// Counter available for use by states which wish to count timeouts.
    /// Reset to 0 on any state transition.
    timeout_count: usize,
    /// present only while in RegisterAA state; used for retransmits
    auth_blob: Option<String>,
}

impl LinkStateMachine {
    pub fn new(link_id: LinkId) -> Self {
        Self {
            id: link_id,
            state: LinkState::Inactive,
            status: LinkStatus::Down,
            silent: false,
            actor_addresses: Default::default(),
            last_state_change: std::time::Instant::now(),
            logical_clock: 0,
            timeout_handle: None,
            timeout_count: 0,
            auth_blob: None,
        }
    }

    pub fn set_state(&mut self, new_state: LinkState) {
        if new_state != self.state {
            debug!(target: LINK_STATE, "Link {} state transition {:?} => {:?}", self.id, self.state, new_state);
        }
        self.state = new_state;
        self.last_state_change = std::time::Instant::now();
        self.cancel_timeout();
        self.timeout_count = 0;
        self.auth_blob = None;
    }

    /// Schedule the given callback to be invoked asynchronously after the
    /// specified duration.
    ///
    /// The callback will be passed the logical clock at which time the
    /// timeout was set, and, after obtaining a lock on the state machine,
    /// the callback should compare this value to the current logical clock
    /// to determine whether it is still valid.
    ///
    /// Any existing callback is cancelled as with `cancel_timeout()`.
    ///
    /// The timeout will be canceled automatically at the next state change.
    /// (Note that any call to `set_state()` will cancel the timeout, even
    /// if the state does not actually change.)
    pub fn set_timeout_callback(
        &mut self,
        duration: std::time::Duration,
        callback: impl FnOnce(u64) + Send + 'static,
    ) {
        // cancel old timeout if present
        self.cancel_timeout();

        // launch new timeout tied to the current (new) logical clock
        let logical_clock = self.logical_clock;
        let jh = tokio::task::spawn(async move {
            tokio::time::sleep(duration).await;
            callback(logical_clock);
        });

        // store new timeout handle
        self.timeout_handle = Some(jh.abort_handle());
    }

    /// Try to cancel any existing timeout.
    ///
    /// Any existing callback may or may not be invoked at a later time.  It
    /// is the responsibility of the callback to ensure atomic behavior by
    /// comparing the logical clock as detailed in `set_timeout_callback()`.
    pub fn cancel_timeout(&mut self) {
        // request to abort existing timeout task if present
        self.timeout_handle.take().inspect(|h| h.abort());
        // increment logical clock to avoid duplicate timeouts
        self.logical_clock = self.logical_clock.wrapping_add(1);
    }
}

const LINK_STATE_EVENT_QUEUE_SIZE: usize = 16;

pub struct LinkStateWrapper {
    id: LinkId, // set at constructor, never changes.
    link_type: LinkType,
    locked_fsm: Mutex<LinkStateMachine>,
    events: broadcast::Sender<LinkEvent>,
    pub locked_data: Mutex<LinkData>,
}

impl LinkStateWrapper {
    pub fn new(new_id: LinkId, new_link_type: LinkType) -> Self {
        Self {
            id: new_id,
            link_type: new_link_type,
            locked_fsm: Mutex::new(LinkStateMachine::new(new_id)),
            events: broadcast::Sender::new(LINK_STATE_EVENT_QUEUE_SIZE),
            locked_data: Mutex::new(LinkData::new()),
        }
    }

    /// Get the link's current state
    pub fn get_state(&self) -> LinkState {
        self.locked_fsm.lock().unwrap().state
    }

    pub fn is_ready(&self) -> bool {
        let locked_fsm = self.locked_fsm.lock().unwrap();
        locked_fsm.status == LinkStatus::Up
            && (locked_fsm.state == LinkState::Active || locked_fsm.state == LinkState::RegisterAA)
    }

    /// Schedule a `Timeout` event to occur after the specified duration.
    ///
    /// Any existing timeout is canceled atomically.
    ///
    /// The timeout will also be canceled automatically and atomically at the next state change.
    ///
    /// The timeout may be cancelled manually using `LinkStateMachine::cancel_timeout()`.
    /// It will be cancelled atomically.
    #[allow(dead_code)]
    fn set_timeout(
        &self,
        asm: &Arc<Assembly>,
        locked_fsm: &mut std::sync::MutexGuard<'_, LinkStateMachine>,
        duration: std::time::Duration,
    ) {
        let link_id = self.id;
        let task_asm = asm.clone();
        locked_fsm.set_timeout_callback(duration, move |logical_clock| {
            if let Err(e) =
                task_asm.process_link_state_event(link_id, LinkEvent::Timeout { logical_clock })
            {
                error!(target: LINK_STATE, "error handling timeout: {e}");
            }
        });
    }

    /// Takes lock, returns copy of addresses.
    /// Will hang if you already have fsm lock!
    pub fn get_actor_addresses(&self) -> Vec<IpAddress> {
        let locked_fsm = self.locked_fsm.lock().unwrap();
        locked_fsm.actor_addresses.clone()
    }

    fn deregister_actor_addresses(&self, asm: &Arc<Assembly>) -> tokio::task::JoinSet<()> {
        let mut join_set = tokio::task::JoinSet::new();

        let vs_id = asm
            .peer_table
            .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);
        if vs_id.is_some() && vs_id.unwrap().get() == self.id {
            return join_set;
        }

        for addr in self.locked_fsm.lock().unwrap().actor_addresses.drain(..) {
            debug!(target: LINK_STATE, "Deregistering {addr}");
            join_set.spawn_local(visa_mgmt::actor_disconnect(asm.clone(), addr));
        }
        join_set
    }

    pub fn process_event(
        &self,
        asm: &Arc<Assembly>,
        event: LinkEvent,
    ) -> Result<(), LinkStateError> {
        debug!(target: LINK_STATE, "Link {}: *EVENT* {event:?}", self.id);

        // Enqueue a copy of this event with any concurrent listening state machines.
        // If there are none, avoid trying to do so we don't make a needless copy.
        let listened_for;
        if self.events.receiver_count() > 0 {
            match self.events.send(event.clone()) {
                Ok(n) => listened_for = n > 0,
                Err(_) => listened_for = false,
            }
        } else {
            listened_for = false;
        }

        match event {
            LinkEvent::Start => self.process_start(asm),
            LinkEvent::KeyingDone => self.process_keying_done(asm),
            LinkEvent::ReceivedHelloRequest(peer_zpr_addr) => {
                self.process_hello_request(asm, peer_zpr_addr)
            }
            LinkEvent::AssignedAAA(addr) => self.process_assigned_aaa(asm, addr),
            LinkEvent::ReceivedHelloResponse(code, aaa_addr, maybe_asa_addrs) => {
                self.process_hello_response(asm, code, aaa_addr, maybe_asa_addrs)
            }

            LinkEvent::SentHelloResponse => self.process_sent_hello_response(asm),

            LinkEvent::ReceivedAcquireZprAddressRequest(addrs, blob) => {
                self.process_acquire_zpr_address_request(asm, addrs, blob)
            }
            LinkEvent::ReceivedAcquireResponse(code) => self.process_acquire_response(asm, code),

            LinkEvent::ReceivedInitAuth((bootstrap_flag, challenge)) => {
                self.process_init_auth(asm, bootstrap_flag, challenge)
            }

            LinkEvent::ReceivedInitAuthResponse(code) => self.process_init_auth_response(asm, code),

            LinkEvent::ReceivedGrantZprAddressRequest(addrs) => {
                self.process_grant_zpr_address_request(asm, addrs)
            }
            LinkEvent::ReceivedGrantResponse(code) => self.process_grant_response(asm, code),

            LinkEvent::AuthenticationFailure => self.process_authentication_failure(asm),

            LinkEvent::AuthenticationSuccess(blob) => {
                self.process_authentication_success(asm, blob)
            }

            LinkEvent::ReceivedAuthorizeResponse => self.process_authorize_response(asm),

            LinkEvent::ReceivedTerminateRequest(code) => self.process_terminate_request(asm, code),
            LinkEvent::ReceivedTerminateResponse(_) => self.process_terminate_response(asm),
            LinkEvent::ReceivedTerminateIndication(code) => {
                self.process_terminate_indication(asm, code)
            }
            LinkEvent::SentTerminate => Ok(self.clean_up_link_state(asm).detach_all()),
            LinkEvent::ReceivedKeepAliveResponse => Err(LinkStateError::OperationNotSupportedYet),
            LinkEvent::Close(code) => self.initiate_close(asm, code),
            LinkEvent::CloseDone => Ok(self.complete_close(asm)),
            LinkEvent::Error => self.process_error_response(asm),
            LinkEvent::Timeout { logical_clock } => self.process_timeout(asm, logical_clock),

            ev => {
                if listened_for {
                    Ok(())
                } else {
                    Err(LinkStateError::UnexpectedTransition(
                        self.locked_fsm.lock().unwrap().state,
                        ev.into(),
                    ))
                }
            }
        }
    }

    /// Start an inactive link/tether
    /// Transitions from Inactive -> Keying
    /// Will trigger key management messages to be sent if this is an adapter
    fn process_start(&self, asm: &Assembly) -> Result<(), LinkStateError> {
        assert!(self.id != zpr::LINK_ID_UNKNOWN);
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if locked_fsm.state != LinkState::Inactive {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "Start",
            ));
        }

        locked_fsm.status = LinkStatus::Up;
        locked_fsm.set_state(LinkState::Keying);

        info!(target: LINK_STATE, "Link {link_id} started.  Keying in progress");

        match self.link_type {
            LinkType::AdapterToNode => {
                km_multiplexor::add_adapter_link(
                    asm,
                    link_id,
                    ZPIPair::new(zpr::ZPI_ENCRYPTED_HEADER_FLAG | 5, 6),
                    asm.self_noise_keypair.clone().unwrap(),
                    asm.peer_noise_keypair.clone().unwrap().public,
                    asm.certx.clone().unwrap(),
                )
                .unwrap();
                Ok(())
            }
            LinkType::NodeToNode => {
                error!(target: LINK_STATE, "Error: Node to node not supported yet");
                locked_fsm.set_state(LinkState::Error);
                Err(LinkStateError::OperationNotSupportedYet)
            }
            LinkType::NodeToAdapter => {
                km_multiplexor::add_node_link(
                    asm,
                    link_id,
                    ZPIPair::new(ZPI_ENCRYPTED_HEADER_FLAG | 3, 4),
                    asm.self_noise_keypair.clone().unwrap(),
                    asm.certx.clone().unwrap(),
                )
                .unwrap();
                Ok(())
            }
            LinkType::Internal => {
                error!(target: LINK_STATE, "Coding error: internal link state machine should not be controlled");
                Err(LinkStateError::InvalidOperation("coding error".into()))
            }
        }
    }

    /// The Key Manager sends in the [LinkEvent::KeyingDone] event when it is done with initial keying.
    /// Transitions from Keying -> Helloing
    /// Will trigger a Hello to be sent if this is an adapter
    fn process_keying_done(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if locked_fsm.state != LinkState::Keying {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "KeyingDone",
            ));
        }

        let Some(peer_state) = asm.peer_table.get(link_id) else {
            return Err(LinkStateError::NotFound(link_id));
        };

        let Some(sa) = peer_state.get_established_transport_association() else {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "KeyingDone when SA not established",
            ));
        };

        if let Some(ref peer_cert) = sa.peer_cert {
            info!(target: LINK_STATE, "Link {link_id} has name {:?}", peer_cert.subject_name());
            // assign special-peer name if this peer is special
            for name in
                special_peers::special_peer_names_from_x509_subject_name(peer_cert.subject_name())
            {
                match asm.peer_table.assign_special_name(name, link_id) {
                    Ok(()) => {
                        info!(target: LINK_STATE, "Link {link_id} assigned special name {name:?}")
                    }
                    Err(_) => {
                        warn!(target: LINK_STATE, "Unable to assign link {link_id} special name {name:?}")
                    }
                }
            }
        }

        debug!(target: LINK_STATE, "Link {link_id} finished keying.  Starting hello");

        locked_fsm.set_state(LinkState::Helloing);

        // IF this is an adapter, it's expected to issue the hello
        if self.link_type == LinkType::AdapterToNode {
            let _seqnum =
                mgmt::requests::send_hello_request(asm, self.id, &asm.local_zpr_addresses);
            self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_REQUEST_RETRY_TIMER);
            debug!(
                target: LINK_STATE,
                "Link {link_id} sent HelloRequest.  Waiting for other side to respond."
            );
        }
        // Otherwise we are a node so wait for an adapter to reach out
        Ok(())
    }

    /// Update link state based on received hello request
    /// Transitions from Helloing to Registering Actor Address
    /// Does not generate any packets
    fn process_hello_request(
        &self,
        _asm: &Arc<Assembly>,
        peer_zpr_addr: IpAddress,
    ) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        let link_id = self.id;
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToNode, LinkState::Helloing) => {
                locked_fsm.set_state(LinkState::Active);
                debug!(target: LINK_STATE, "Link {link_id} finished helloing.  Becoming active");
                Ok(())
            }
            (LinkType::NodeToAdapter, LinkState::Helloing) => {
                locked_fsm.actor_addresses.push(peer_zpr_addr);
                debug!(
                    target: LINK_STATE,
                    "Link {link_id} peer is using ZPR addr {}",
                    peer_zpr_addr
                );
                // State transition processing happens in [LinkStateWrapper::process_sent_hello_response]
                Ok(())
            }
            (LinkType::AdapterToNode, _) => {
                // Adapters should not be receiving these messages from nodes
                Err(LinkStateError::InvalidOperation(
                    "Discarded unsolicited Hello Request".to_string(),
                ))
            }
            (_, _) => Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedHelloRequest",
            )),
        }
    }

    /// This is called when we receive an AAA address assignment.
    /// Does not generate an error.
    fn process_assigned_aaa(
        &self,
        _asm: &Arc<Assembly>,
        aaa_addr: IpAddress,
    ) -> Result<(), LinkStateError> {
        // Just keep track of this for cleanup later.
        let link_id = self.id;
        debug!(target: LINK_STATE, "Link {link_id} assigned AAA address {aaa_addr}");
        let mut link_data = self.locked_data.lock().unwrap();
        link_data.aaa_address = Some(aaa_addr);
        Ok(())
    }

    fn process_sent_hello_response(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        let link_id = self.id;
        match (self.link_type, locked_fsm.state) {
            // Node->Adapter - we are in helloing state until we have fired off our
            // HelloResponse.  At that point we can send an init-auth request.
            (LinkType::NodeToAdapter, LinkState::Helloing) => {
                locked_fsm.set_state(LinkState::WaitForInitAuth);
                self.send_init_authentication_request(asm);
                self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_REQUEST_RETRY_TIMER);
                debug!(
                    target: LINK_STATE,
                    "Link {link_id} finished helloing.  Waiting for other side to respond to init-auth"
                );
                Ok(())
            }
            (LinkType::AdapterToNode, _) => {
                // Adapters should not be sending hello-response to a node.
                Err(LinkStateError::InvalidOperation(
                    "Adapter should not send hello-response".to_string(),
                ))
            }
            (_, _) => Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "SentHelloResponse",
            )),
        }
    }

    /// This is kicked off by [LinkEvent::ReceivedHelloResponse].
    /// That event may be generated when we have sent hello
    /// message ourselves [LinkStateWrapper::maybe_send_hello]
    ///
    /// Update link state based on received hello response
    /// Transitions from Helloing to Registering Actor Address
    /// Sends a Register Actor Address request if this is an adapter
    fn process_hello_response(
        &self,
        asm: &Arc<Assembly>,
        code: ResponseCode,
        aaa_addr: IpAddress,
        maybe_asa_addrs: Option<Vec<SocketAddr>>,
    ) -> Result<(), LinkStateError> {
        if code == ResponseCode::Other {
            // Received an error response.
            return self.process_error_response(&asm);
        }

        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        match (self.link_type, locked_fsm.state) {
            (LinkType::AdapterToNode, LinkState::Helloing) => {
                let mut link_data = self.locked_data.lock().unwrap();
                link_data.asa_addresses = maybe_asa_addrs.clone();

                // On the node side, the aaa_address link_data field is used to keep track of the
                // AAA we handed out to the peer.  On the client-adapter side, we hold the AAA
                // we got from the node in there.
                link_data.aaa_address = Some(aaa_addr);
                drop(link_data);

                // The adapter is waiting for an init-auth-request.
                locked_fsm.set_state(LinkState::WaitForInitAuth);
                debug!(
                    target: LINK_STATE,
                    "Link {link_id} finished helloing.  Now waiting for init auth."
                );
                drop(locked_fsm);
                Ok(())
            }
            (LinkType::NodeToNode, LinkState::Helloing) => {
                let mut link_data = self.locked_data.lock().unwrap();
                link_data.asa_addresses = maybe_asa_addrs.clone();
                drop(link_data);
                locked_fsm.set_state(LinkState::Active);
                debug!(target: LINK_STATE, "Link {link_id} finished helloing.  Becoming active");
                Ok(())
            }
            (LinkType::NodeToAdapter, _) => {
                // Nodes should not be receiving these messages from adapters
                Err(LinkStateError::InvalidOperation(
                    "Discarded unsolicited Hello Response".to_string(),
                ))
            }
            (_, _) => Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedHelloRespone",
            )),
        }
    }

    /// The ZprAddressRequest is from adapter to node (future: joining node to node).
    /// Includes authentication blob from sender, as well as the requested addresses.
    /// Inclusion of requested addresses is temporary.
    ///
    /// A Node expects this message from an adapter sometime after sending it an
    /// init-authentication message.
    ///
    /// This will call off to visa service for checking.
    /// Results comes back through a ReceivedAuthorizeResponse event.
    fn process_acquire_zpr_address_request(
        &self,
        asm: &Arc<Assembly>,
        addrs: Option<Vec<IpAddress>>,
        blob: String,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::WaitForAcquireZprAddress) => {}

            (_, _) => {
                return Err(LinkStateError::InvalidOperation(
                    "Discarded unsolicited acquire ZPR address request".to_string(),
                ))
            }
        }

        if addrs.is_none() {
            warn!(target: LINK_STATE, "Link {link_id} received acquire request with no addresses");
            drop(locked_fsm);
            return self.process_error_response(asm);
        }
        let addrs = addrs.unwrap();

        // TODO: For now there can be at most one address.
        if addrs.len() > 1 {
            warn!(target: LINK_STATE, "Link {link_id} received acquire request with multiple addresses");
            drop(locked_fsm);
            return self.process_error_response(asm);
        }
        let requested_addr = addrs[0];

        // We probably already know the address from hello.
        // I'm assuming we won't be acquiring more ZPR addresses for this one peer so
        // we will override the old one with this one.
        locked_fsm.actor_addresses.clear();
        locked_fsm.actor_addresses.push(requested_addr);
        debug!(
            target: LINK_STATE,
            "Link {link_id} received acquire addr request for actor ({requested_addr})."
        );

        // A self-signed blob needs to be checked before we forward it on.

        let Ok(d_blob) = auth::decode_blob(&blob) else {
            warn!(target: LINK_STATE, "Link {link_id} received acquire request with invalid blob");
            drop(locked_fsm);
            return self.process_error_response(asm);
        };

        match d_blob {
            DecodedBlob::AuthCode(_) => {}
            DecodedBlob::SelfSigned(ss_blob) => {
                if !self.check_self_signed_blob(asm, link_id, &ss_blob) {
                    drop(locked_fsm);
                    return self.process_error_response(asm);
                }
            }
        }

        locked_fsm.set_state(LinkState::RegisterAA);

        // Now we have verified our part of the blob, we can send to the visa service for checking the signature.
        match visa_mgmt::build_connect_request(asm, link_id, requested_addr, &blob) {
            Ok(Some(conn_req)) => {
                drop(locked_fsm);
                Ok(visa_mgmt::authorize_connect(asm, link_id, conn_req))
            }

            Ok(None) => {
                debug!(target: LINK_STATE, "skipping visa service authorize call, authorizing ourselves");

                // Need to send a grant here anyway to "turn on" the adapter (and outselves)
                // So pretend we are the visa service and handle our own authorization.
                drop(locked_fsm);

                if let Err(e) =
                    asm.process_link_state_event(link_id, LinkEvent::ReceivedAuthorizeResponse)
                {
                    error!(target: LINK_STATE, "Link {link_id} failed to process authorize response: {e}");
                }

                Ok(())
            }

            Err(e) => Err(e),
        }
    }

    fn check_self_signed_blob(
        &self,
        asm: &Arc<Assembly>,
        link_id: LinkId,
        ss_blob: &ZdpSelfSignedBlob,
    ) -> bool {
        // Now check that the CN in the presented blob matches the CN the peer used to establish link.
        let Some(peer_state) = asm.peer_table.get(link_id) else {
            warn!(target: LINK_STATE, "Link {link_id} blob check failed: cannot find peer state entry");
            return false;
        };
        let Some(sa) = peer_state.get_established_transport_association() else {
            warn!(target: LINK_STATE, "Link {link_id} blob check failed: cannot find SA");
            return false;
        };
        let Some(ref peer_cert) = sa.peer_cert else {
            warn!(target: LINK_STATE, "Link {link_id} no peer cert found, cannot validate blob");
            return false;
        };
        let key = asm.peer_table.inspect(link_id, {
            |peer| {
                let mut key = [0u8; AUTH_KEY_SIZE_BYTES];
                key[0..AUTH_KEY_SIZE_BYTES].copy_from_slice(&peer.auth_key[0..AUTH_KEY_SIZE_BYTES]);
                key
            }
        });
        if key.is_none() {
            warn!(target: LINK_STATE, "Link {link_id} received acquire request but have no auth key");
            return false;
        }
        let key = key.unwrap();

        if let Err(e) = ss_blob.verify_blob_challenge(peer_cert, &key) {
            warn!(target: LINK_STATE, "Link {link_id} challenge verification failed: {e}");
            return false;
        }
        true
    }

    /// AcquireResponse is sent from a node to the adapter after adapter sends
    /// in the acquire zpr address message (which is essentially an auth message).
    /// The ACK of this means we are now waiting for a Grant message.
    ///
    /// No state change. No messages.
    fn process_acquire_response(
        &self,
        _asm: &Arc<Assembly>,
        code: ResponseCode,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::AdapterToNode, LinkState::RegisterAA) => {
                debug!(target: LINK_STATE, "link {link_id} acquire ZDP address response (ACK) message received, code {:?}", code);
                Ok(())
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited acquire zpr address response".to_string(),
            )),
        }
    }

    /// A grant response is just an ACK of a ZPR address grant message.
    /// For now only expected from an adapter to a a node.
    /// If status is OK means the link is addressed and up on sender side.
    fn process_grant_response(
        &self,
        asm: &Arc<Assembly>,
        code: ResponseCode,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::RegisterAA) => {
                if code == ResponseCode::Success {
                    locked_fsm.set_state(LinkState::Active);
                    debug!(target: LINK_STATE, "Link {link_id} has ACKd the grant.  Becoming active");
                    drop(locked_fsm);
                    self.run_active(&asm)
                } else {
                    warn!(target: LINK_STATE, "Link {link_id} did not ACK the grant. Shutting down");
                    locked_fsm.set_state(LinkState::Error);
                    drop(locked_fsm);
                    self.initiate_close(asm, TerminateReason::Other)
                }
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited grant response".to_string(),
            )),
        }
    }

    /// Grant ZPR Address message is from a node to an adapter and includes the
    /// result of authentication verification.
    ///
    /// If this inidicates success it will include the ZPR addresses we are
    /// supposed to use.  If this indicates failure we should tear down the link.
    ///
    /// Currently we tell the node what address we want so these should be no
    /// suprise and are actually already set.
    ///
    /// `addrs` has granted address on success, None on failure.
    fn process_grant_zpr_address_request(
        &self,
        asm: &Arc<Assembly>,
        addrs: Option<Vec<IpAddress>>,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::AdapterToNode, LinkState::RegisterAA) => {
                match addrs {
                    Some(addrs) => {
                        // TODO: In future we will take addresses from here and configure TUN.
                        info!(target: LINK_STATE, "Link {link_id} granted ZPR addresses {:?}, becoming ACTIVE", addrs);
                        locked_fsm.set_state(LinkState::Active);
                        asm.tun_ctl.set_carrier(true).unwrap();
                        debug!(
                            target: LINK_STATE,
                            "Link {link_id} finished registering actor address: becoming active"
                        );
                        drop(locked_fsm);
                        self.run_active(asm)
                    }
                    None => {
                        // Grant failed.
                        warn!(target: LINK_STATE, "Link {link_id} failed to be granted ZPR address");
                        locked_fsm.set_state(LinkState::Error);
                        drop(locked_fsm);
                        self.initiate_close(asm, TerminateReason::Other)
                    }
                }
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited Grant Zpr Address request".to_string(),
            )),
        }
    }

    /// This is the event handler fro the return path from the visa service AUTHORIZE operation.
    /// This needs to trigger sending of the Grant Address message.
    ///
    /// TODO: At some point this will need the ZPR address returned to it also.  For now we
    /// use the address we saved in our state (from the original request).
    ///
    fn process_authorize_response(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::RegisterAA) => {} // ok
            (_, _) => {
                return Err(LinkStateError::InvalidOperation(
                    "Discarded unsolicited authorize response".to_string(),
                ))
            }
        }

        // Send a Grant message, consume the response and then send in an event
        // indicating we got it (ReceivedGrantResponse).

        // Will call back via ReceivedGrantResponse event if successful.
        self.send_grant_zpr_address_request(asm, &locked_fsm.actor_addresses);
        self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_REQUEST_RETRY_TIMER);
        Ok(())
    }

    /// Handle an init-auth message from sender.
    ///
    /// This is a slow function that is called AFTER we send a reply to the
    /// init-auth message.
    ///
    /// If this is bootstrap and we are configured for bootstrap we can self-authenticate
    /// and send in an AcquireZprAddressRequest.
    ///
    /// For now we must be in WaitForInitAuth to accept this message.
    /// We transition to RegisterAA if we successfully self-auth, otherwise we go to
    /// error and shutdown the link.
    fn process_init_auth(
        &self,
        asm: &Arc<Assembly>,
        bootstrap: bool,
        challenge: Option<auth::ZdpInitAuthenticationPayload>,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;

        // Grab a copy of our ASA, AAA addresses.
        let data = self.locked_data.lock().unwrap();
        let asa_addrs = data.asa_addresses.clone();
        let aaa_addr = data.aaa_address.clone();
        drop(data);

        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            // NOTE: This is not exactly right, in general we can get an InitAuth at any time, though we
            // may not want to act on it and sometimes may be a protocol error.
            (LinkType::AdapterToNode, LinkState::WaitForInitAuth) => {
                debug!(target: LINK_STATE, "Link {link_id} received init auth.");

                // If we can do bootstrap and it is allowed, then do that.
                if bootstrap && asm.bsauth.is_some() {
                    if challenge.is_none() {
                        error!(target: LINK_STATE, "Link {link_id} received init auth with no challenge");
                        locked_fsm.set_state(LinkState::Error);
                        drop(locked_fsm);
                        return self.initiate_close(asm, TerminateReason::Other);
                    }
                    let challenge = challenge.unwrap();
                    if let Some(bs) = asm.bsauth.as_ref() {
                        match bs.authenticate(&challenge) {
                            Ok(blobstr) => {
                                // The send function below will invoke a state event callback.
                                // We staty in RegisterAA state until we get a grant.
                                self.send_acquire_zpr_address_request(asm, &blobstr);
                                locked_fsm.set_state(LinkState::RegisterAA);
                                locked_fsm.auth_blob = Some(blobstr);
                                self.set_timeout(
                                    asm,
                                    &mut locked_fsm,
                                    config::DEFAULT_REQUEST_RETRY_TIMER,
                                );
                            }
                            Err(e) => {
                                error!(target: LINK_STATE, "Link {link_id} failed to self-authenticate: {e:?}");
                                // Shutdown the link
                                locked_fsm.set_state(LinkState::Error);
                                drop(locked_fsm);
                                return self.initiate_close(asm, TerminateReason::Other);
                            }
                        }
                    }
                } else {
                    // Bootstrap not allowed or not configured.
                    locked_fsm.set_state(LinkState::RegisterAA);
                    info!(target: LINK_STATE, "Link {link_id} received init auth, time to talk to authentication service");

                    // TODO: We get the ZPR address of the auth services from our node. What about the cert?
                    if asm.rsauth.is_some() && asa_addrs.is_some() {
                        drop(locked_fsm);

                        // If we have not configured our TUN interface with our AAA address or if the
                        // TUN has the wrong address on it, we fix that up now.
                        //
                        // TODO: If we are re-authenticating would we need to use an AAA address? We would already
                        //       have a ZPR address.

                        panic!("TODO - configure or check configuration of TUN now!");

                        self.do_https_authenticate(asm, asa_addrs.unwrap());
                    } else {
                        error!(target: LINK_STATE, "Link {link_id} no auth service configured");
                        locked_fsm.set_state(LinkState::Error);
                        drop(locked_fsm);
                        return self.initiate_close(asm, TerminateReason::Other);
                    }
                }
            }
            (_, _) => {
                return Err(LinkStateError::UnexpectedTransition(
                    locked_fsm.state,
                    "ReceivedInitAuth",
                ));
            }
        }

        Ok(())
    }

    /// The node sends init-authentication to the adapter, the response only serves to
    /// clear our retry timer.  The adapter will in the meantime take care of doing
    /// whatever authentication it needs to and will eventually send us an acquire-zpr-address
    /// message with the authentication results (blob).
    fn process_init_auth_response(
        &self,
        asm: &Arc<Assembly>,
        response_code: ResponseCode,
    ) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::WaitForInitAuth) => {
                debug!(target: LINK_STATE, "Link {} received init auth response with code {:?}", self.id, response_code);
                if response_code == ResponseCode::Success {
                    locked_fsm.set_state(LinkState::WaitForAcquireZprAddress);
                    // In this state we are waiting on the adapter to perform authentication and
                    // that may involve external services and could be quite slow relative to a
                    // straightforward ZDP response.  So, we set a longer timeout.  We do not retransmit
                    // anything... if we do not get auth within a reasonable amount of time we shut down
                    // the link.
                    self.set_timeout(asm, &mut locked_fsm, config::ACTOR_AUTHENTICATION_TIMEOUT);
                    Ok(())
                } else {
                    error!(target: LINK_STATE, "Link {} received init auth response with non-success response {:?}", self.id, response_code);
                    drop(locked_fsm);
                    self.initiate_close(asm, TerminateReason::Other)
                }
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited init auth response".to_string(),
            )),
        }
    }

    /// Send off the Inti-Authentication message with a blob that the receiver could
    /// use for authentication.
    fn send_init_authentication_request(&self, asm: &Arc<Assembly>) {
        let link_id = self.id;

        // TODO: Whether or not we are in bootstrap mode comes from visa service.  For now hardcoded ON.
        let is_bootstrap = true;

        let payload: auth::ZdpInitAuthenticationPayload;
        let mut flags = 0u8;

        if is_bootstrap {
            flags |= zdp::init_authentication_flags::BOOTSTRAP_SUPPORT;

            // TODO: Pretty sure I do not need `inspect_sync` below. The key is set at create time and not changed.
            let key = asm.peer_table.inspect(link_id, {
                |peer| {
                    let mut key = [0u8; auth::AUTH_KEY_SIZE_BYTES];
                    key[0..auth::AUTH_KEY_SIZE_BYTES]
                        .copy_from_slice(&peer.auth_key[0..auth::AUTH_KEY_SIZE_BYTES]);
                    key
                }
            });
            match key {
                Some(key) => payload = auth::ZdpInitAuthenticationPayload::new(&key),
                None => {
                    // TODO: Possibly we want to send the Init Authentication message anyway, but
                    //       just not support bootstrap mode.
                    error!(target: LINK_STATE, "unable to send Init Authentication: no auth key found for link {link_id}");
                    if let Err(e) = asm.process_link_state_event(link_id, LinkEvent::Error) {
                        error!(target: LINK_STATE, "event handling error: {e}");
                    }
                    return;
                }
            }
        } else {
            payload = auth::ZdpInitAuthenticationPayload::default(); // empty
        }

        mgmt::requests::send_init_authentication_request(asm, link_id, flags, payload);
    }

    /// Send the Grant message
    fn send_grant_zpr_address_request(&self, asm: &Arc<Assembly>, addrs: &[IpAddress]) {
        // Convert the IpAddresses into IpAddrs
        let ipaddrs = addrs
            .iter()
            .map(|addr| IpAddr::from(addr))
            .collect::<Vec<_>>();

        mgmt::requests::send_grant_zpr_address_request(
            asm,
            self.id,
            ResponseCode::Success,
            &ipaddrs,
        );
    }

    /// Run the HTTPS authentication process in a tokio task.
    /// - [LinkEvent::AuthenticationSuccess] on success
    /// - [LinkEvent::AuthenticationFailure] on failure
    ///
    /// TODO: Figure out what it means if there are multiple ASA addresses.
    /// For now this uses the first address in the list.
    fn do_https_authenticate(&self, asm: &Arc<Assembly>, asa_addrs: Vec<SocketAddr>) {
        let link_id = self.id;

        if asa_addrs.is_empty() {
            error!(target: LINK_STATE, "Link {link_id}: no ASA addresses provided for authentication");
            if let Err(e) = asm.process_link_state_event(link_id, LinkEvent::AuthenticationFailure)
            {
                error!(target: LINK_STATE, "Link {link_id}: event handling error {e}");
            }
            return;
        }
        let service_addr = asa_addrs[0];

        let tls_cert = X509::from_pem(auth::HARD_CODED_BAS_TLS_CERT_PEM.as_bytes()).unwrap();
        let task_asm = asm.clone();

        tokio::task::spawn_local(async move {
            let Some(rsauth) = task_asm.rsauth.as_ref() else {
                error!(target: LINK_STATE, "Link {link_id}: auth requested but no auth service configured");
                if let Err(e) =
                    task_asm.process_link_state_event(link_id, LinkEvent::AuthenticationFailure)
                {
                    error!(target: LINK_STATE, "Link {link_id}: event handling error {e}");
                }
                return;
            };

            let event = match rsauth.authenticate(service_addr, tls_cert).await {
                Ok(blob) => LinkEvent::AuthenticationSuccess(blob),
                // TODO: Handler of the event needs to do this
                // self.send_acquire_zpr_address_request(asm, &blob.encode());
                Err(e) => {
                    error!(target: LINK_STATE, "Link {link_id} failed to authenticate with auth service: {e:?}");
                    LinkEvent::AuthenticationFailure
                }
            };
            if let Err(e) = task_asm.process_link_state_event(link_id, event) {
                error!(target: LINK_STATE, "Link {link_id}: event handling error {e}");
            }
        });
    }

    /// Callback via the AuthenticationFailure event.
    fn process_authentication_failure(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        locked_fsm.set_state(LinkState::Error);
        drop(locked_fsm);
        info!(target: LINK_STATE, "Link {link_id} authentication failed");
        self.initiate_close(asm, TerminateReason::Other)
    }

    /// Callback via the AuthenticationSuccess event.
    ///
    /// We exepect to be in the RegisterAA state.
    ///
    /// TODO: Should we have a state to represent waiting-for-authentication?
    fn process_authentication_success(
        &self,
        asm: &Arc<Assembly>,
        blob: ZdpAuthCodeBlob,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        if locked_fsm.state != LinkState::RegisterAA {
            error!(
                "Link {link_id} authentication success ignored in unexpected state {:?}",
                locked_fsm.state
            );
            return Ok(());
        }

        info!(target: LINK_STATE, "Link {link_id}: authentication success, client_id={}", blob.client_id);
        let blobstr = blob.encode();
        self.send_acquire_zpr_address_request(asm, &blobstr);
        locked_fsm.auth_blob = Some(blobstr);
        self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_REQUEST_RETRY_TIMER);
        Ok(())
    }

    /// Send Acquire message
    fn send_acquire_zpr_address_request(&self, asm: &Arc<Assembly>, blob: &str) {
        mgmt::requests::send_acquire_zpr_address_request(
            asm,
            self.id,
            &asm.local_zpr_addresses,
            Some(blob.as_bytes()),
        );
    }

    fn process_error_response(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        asm.counters[CounterType::PeerHandshakeFailure].increment();
        warn!(target: LINK_STATE, "Link {link_id} bringup failed at state {:?}",
            self.locked_fsm.lock().unwrap().state);

        self.initiate_close(&asm, TerminateReason::Other)
    }

    fn process_timeout(
        &self,
        asm: &Arc<Assembly>,
        logical_clock: u64,
    ) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if logical_clock != locked_fsm.logical_clock {
            // timeout was for some earlier state & we won the task abort race; ignore
            return Ok(());
        }

        // handle the timeout...
        match (self.link_type, locked_fsm.state) {
            // all these states use timeout simply for retransmits
            (LinkType::AdapterToNode, LinkState::RegisterAA)
            | (LinkType::NodeToAdapter, LinkState::RegisterAA)
            | (LinkType::NodeToAdapter, LinkState::WaitForInitAuth)
            | (LinkType::AdapterToNode, LinkState::Helloing) => {
                locked_fsm.timeout_count += 1;

                if locked_fsm.timeout_count >= config::DEFAULT_REQUEST_RETRY_COUNT {
                    error!(target: LINK_STATE, "Link {} timed out in state {:?}", self.id, locked_fsm.state);
                    drop(locked_fsm);
                    return self.process_error_response(&asm);
                }

                warn!(target: LINK_STATE, "Link {} timed out in state {:?}, retransmitting", self.id, locked_fsm.state);
                self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_REQUEST_RETRY_TIMER);
                self.retransmit(asm, &mut locked_fsm);
                Ok(())
            }

            (LinkType::NodeToAdapter, LinkState::WaitForAcquireZprAddress) => {
                // This is a timeout while waiting for the adapter to authenticate.
                // Timeout here means we give up on the link.
                error!(target: LINK_STATE, "Link {} timed out in state {:?}", self.id, locked_fsm.state);
                drop(locked_fsm);
                return self.process_error_response(&asm);
            }

            (_, LinkState::Closing) => {
                // This is a timeout while we are waiting for a terminate response post initiate close.
                // Now we finish the job,
                debug!(target: LINK_STATE, "Link {} received timeout waiting on terminate response, shutting down link", self.id);
                drop(locked_fsm);
                self.clean_up_link_state(asm).detach_all();
                Ok(())
            }

            (_, _) => Err(LinkStateError::InvalidOperation(format!(
                "Ignoring unexpected timeout in state {:?}",
                locked_fsm.state
            ))),
        }
    }

    /// Invoked due to a state transition timeout while waiting for a reply; retransmits the associated request.
    fn retransmit(
        &self,
        asm: &Arc<Assembly>,
        locked_fsm: &mut std::sync::MutexGuard<'_, LinkStateMachine>,
    ) {
        match (self.link_type, locked_fsm.state) {
            (LinkType::AdapterToNode, LinkState::RegisterAA) => {
                self.send_acquire_zpr_address_request(asm, &locked_fsm.auth_blob.as_ref().unwrap())
            }

            (LinkType::NodeToAdapter, LinkState::RegisterAA) => {
                self.send_grant_zpr_address_request(asm, &locked_fsm.actor_addresses)
            }

            (LinkType::NodeToAdapter, LinkState::WaitForInitAuth) => {
                self.send_init_authentication_request(asm)
            }

            (LinkType::AdapterToNode, LinkState::Helloing) => {
                mgmt::requests::send_hello_request(asm, self.id, &asm.local_zpr_addresses);
            }

            // Programming error!
            (_, _) => panic!(
                "call to retransmit in state {:?} but not implemented",
                locked_fsm.state
            ),
        }
    }

    /// Validate a received shutdown request
    /// Does not transition
    /// Generates no packets
    fn process_terminate_request(
        &self,
        _asm: &Assembly,
        reason: TerminateReason,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        info!(target: LINK_STATE,
            "Received shutdown request on link {link_id} for reason {reason:?}"
        );
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if locked_fsm.state == LinkState::Inactive {
            Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedTerminateRequest",
            ))
        } else {
            locked_fsm.set_state(LinkState::Closing);
            Ok(())
        }
    }

    /// Initiate the shutdown of the link
    /// Transitions to Closing from any running state
    /// Generates a Terminate Request packet
    /// Sets a timeout in case we do not get a terminate response.
    fn initiate_close(
        &self,
        asm: &Arc<Assembly>,
        reason: TerminateReason,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        info!(target: LINK_STATE,"Initiating shutdown on link {link_id}");

        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        locked_fsm.set_state(LinkState::Closing);
        self.set_timeout(
            asm,
            &mut locked_fsm,
            config::DEFAULT_TERMINATE_RESPONSE_TIMER,
        );
        mgmt::requests::send_terminate_request(asm, self.id, reason);
        Ok(())
    }

    /// Tear down link state.
    /// This sends notice to the visa service that we have lost an actor.
    /// Sends a CloseDone event (which triggers [LinkStateWrapper::complete_close])
    fn clean_up_link_state(&self, asm: &Arc<Assembly>) -> tokio::task::JoinSet<()> {
        let link_id = self.id;
        let mut join_set = tokio::task::JoinSet::new();
        info!(target: LINK_STATE, "Link {link_id} is clearing its state");

        let mut link_data = self.locked_data.lock().unwrap();
        if let Some(aaa_addr) = link_data.aaa_address.take() {
            if let Some(pool) = asm.address_pool.lock().unwrap().as_mut() {
                match pool.release_address(aaa_addr) {
                    Ok(_) => {
                        debug!(target: LINK_STATE, "Link {link_id} released AAA address {aaa_addr}")
                    }
                    Err(e) => {
                        error!(target: LINK_STATE, "Failed to release AAA address {aaa_addr}: {e:?}")
                    }
                };
            }
        }

        asm.peer_table.clear_peer_state(link_id);

        match self.link_type {
            LinkType::AdapterToNode => asm.tun_ctl.set_carrier(false).unwrap(),
            LinkType::NodeToAdapter => join_set = self.deregister_actor_addresses(asm),
            _ => {}
        }

        let task_asm = asm.clone();
        join_set.spawn_local(async move {
            // NOTE: Any mgmt messages MUST have been sent before this is called
            km_multiplexor::drop_link(&task_asm, link_id).await;

            if let Err(e) = task_asm.process_link_state_event(link_id, LinkEvent::CloseDone) {
                error!(target: LINK_STATE, "Error shutting down link {link_id}: {e:?}");
            }
        });
        join_set
    }

    /// Complete a link shutdown, upon receiving a terminate request or response
    /// Transitions from Closing to Inactive
    /// Generates no packets
    fn complete_close(&self, asm: &Arc<Assembly>) {
        let link_id = self.id;
        info!(target: LINK_STATE, "Shutting down link {link_id}");
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        match (locked_fsm.state, self.link_type) {
            (LinkState::Closing, LinkType::NodeToAdapter) | (LinkState::Resetting, _) => {
                // Clear whole peer out
                drop(locked_fsm);
                asm.drop_peer(link_id);
                return;
            }
            (LinkState::Closing, _) => {
                locked_fsm.silent = false;
                locked_fsm.set_state(LinkState::Inactive);
                info!("Link {link_id} has fully shut down");
                drop(locked_fsm);
                self.setup_restart(asm);
            }
            _ => {
                error!(
                    "Link {link_id} tried to close from state {:?}",
                    locked_fsm.state
                );
            }
        }
    }

    /// Set a timer to attempt a link restart after a holddown period
    fn setup_restart(&self, asm: &Arc<Assembly>) {
        // TODO: use timeout mechanism
        let link_id = self.id;
        let task_asm = asm.clone();
        tokio::task::spawn_local(async move {
            tokio::time::sleep(config::DEFAULT_LINK_RESTART_HOLDDOWN).await;
            info!(target: LINK_STATE, "Attempting to restart link {link_id}");
            let _ = task_asm.process_link_state_event(link_id, LinkEvent::Start);
        });
    }

    /// Reset the link, shutting it down and wiping its configuration
    /// Instead of transitioning, the state machine will be destroyed
    /// Sends a Terminate Indication
    pub async fn reset(&self, asm: &Arc<Assembly>) {
        let link_id = self.id;
        info!(target: LINK_STATE,
            "Resetting link {link_id} from state {:?}",
            self.locked_fsm.lock().unwrap().state
        );
        self.locked_fsm
            .lock()
            .unwrap()
            .set_state(LinkState::Resetting);
        mgmt::requests::send_terminate_indication(asm, link_id, TerminateReason::Reset);
        let _ = self.clean_up_link_state(asm).join_all().await;
    }

    /// Handle a terminate response packet
    fn process_terminate_response(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        info!(target: LINK_STATE,"Received terminate response for link {link_id}");
        let state = self.locked_fsm.lock().unwrap().state;
        match state {
            LinkState::Closing => {
                self.clean_up_link_state(asm).detach_all();
                Ok(())
            }
            _ => Err(LinkStateError::UnexpectedTransition(
                state,
                "ReceivedTerminateResponse",
            )),
        }
    }

    fn process_terminate_indication(
        &self,
        asm: &Arc<Assembly>,
        reason: TerminateReason,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        info!(target: LINK_STATE,
            "Received terminate indication for link {link_id} with reason {reason:?}"
        );
        self.locked_fsm
            .lock()
            .unwrap()
            .set_state(LinkState::Closing);
        self.clean_up_link_state(asm).detach_all();
        Ok(())
    }

    pub fn run_active(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let task_asm = asm.clone();
        let task_events = self.events.clone();
        asm.counters[CounterType::PeerHandshakeSuccess].increment();
        debug!(target: LINK_STATE, "Link {link_id} entering active state");
        tokio::task::spawn_local(async move {
            let mut interval = tokio::time::interval(config::DEFAULT_KEEP_ALIVE_PERIOD);
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            let mut consecutive_misses = 0;
            while task_asm.is_link_ready(link_id) {
                interval.tick().await;
                let start_time = Instant::now();
                let Some(peer) = task_asm.peer_table.get(link_id) else {
                    return;
                };
                if peer.link_state_machine.locked_fsm.lock().unwrap().state != LinkState::Active {
                    return;
                }

                let mut recv = task_events.subscribe();

                let sent_seq_num = mgmt::requests::send_echo_request(&task_asm, link_id);
                let expected_seq_num = (sent_seq_num & 0xffff) as u16;

                let got_response =
                    tokio::time::timeout(config::DEFAULT_REQUEST_RETRY_TIMER,
                        async {
                            loop {
                                match recv.recv().await {
                                    Ok(LinkEvent::ReceivedEchoResponse { sequence_number: recvd_seq_num }) => {
                                        if recvd_seq_num == expected_seq_num {
                                            break true;
                                        } else {
                                            debug!(target: LINK_STATE, "Link {link_id} saw echo response {recvd_seq_num} while waiting for {expected_seq_num}");
                                        }
                                    }

                                    Ok(_) => (),

                                    Err(broadcast::error::RecvError::Lagged(_)) => {
                                        debug!(target: LINK_STATE, "Link {link_id} lagged waiting for echo response (unexpected)");
                                    }

                                    Err(broadcast::error::RecvError::Closed) => {
                                        break false;  // we'll exit next time through the loop
                                    }
                                }
                            }
                        }).await.unwrap_or(false);

                drop(recv);

                let mut link_data = peer.link_state_machine.locked_data.lock().unwrap();

                if got_response {
                    link_data.echo_success += 1;
                    link_data
                        .latency_data
                        .add(Instant::now().duration_since(start_time));
                    consecutive_misses = 0;
                } else {
                    link_data.echo_timeout += 1;
                    consecutive_misses += 1;
                }

                drop(link_data);

                if consecutive_misses >= config::DEFAULT_KEEP_ALIVE_RETRIES {
                    if task_asm
                        .process_link_state_event(
                            link_id,
                            LinkEvent::Close(TerminateReason::RequestTimedOut),
                        )
                        .is_err()
                    {
                        error!(target: LINK_STATE, "Failed to shut down link after missed keepalives");
                    }
                    return;
                }
            }
        });
        Ok(())
    }
}

impl Display for LinkStateWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // FIXME: This doesn't print link ID because the caller is printing link ID
        // followed by substrate addr, which is out of scope for this display function
        write!(f, "  Type: {:?}\n", self.link_type)?;

        write!(f, "{}", self.locked_fsm.lock().unwrap())?;
        if self.get_state() == LinkState::Active {
            write!(f, "{}", self.locked_data.lock().unwrap())?;
        }
        Ok(())
    }
}

impl Display for LinkStateMachine {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.actor_addresses.is_empty() {
            write!(f, "  Actor Addresses: None\n")?;
        } else {
            write!(f, "  Actor Addresses: [ {}", self.actor_addresses[0])?;
            for addr in &self.actor_addresses[1..self.actor_addresses.len()] {
                write!(f, ", {}", addr)?;
            }
            write!(f, " ]\n")?;
        }

        // TODO: Format time since last state change better
        write!(
            f,
            "  State: {:?} (for {:?})\n",
            self.state,
            Instant::now().duration_since(self.last_state_change)
        )?;
        write!(f, "  Status: {:?}\n", self.status)
    }
}

impl Display for LinkData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let (total, count) = self.latency_data.get_total_and_count();
        let average = if count > 0 {
            total.div_f64(count as f64)
        } else {
            Duration::ZERO
        };

        write!(f, "  Echo stats:\n")?;
        write!(f, "    Successes: {}\n", self.echo_success)?;
        write!(f, "    Timeouts: {}\n", self.echo_timeout)?;
        write!(
            f,
            "    Latency: Min {:?}, Max {:?}, Avg {average:?}\n",
            self.latency_data.get_min(),
            self.latency_data.get_max(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{LinkState, LinkStateMachine};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::oneshot;

    #[tokio::test(start_paused = true)]
    async fn timeout_test() {
        let sm = Arc::new(Mutex::new(LinkStateMachine::new(1)));
        let (tx, rx) = oneshot::channel();

        set_timeout(&sm, Duration::from_secs(5), tx);

        tokio::time::sleep(Duration::from_secs(4)).await;

        assert!(rx.is_empty());

        tokio::time::sleep(Duration::from_secs(2)).await;

        assert!(rx.await.is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_explicit_cancel_test() {
        let sm = Arc::new(Mutex::new(LinkStateMachine::new(1)));
        let (tx, rx) = oneshot::channel();

        set_timeout(&sm, Duration::from_secs(5), tx);

        tokio::time::sleep(Duration::from_secs(4)).await;

        sm.lock().unwrap().cancel_timeout();

        tokio::time::sleep(Duration::from_secs(2)).await;

        assert!(rx.await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_implicit_cancel_test() {
        let sm = Arc::new(Mutex::new(LinkStateMachine::new(1)));
        let (tx, rx) = oneshot::channel();

        set_timeout(&sm, Duration::from_secs(5), tx);

        tokio::time::sleep(Duration::from_secs(4)).await;

        sm.lock().unwrap().set_state(LinkState::Keying);

        tokio::time::sleep(Duration::from_secs(2)).await;

        assert!(rx.await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_reschedule_test() {
        let sm = Arc::new(Mutex::new(LinkStateMachine::new(1)));
        let (tx1, rx1) = oneshot::channel();
        let (tx2, rx2) = oneshot::channel();

        set_timeout(&sm, Duration::from_secs(5), tx1);

        tokio::time::sleep(Duration::from_secs(4)).await;

        set_timeout(&sm, Duration::from_secs(5), tx2);

        tokio::time::sleep(Duration::from_secs(4)).await;

        assert!(rx1.await.is_err());
        assert!(rx2.is_empty());

        tokio::time::sleep(Duration::from_secs(2)).await;

        assert!(rx2.await.is_ok());
    }

    fn set_timeout(sm: &Arc<Mutex<LinkStateMachine>>, duration: Duration, tx: oneshot::Sender<()>) {
        let sm_cb = sm.clone();
        sm.lock()
            .unwrap()
            .set_timeout_callback(duration, move |lc| {
                if sm_cb.lock().unwrap().logical_clock != lc {
                    return;
                }
                tx.send(()).unwrap();
            });
    }
}
