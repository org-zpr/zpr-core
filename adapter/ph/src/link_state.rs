use crate::assembly::Assembly;
use crate::config;
use crate::counters::CounterType;
use crate::km::ZPIPair;
use crate::km_multiplexor;
use crate::logging::targets::LINK_STATE;
use crate::mgmt;
use crate::mgmt::core::SyncReqError;
use crate::net_defs::IpAddress;
use crate::sample_ring::SampleRing;
use crate::special_peers;
use crate::special_peers::SpecialPeerName;
use crate::visa_mgmt;
use crate::zdp::{ResponseCode, TerminateReason};

use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::time::MissedTickBehavior;
use tracing::*;
use zpr::LinkId;
use zpr::ZPI_ENCRYPTED_HEADER_FLAG;

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
    RegisterAA,
    Error,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum LinkEvent {
    Start,
    KeyingDone,
    ReceivedHelloRequest,
    ReceivedHelloResponse(ResponseCode),
    ReceivedRegisterRequest(IpAddress),
    ReceivedRegisterResponse(ResponseCode),
    ReceivedAuthorizeResponse,
    ReceivedKeepAliveResponse,
    ReceivedTerminateRequest(TerminateReason),
    ReceivedTerminateResponse(ResponseCode),
    ReceivedTerminateIndication(TerminateReason),
    SentTerminate,
    Close(TerminateReason),
    CloseDone,
    Error,
}

#[derive(Error, Debug)]
pub enum LinkStateError {
    #[error("Got unexpected event {1} on state {0:?}")]
    UnexpectedTransition(LinkState, String),
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

pub struct LinkData {
    echo_success: u64, // Echo requests received response
    echo_timeout: u64, // Echo requests timed out
    echo_failure: u64, // Echo requests failed for other reasons
    // TODO: configurable keep-alive period
    // For now, keep-alives are attempted every 3 seconds
    // Assuming no loss, 100 samples will store 5 minutes of latency data
    latency_data: SampleRing<Duration, 100>,
}

impl LinkData {
    pub fn new() -> Self {
        Self {
            echo_success: 0,
            echo_timeout: 0,
            echo_failure: 0,
            latency_data: SampleRing::new(Duration::ZERO),
        }
    }
}

pub struct LinkStateMachine {
    state: LinkState,
    status: LinkStatus,
    silent: bool,
    actor_addresses: Vec<IpAddress>,
    last_state_change: std::time::Instant,
}

impl LinkStateMachine {
    pub fn new() -> Self {
        Self {
            state: LinkState::Inactive,
            status: LinkStatus::Down,
            silent: false,
            actor_addresses: Default::default(),
            last_state_change: std::time::Instant::now(),
        }
    }

    pub fn set_state(&mut self, new_state: LinkState) {
        self.state = new_state;
        self.last_state_change = std::time::Instant::now();
    }
}

pub struct LinkStateWrapper {
    id: LinkId,
    link_type: LinkType,
    locked_fsm: Mutex<LinkStateMachine>,
    pub locked_data: Mutex<LinkData>,
}

impl LinkStateWrapper {
    pub fn new(new_id: LinkId, new_link_type: LinkType) -> Self {
        Self {
            id: new_id,
            link_type: new_link_type,
            locked_fsm: Mutex::new(LinkStateMachine::new()),
            locked_data: Mutex::new(LinkData::new()),
        }
    }

    /// Get the link's current state
    pub fn get_state(&self) -> LinkState {
        self.locked_fsm.lock().unwrap().state
    }

    pub fn is_ready(&self) -> bool {
        let locked_fsm = self.locked_fsm.lock().unwrap();
        locked_fsm.status == LinkStatus::Up && locked_fsm.state == LinkState::Active
    }

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
        match event {
            LinkEvent::Start => self.start(asm),
            LinkEvent::KeyingDone => self.keying_done(asm),
            LinkEvent::ReceivedHelloRequest => self.process_hello_request(asm),
            LinkEvent::ReceivedHelloResponse(code) => self.process_hello_response(asm, code),
            LinkEvent::ReceivedRegisterRequest(addr) => {
                self.process_register_actor_address_request(asm, addr)
            }
            LinkEvent::ReceivedRegisterResponse(code) => {
                self.process_register_actor_address_response(asm, code)
            }
            LinkEvent::ReceivedAuthorizeResponse => self.process_authorize_repsonse(asm),
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
        }
    }

    /// Start an inactive link/tether
    /// Transitions from Inactive -> Keying
    /// Will trigger key management messages to be sent if this is an adapter
    fn start(&self, asm: &Assembly) -> Result<(), LinkStateError> {
        assert!(self.id != zpr::LINK_ID_UNKNOWN);
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if locked_fsm.state != LinkState::Inactive {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "start".to_string(),
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

    /// The Key Manager calls this when it is done initial keying
    /// Transitions from Keying -> Helloing
    /// Will trigger a Hello to be sent if this is an adapter
    fn keying_done(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if locked_fsm.state != LinkState::Keying {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "keying done".to_string(),
            ));
        }

        let Some(peer_state) = asm.peer_table.get(link_id) else {
            return Err(LinkStateError::NotFound(link_id));
        };

        let Some(sa) = peer_state.get_established_transport_association() else {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "keying done when SA not established".to_owned(),
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
        drop(locked_fsm);
        self.maybe_send_hello(asm);
        Ok(())
    }

    fn maybe_send_hello(&self, asm: &Arc<Assembly>) {
        // IF this is an adapter, it's expected to issue the hello
        if self.link_type == LinkType::AdapterToNode {
            let link_id = self.id;
            let task_asm = asm.clone();
            tokio::task::spawn_local(async move {
                let status = mgmt::requests::send_hello_request(&task_asm, link_id).await?;

                task_asm
                    .process_link_state_event(link_id, LinkEvent::ReceivedHelloResponse(status))
                    .map_err(|_| ())
            });
        }
        // Otherwise, wait for the adapter to reach out
    }

    /// Update link state based on received hello request
    /// Transitions from Helloing to Registering Actor Address
    /// Does not generate any packets
    fn process_hello_request(&self, _asm: &Assembly) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        let link_id = self.id;
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToNode, LinkState::Helloing) => {
                locked_fsm.set_state(LinkState::Active);
                debug!(target: LINK_STATE, "Link {link_id} finished helloing.  Becoming active");
                Ok(())
            }
            (LinkType::NodeToAdapter, LinkState::Helloing) => {
                locked_fsm.set_state(LinkState::RegisterAA);
                debug!(
                    target: LINK_STATE,
                    "Link {link_id} finished helloing.  Waiting on register actor address"
                );
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
                "process hello request".to_string(),
            )),
        }
    }

    /// Update link state based on received hello response
    /// Transitions from Helloing to Registering Actor Address
    /// Sends a Register Actor Address request if this is an adapter
    fn process_hello_response(
        &self,
        asm: &Arc<Assembly>,
        code: ResponseCode,
    ) -> Result<(), LinkStateError> {
        if code == ResponseCode::Other {
            // Received an error response.
            return self.process_error_response(&asm);
        }

        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        match (self.link_type, locked_fsm.state) {
            (LinkType::AdapterToNode, LinkState::Helloing) => {
                locked_fsm.set_state(LinkState::RegisterAA);
                debug!(
                    target: LINK_STATE,
                    "Link {link_id} finished helloing.  Sending register actor address"
                );
                drop(locked_fsm);
                self.send_register_address(asm);
                Ok(())
            }
            (LinkType::NodeToNode, LinkState::Helloing) => {
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
                "process hello response".to_string(),
            )),
        }
    }

    fn send_register_address(&self, asm: &Arc<Assembly>) {
        let link_id = self.id;
        let task_asm = asm.clone();
        tokio::task::spawn_local(async move {
            for actor_addr in &task_asm.local_zpr_addresses {
                let result = mgmt::requests::send_register_actor_address_request(
                    &task_asm,
                    link_id,
                    *actor_addr,
                )
                .await;

                if result.is_err() || result.unwrap() == ResponseCode::Other {
                    warn!(target: LINK_STATE, "Link {link_id} failed to register address {actor_addr}");
                }
            }

            task_asm.process_link_state_event(
                link_id,
                LinkEvent::ReceivedRegisterResponse(ResponseCode::Success),
            )
        });
    }

    /// Update link state based on received register actor address request
    /// Transitions from Registering Actor Address to Active
    /// Does not generate any packets
    fn process_register_actor_address_request(
        &self,
        asm: &Arc<Assembly>,
        addr: IpAddress,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::RegisterAA) => {
                locked_fsm.actor_addresses.push(addr);
                debug!(
                    target: LINK_STATE,
                    "Link {link_id} received actor address ({addr}).  Authorizing with visa service"
                );

                match visa_mgmt::build_connect_request(asm, link_id, addr) {
                    Ok(Some(conn_req)) => Ok(visa_mgmt::authorize_connect(asm, link_id, conn_req)),
                    Ok(None) => {
                        locked_fsm.set_state(LinkState::Active);
                        debug!(
                            target: LINK_STATE,
                            "Link {link_id} (Visa Service) received actor address.  Becoming active, no authorization required"
                        );
                        drop(locked_fsm);
                        self.run_active(asm)
                    }
                    Err(e) => Err(e),
                }
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited register address request".to_string(),
            )),
        }
    }

    fn process_authorize_repsonse(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::RegisterAA) => {
                locked_fsm.set_state(LinkState::Active);
                debug!(target: LINK_STATE, "Link {link_id} authorized.  Becoming active");
                drop(locked_fsm);
                self.run_active(&asm)
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited authorize response".to_string(),
            )),
        }
    }

    /// Update link state based on received register actor address response
    /// Transitions from Registering Actor Address to Active
    /// Does not generate any packets
    fn process_register_actor_address_response(
        &self,
        asm: &Arc<Assembly>,
        _code: ResponseCode,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::AdapterToNode, LinkState::RegisterAA) => {
                locked_fsm.set_state(LinkState::Active);
                asm.tun_ctl.set_carrier(true).unwrap();
                debug!(
                    target: LINK_STATE,
                    "Link {link_id} finished registering actor address.  Becoming active"
                );
                drop(locked_fsm);
                self.run_active(asm)
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited register address response".to_string(),
            )),
        }
    }

    fn process_error_response(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        asm.counters[CounterType::PeerHandshakeFailure].increment();
        warn!(target: LINK_STATE, "Link {link_id} bringup failed at state {:?}",
            self.locked_fsm.lock().unwrap().state);

        self.initiate_close(&asm, TerminateReason::Other)
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
                "terminate".to_string(),
            ))
        } else {
            locked_fsm.set_state(LinkState::Closing);
            Ok(())
        }
    }

    /// Initiate the shutdown of the link
    /// Transitions to Closing from any running state
    /// Generates a Terminate Request packet
    fn initiate_close(
        &self,
        asm: &Arc<Assembly>,
        reason: TerminateReason,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        info!(target: LINK_STATE,"Initiating shutdown on link {link_id}");

        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        locked_fsm.set_state(LinkState::Closing);
        let task_asm = asm.clone();
        tokio::task::spawn_local(async move {
            let _ = send_terminate_request(&task_asm, link_id, reason).await;
        });
        Ok(())
    }

    /// Tear down link state
    fn clean_up_link_state(&self, asm: &Arc<Assembly>) -> tokio::task::JoinSet<()> {
        let link_id = self.id;
        let mut join_set = tokio::task::JoinSet::new();
        info!(target: LINK_STATE, "Link {link_id} is clearing its state");

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
        mgmt::requests::send_terminate_indication(asm, link_id, TerminateReason::Reset).await;
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
                "terminate response".to_string(),
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
                let response = mgmt::requests::send_echo_request(&task_asm, link_id).await;
                match response {
                    Ok(()) => {
                        let mut link_data = peer.link_state_machine.locked_data.lock().unwrap();
                        link_data.echo_success += 1;
                        link_data
                            .latency_data
                            .add(Instant::now().duration_since(start_time));
                        consecutive_misses = 0;
                    }
                    Err(SyncReqError::Timeout) => {
                        peer.link_state_machine
                            .locked_data
                            .lock()
                            .unwrap()
                            .echo_timeout += 1;
                        consecutive_misses += 1;
                    }
                    Err(_) => {
                        peer.link_state_machine
                            .locked_data
                            .lock()
                            .unwrap()
                            .echo_failure += 1;
                        consecutive_misses += 1;
                    }
                }

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

async fn send_terminate_request(
    asm: &Arc<Assembly>,
    link_id: LinkId,
    reason: TerminateReason,
) -> Result<(), LinkStateError> {
    match mgmt::requests::send_terminate_request(&asm, link_id, reason).await {
        Err(e) => {
            warn!(target: LINK_STATE,
                "Link {link_id} got error '{e:?}' when trying to shut down.  Shutting down anyway"
            );
            mgmt::requests::send_terminate_indication(asm, link_id, reason).await;
            asm.process_link_state_event(link_id, LinkEvent::SentTerminate)
        }
        Ok(response) => {
            asm.process_link_state_event(link_id, LinkEvent::ReceivedTerminateResponse(response))
        }
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
        write!(f, "    Other failures: {}\n", self.echo_failure)?;
        write!(
            f,
            "    Latency: Min {:?}, Max {:?}, Avg {average:?}\n",
            self.latency_data.get_min(),
            self.latency_data.get_max(),
        )
    }
}
