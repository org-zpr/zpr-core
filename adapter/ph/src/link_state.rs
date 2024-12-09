use crate::assembly::{Assembly, PhMode};
use crate::km::ZPIPair;
use crate::km_multiplexor;
use crate::mgmt;
use crate::net_defs::IpAddress;
use crate::special_peers;

use std::sync::{Arc, Mutex};
use thiserror::Error;
use tracing::*;
use zpr::LinkId;
use zpr::ZPI_ENCRYPTED_HEADER_FLAG;

/// State machine for links and docking sessions

// Node-to-Node
// +---------+       +----------+       +--------+
// | INITIAL |--CD-->| INACTIVE |--ST-->| KEYING |
// +---------+       +----------+       +--------+
//     ^                  ^               | |  |
//     |                  |   +------KDe--+ |  +--KDu--------+
//     |                  CC  |       C    KDo               |
//     |                  |   V             V                V
//     |              +---------+  HDe  +----------+     +----------+
//     |              | CLOSING |<--C---| HELLOING |     | HELLOING |
//     |              +---------+       +----------+     | SILENT   |
//     R                  ^                  |   |       +----------+
//     |                  |                 HDo HDu          |    |
//     |                  C                  |   |          HDu   C
//     |                  |                  |   +------+   HDo  HDe
//     |                  |                  V          V    V     |
//     |                  | KDe, C, KF   +--------+    +--------+  |
//     |                  +----------+---| ACTIVE |--->| ACTIVE |  |
//     |                             |   +--------+ KDu| Silent |  |
//     +<-R-[ANY STATE]               \                +--------+  |
//     |                               \                   |       |
// +-------+                            \                  C       |
// | ERROR |<-- Error -- [ANY STATE]     \                 |       |
// +-------+                              +----------------+-------+

// Node-to-Adapter
// +---------+       +----------+       +-----------+      +--------+
// | INITIAL |--CD-->| INACTIVE |--ST-->| LISTENING |-RKM->| KEYING |
// +---------+       +----------+       +-----------+      +--------+
//     ^                  ^                    |             | |  |
//     |                  |   +------KDe------- -------------+ |  +--KDu--+
//     |                  CC  |       C        |              KDo         |
//     |                  |   |                +- RHM---+   +--+          |
//     |                  |   V                         V   V             V
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
//
// NOTE: Because we currently lack a way to know that an adapter will be
// connecting before the key management message comes, the LISTENING state
// is currently not implemented.

// Adapter-to-Node
// +---------+       +----------+                          +--------+
// | INITIAL |--CD-->| INACTIVE |--ST--------------------->| KEYING |
// +---------+       +----------+                          +--------+
//     ^                  ^                                  | |  |
//     |                  |   +------KDe---------------------+ |  +--KDu-----+
//     |                  CC  |       C                       KDo            |
//     |                  |   |                                |             |
//     |                  |   V                                V             V
//     |              +---------+             HDe   +----------+  +----------+
//     |              | CLOSING |<--------------C---| HELLOING |  | HELLOING |
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

// NOTE: I think long term we want these added by topology instead of how they are now

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum LinkState {
    Initial,
    Inactive,
    // Listening, // Unused, see note above
    Keying,
    Helloing,
    Closing,
    Active,
    RegisterAA,
    Error,
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum LinkEvent {
    Configure,
    Start,
    KeyingDone,
    ReceivedHelloRequest,
    ReceivedHelloResponse,
    ReceivedRegisterRequest(IpAddress),
    ReceivedRegisterResponse,
    ReceivedAuthorizeResponse,
    ReceivedKeepAliveResponse,
    ReceivedTerminationRequest,
    ReceivedTerminationResponse,
    ReceivedTerminationIndication,
    Close,
    Reset,
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

#[derive(Copy, Clone, PartialEq)]
pub enum LinkType {
    Internal,
    AdapterToNode,
    NodeToNode, // Currently unsupported
    NodeToAdapter,
}

#[derive(Copy, Clone, Debug)]
pub enum LinkStatus {
    Up,
    Down,
}

pub struct LinkStateMachine {
    state: LinkState,
    status: LinkStatus,
    silent: bool,
    agent_addresses: Vec<IpAddress>,
}

impl LinkStateMachine {
    pub fn new() -> Self {
        Self {
            state: LinkState::Initial,
            status: LinkStatus::Down,
            silent: false,
            agent_addresses: Default::default(),
        }
    }
}

pub struct LinkStateWrapper {
    id: LinkId,
    link_type: LinkType,
    locked_fsm: Mutex<LinkStateMachine>,
}

impl LinkStateWrapper {
    pub fn new(new_id: LinkId, new_link_type: LinkType) -> Self {
        Self {
            id: new_id,
            link_type: new_link_type,
            locked_fsm: Mutex::new(LinkStateMachine::new()),
        }
    }

    #[allow(dead_code)]
    /// Query whether the link is up
    pub fn get_status(&self) -> LinkStatus {
        self.locked_fsm.lock().unwrap().status
    }

    pub fn process_event(
        &self,
        asm: &Arc<Assembly>,
        event: LinkEvent,
    ) -> Result<(), LinkStateError> {
        match event {
            LinkEvent::Configure => self.configure(asm),
            LinkEvent::Start => self.start(asm),
            LinkEvent::KeyingDone => self.keying_done(asm),
            LinkEvent::ReceivedHelloRequest => self.process_hello_request(asm),
            LinkEvent::ReceivedHelloResponse => self.process_hello_response(asm),
            LinkEvent::ReceivedRegisterRequest(addr) => {
                self.process_register_agent_address_request(asm, addr)
            }
            LinkEvent::ReceivedRegisterResponse => {
                self.process_register_agent_address_response(asm)
            }
            LinkEvent::ReceivedAuthorizeResponse => self.process_authorize_repsonse(asm),
            LinkEvent::ReceivedKeepAliveResponse => Err(LinkStateError::OperationNotSupportedYet),
            LinkEvent::ReceivedTerminationResponse => Err(LinkStateError::OperationNotSupportedYet),
            LinkEvent::ReceivedTerminationRequest => Err(LinkStateError::OperationNotSupportedYet),
            LinkEvent::ReceivedTerminationIndication => {
                Err(LinkStateError::OperationNotSupportedYet)
            }
            LinkEvent::Close => Ok(self.initiate_close()),
            LinkEvent::Reset => Ok(self.reset(asm)),
        }
    }

    /// Configure an uninitialized link/tether
    /// Transitions from Initial -> Inactive
    /// Does not generate any packets
    fn configure(&self, _asm: &Assembly) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if locked_fsm.state != LinkState::Initial {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "configure".to_string(),
            ));
        }

        // TODO: What configuration goes here?
        // For now, just set the link up and transition it to the inactive state
        locked_fsm.status = LinkStatus::Up;
        locked_fsm.state = LinkState::Inactive;

        debug!(
            "Configured link {}.  State: {:?}, status: {:?}",
            self.id, locked_fsm.state, locked_fsm.status
        );
        Ok(())
    }

    /// Start an inactive link/tether
    /// Transitions from Inactive -> Keying
    /// Will trigger key management messages to be sent if this is an adapter
    fn start(&self, asm: &Assembly) -> Result<(), LinkStateError> {
        assert!(self.id != zpr::LINK_ID_UNKNOWN);
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if locked_fsm.state != LinkState::Inactive {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "start".to_string(),
            ));
        }

        locked_fsm.state = LinkState::Keying;

        debug!("Link {} started.  Keying in progress", self.id);

        match self.link_type {
            LinkType::AdapterToNode => {
                km_multiplexor::add_adapter_link(
                    asm,
                    self.id,
                    ZPIPair::new(zpr::ZPI_ENCRYPTED_HEADER_FLAG | 5, 6),
                    asm.self_noise_keypair.clone().unwrap(),
                    asm.peer_noise_keypair.clone().unwrap().public,
                    asm.certx.clone().unwrap(),
                )
                .unwrap();
                Ok(())
            }
            LinkType::NodeToNode => {
                warn!("Error: Node to node not supported yet");
                locked_fsm.state = LinkState::Error;
                Err(LinkStateError::OperationNotSupportedYet)
            }
            LinkType::NodeToAdapter => {
                km_multiplexor::add_node_link(
                    asm,
                    self.id,
                    ZPIPair::new(ZPI_ENCRYPTED_HEADER_FLAG | 3, 4),
                    asm.self_noise_keypair.clone().unwrap(),
                    asm.certx.clone().unwrap(),
                )
                .unwrap();
                Ok(())
            }
            LinkType::Internal => {
                error!("Coding error: internal link state machine should not be controlled");
                Err(LinkStateError::InvalidOperation("coding error".into()))
            }
        }
    }

    /// The Key Manager calls this when it is done initial keying
    /// Transitions from Keying -> Helloing
    /// Will trigger a Hello to be sent if this is an adapter
    fn keying_done(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if locked_fsm.state != LinkState::Keying {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "keying done".to_string(),
            ));
        }

        let Some(peer_state) = asm.peer_table.get(self.id) else {
            return Err(LinkStateError::NotFound(self.id));
        };

        let Some(sa) = peer_state.get_established_transport_association() else {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "keying done when SA not established".to_owned(),
            ));
        };

        if let Some(ref peer_cert) = sa.peer_cert {
            info!("Link {} has name {:?}", self.id, peer_cert.subject_name());

            // assign special-peer name if this peer is special
            for name in
                special_peers::special_peer_names_from_x509_subject_name(peer_cert.subject_name())
            {
                match asm.peer_table.assign_special_name(name, self.id) {
                    Ok(()) => info!("Link {} assigned special name {:?}", self.id, name),
                    Err(_) => warn!("Unable to assign link {} special name {:?}", self.id, name),
                }
            }
        }

        debug!("Link {} finished keying.  Starting hello", self.id);

        locked_fsm.state = LinkState::Helloing;
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
                mgmt::requests::send_hello_request(&task_asm, link_id).await?;

                if task_asm
                    .process_link_state_event(link_id, LinkEvent::ReceivedHelloResponse)
                    .is_err()
                {
                    Err(())
                } else {
                    Ok(())
                }
            });
        }
        // Otherwise, wait for the adapter to reach out
    }

    /// Update link state based on received hello request
    /// Transitions from Helloing to Registering Agent Address
    /// Does not generate any packets
    fn process_hello_request(&self, _asm: &Assembly) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToNode, LinkState::Helloing) => {
                locked_fsm.state = LinkState::Active;
                debug!("Link {} finished helloing.  Becoming active", self.id);
                Ok(())
            }
            (LinkType::NodeToAdapter, LinkState::Helloing) => {
                locked_fsm.state = LinkState::RegisterAA;
                debug!(
                    "Link {} finished helloing.  Waiting on register agent address",
                    self.id
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
    /// Transitions from Helloing to Registering Agent Address
    /// Sends a Register Agent Address request if this is an adapter
    fn process_hello_response(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::AdapterToNode, LinkState::Helloing) => {
                locked_fsm.state = LinkState::RegisterAA;
                debug!(
                    "Link {} finished helloing.  Sending register agent address",
                    self.id
                );
                let link_id = self.id;
                let task_asm = asm.clone();
                tokio::task::spawn_local(async move {
                    for agent_addr in &task_asm.agent_addresses {
                        mgmt::requests::send_register_agent_address_request(
                            &task_asm,
                            link_id,
                            *agent_addr,
                        )
                        .await?;
                    }

                    if task_asm
                        .process_link_state_event(link_id, LinkEvent::ReceivedRegisterResponse)
                        .is_err()
                    {
                        Err(())
                    } else {
                        Ok(())
                    }
                });
                Ok(())
            }
            (LinkType::NodeToNode, LinkState::Helloing) => {
                locked_fsm.state = LinkState::Active;
                debug!("Link {} finished helloing.  Becoming active", self.id);
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

    /// Update link state based on received register agent address request
    /// Transitions from Registering Agent Address to Active
    /// Does not generate any packets
    fn process_register_agent_address_request(
        &self,
        asm: &Arc<Assembly>,
        addr: IpAddress,
    ) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::RegisterAA) => {
                locked_fsm.agent_addresses.push(addr);
                debug!(
                    "Link {} received agent address ({addr}).  Authorizing with visa service",
                    self.id
                );

                let Some(peer_state) = asm.peer_table.get(self.id) else {
                    return Err(LinkStateError::NotFound(self.id));
                };

                let Some(sa) = peer_state.get_established_transport_association() else {
                    return Err(LinkStateError::UnexpectedTransition(
                        locked_fsm.state,
                        "register agent address when SA not established".to_owned(),
                    ));
                };

                // TODO: validate that DN *only* has CN, since this is what VS expects
                // (or, teach VS about DNs)

                let cn: String;

                if let Some(ref peer_cert) = sa.peer_cert {
                    cn = peer_cert
                        .subject_name()
                        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
                        .next()
                        .and_then(|entry| Some(entry.data().as_utf8().ok()?.to_owned()))
                        .unwrap_or_default();
                } else {
                    cn = String::new();
                }

                info!("Link {} CN is {cn}", self.id);

                if cn == zpr::VISA_SERVICE_CN {
                    locked_fsm.state = LinkState::Active;
                    debug!(
                        "Link {} (Visa Service) received agent address.  Becoming active, no authorization required",
                        self.id
                    );
                    drop(locked_fsm);
                    self.run_active(asm)
                } else {
                    drop(locked_fsm);

                    // issue an Authorize Connect Request to the visa service for this adapter
                    let connect_req = libnode::vsapi::ConnectRequest {
                        connection_id: Some(123), // unused
                        dock_addr: Some(
                            IpAddress::new_from_std(&asm.agent_addresses[0]).into_v4_or_v6_octets(),
                        ),
                        claims: Some(
                            [
                                ("zpr.addr".to_owned(), addr.to_string()),
                                ("zpr.adapter.cn".to_owned(), cn),
                            ]
                            .into(),
                        ),
                        challenge: None,           // unused
                        challenge_responses: None, // unused
                    };

                    let link_id = self.id;
                    let task_asm = asm.clone();
                    tokio::task::spawn_local(async move {
                        match task_asm
                            .vsconn
                            .as_ref()
                            .unwrap()
                            .authorize_connect(connect_req)
                            .await
                        {
                            Ok(libnode::vsapi::ConnectResponse {
                                status: Some(libnode::vsapi::StatusCode::SUCCESS),
                                ..
                            }) => {
                                info!("link {link_id} authorized");

                                if task_asm
                                    .process_link_state_event(
                                        link_id,
                                        LinkEvent::ReceivedAuthorizeResponse,
                                    )
                                    .is_err()
                                {
                                    Err(())
                                } else {
                                    Ok(())
                                }
                            }

                            Ok(cr) => {
                                warn!(
                                    "link {link_id} authorization rejected: {}",
                                    cr.reason.unwrap_or("(no reason given)".to_owned())
                                );

                                if task_asm
                                    .process_link_state_event(link_id, LinkEvent::Reset)
                                    .is_err()
                                {
                                    Err(())
                                } else {
                                    Ok(())
                                }
                            }

                            Err(err) => {
                                warn!("link {link_id} authorization failed: {err}");

                                if task_asm
                                    .process_link_state_event(link_id, LinkEvent::Reset)
                                    .is_err()
                                {
                                    Err(())
                                } else {
                                    Ok(())
                                }
                            }
                        }
                    });

                    Ok(())
                }
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited register address request".to_string(),
            )),
        }
    }

    fn process_authorize_repsonse(&self, asm: &Assembly) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::RegisterAA) => {
                locked_fsm.state = LinkState::Active;
                debug!("Link {} authorized.  Becoming active", self.id);
                drop(locked_fsm);
                self.run_active(asm)
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited authorize response".to_string(),
            )),
        }
    }

    /// Update link state based on received register agent address response
    /// Transitions from Registering Agent Address to Active
    /// Does not generate any packets
    fn process_register_agent_address_response(
        &self,
        asm: &Assembly,
    ) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::AdapterToNode, LinkState::RegisterAA) => {
                locked_fsm.state = LinkState::Active;
                asm.tun_ctl.set_carrier(true).unwrap();
                debug!(
                    "Link {} finished registering agent address.  Becoming active",
                    self.id
                );
                drop(locked_fsm);
                self.run_active(asm)
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited register address response".to_string(),
            )),
        }
    }

    #[allow(dead_code)]
    /// Initiate the shutdown of the link
    /// Transitions to Closed from any running state
    pub fn initiate_close(&self) {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        locked_fsm.state = LinkState::Closing;
        // TODO: Send stateful terminate
    }

    /// Complete a link shutdown, upon receiving a terminate request or response
    /// Transitions from Closed to Inactive
    #[allow(dead_code)]
    pub fn complete_close(&self, asm: &Assembly) -> Result<(), LinkStateError> {
        info!("Shutting down link {}", self.id);
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        locked_fsm.state = LinkState::Inactive;
        if asm.ph_mode != PhMode::Node {
            asm.tun_ctl.set_carrier(false).unwrap();
        }
        // TODO: Bring down KM
        Ok(())
    }

    /// Reset the link, shutting it down and wiping its configuration
    /// Transitions to Initial from any state
    pub fn reset(&self, asm: &Assembly) {
        info!("Resetting link {}", self.id);
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        locked_fsm.state = LinkState::Initial;
        locked_fsm.silent = false;
        if asm.ph_mode != PhMode::Node {
            asm.tun_ctl.set_carrier(false).unwrap();
        }
        // TODO: Send stateless terminate
        // TODO: Bring down KM
    }

    pub fn run_active(&self, _asm: &Assembly) -> Result<(), LinkStateError> {
        debug!("Link {} entering active state", self.id);
        // TODO send echoes
        Ok(())
    }
}
