use crate::assembly::Assembly;
use crate::km::ZPIPair;
use crate::km_multiplexor;
use crate::mgmt;
use crate::net_defs::IpAddress;

use std::sync::Mutex;
use tracing::{info, warn};
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

pub enum LinkStateError {
    UnexpectedTransition,
    InvalidOperation,
    OperationNotSupportedYet,
}

#[allow(dead_code)]
#[derive(Copy, Clone, PartialEq)]
pub enum LinkType {
    AdapterToNode,
    NodeToNode, // Currently unsupported
    NodeToAdapter,
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub enum LinkStatus {
    Up,
    Down,
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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
    pub fn get_status(&self) -> LinkStatus {
        self.locked_fsm.lock().unwrap().status
    }

    fn get_state(&self) -> LinkState {
        self.locked_fsm.lock().unwrap().state
    }

    fn set_state(&self, state: LinkState) {
        self.locked_fsm.lock().unwrap().state = state
    }

    #[allow(dead_code)]
    pub fn set_silent(&mut self) {
        self.locked_fsm.lock().unwrap().silent = true
    }

    pub fn reset(&self) {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        locked_fsm.state = LinkState::Initial;
        locked_fsm.silent = false;
        // TODO: Send terminate
    }

    #[allow(dead_code)]
    /// Initiate the shutdown of the link
    pub fn shutdown(&mut self) {
        self.set_state(LinkState::Closing);
    }

    /// Configure an uninitialized link/tether
    /// Transitions from Initial -> Inactive
    pub fn configure(&self, asm: &Assembly) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if locked_fsm.state != LinkState::Initial {
            return Err(LinkStateError::UnexpectedTransition);
        }

        // TODO: What configuration goes here?
        // For now, just set the link up and transition it to the inactive state
        locked_fsm.status = LinkStatus::Up;
        locked_fsm.state = LinkState::Inactive;

        info!(
            "{}: Configured link {}.  State: {:?}, status: {:?}",
            asm.system_name, self.id, locked_fsm.state, locked_fsm.status
        );
        Ok(())
    }

    /// Start an inactive link/tether
    /// Transitions from Inactive -> Keying
    pub fn start<'pktbuf>(&self, asm: &'static Assembly<'pktbuf>) -> Result<(), LinkStateError> {
        assert!(self.id != 0);
        if self.get_state() != LinkState::Inactive {
            return Err(LinkStateError::UnexpectedTransition);
        }

        self.set_state(LinkState::Keying);

        info!(
            "{}: Link {} started.  Keying in progress",
            asm.system_name, self.id
        );

        match self.link_type {
            LinkType::AdapterToNode => {
                if !asm.flags.disable_key_management {
                    km_multiplexor::add_adapter_link(
                        &asm,
                        self.id,
                        ZPIPair::new(zpr::ZPI_ENCRYPTED_HEADER_FLAG | 5, 6),
                        asm.self_noise_keypair.clone().unwrap(),
                        asm.peer_noise_keypair.clone().unwrap().public,
                        asm.certx.clone().unwrap(),
                    )
                    .unwrap();
                    Ok(())
                } else {
                    self.keying_done(asm)
                }
            }
            LinkType::NodeToNode => {
                warn!("Error: Node to node not supported yet");
                self.set_state(LinkState::Error);
                return Err(LinkStateError::OperationNotSupportedYet);
            }
            LinkType::NodeToAdapter => {
                if !asm.flags.disable_key_management {
                    km_multiplexor::add_node_link(
                        &asm,
                        self.id,
                        ZPIPair::new(ZPI_ENCRYPTED_HEADER_FLAG | 3, 4),
                        asm.self_noise_keypair.clone().unwrap(),
                        asm.certx.clone().unwrap(),
                    )
                    .unwrap();
                    Ok(())
                } else {
                    self.keying_done(asm)
                }
            }
        }
    }

    /// The Key Manager calls this when it is done initial keying
    /// Transitions from Keying -> Helloing
    pub fn keying_done<'pktbuf>(
        &self,
        asm: &'static Assembly<'pktbuf>,
    ) -> Result<(), LinkStateError> {
        if self.get_state() != LinkState::Keying {
            return Err(LinkStateError::UnexpectedTransition);
        }

        self.set_state(LinkState::Helloing);
        self.send_hello(asm);
        Ok(())
    }

    fn send_hello<'pktbuf>(&self, asm: &'static Assembly<'pktbuf>) {
        // IF this is an adapter, it's expected to issue the hello
        if self.link_type == LinkType::AdapterToNode {
            tokio::task::spawn_local(mgmt::requests::send_hello_request(asm, self.id));
        }
        // Otherwise, wait for the adapter to reach out
    }

    /// Update link state based on received hello request
    /// Transitions from Helloing to Registering Agent Address
    pub fn process_hello_request(&self) -> Result<(), LinkStateError> {
        match (self.link_type, self.get_state()) {
            (LinkType::NodeToNode, LinkState::Helloing) => {
                self.set_state(LinkState::Active);
                Ok(())
            }
            (LinkType::NodeToAdapter, LinkState::Helloing) => {
                self.set_state(LinkState::RegisterAA);
                Ok(())
            }
            (LinkType::AdapterToNode, _) => {
                // Adapters should not be receiving these messages from nodes
                warn!("Adapter discarded unsolicited Hello Request");
                return Err(LinkStateError::InvalidOperation);
            }
            (_, _) => {
                return Err(LinkStateError::UnexpectedTransition);
            }
        }
    }

    /// Update link state based on received hello response
    /// Transitions from Helloing to Registering Agent Address
    pub fn process_hello_response<'pktbuf>(
        &self,
        asm: &'static Assembly<'pktbuf>,
    ) -> Result<(), LinkStateError> {
        match (self.link_type, self.get_state()) {
            (LinkType::AdapterToNode, LinkState::Helloing) => {
                self.set_state(LinkState::RegisterAA);
                tokio::task::spawn_local(mgmt::requests::send_register_agent_address_request(
                    asm, self.id,
                ));
            }
            (LinkType::NodeToNode, LinkState::Helloing) => {
                self.set_state(LinkState::Active);
            }
            (LinkType::NodeToAdapter, _) => {
                // Nodes should not be receiving these messages from adapters
                warn!("{}: Discarded unsolicited Hello Response", asm.system_name);
            }
            (_, _) => {
                return Err(LinkStateError::UnexpectedTransition);
            }
        }

        Ok(())
    }

    /// Update link state based on received register agent address request
    /// Transitions from Registering Agent Address to Active
    pub fn process_register_agent_address_request(
        &self,
        asm: &Assembly,
        addr: IpAddress,
    ) -> Result<(), LinkStateError> {
        match (self.link_type, self.get_state()) {
            (LinkType::NodeToAdapter, LinkState::RegisterAA) => {
                self.locked_fsm.lock().unwrap().agent_addresses.push(addr);
                self.set_state(LinkState::Active);
                self.run_active(asm)
            }
            (_, _) => {
                warn!("Error: Received invalid register address request");
                Err(LinkStateError::InvalidOperation)
            }
        }
    }

    /// Update link state based on received register agent address response
    /// Transitions from Registering Agent Address to Active
    pub fn process_register_agent_address_response(
        &self,
        asm: &Assembly,
    ) -> Result<(), LinkStateError> {
        match (self.link_type, self.get_state()) {
            (LinkType::AdapterToNode, LinkState::RegisterAA) => {
                self.set_state(LinkState::Active);
                asm.tun_ctl.set_carrier(true).unwrap();
                self.run_active(asm)
            }
            (_, _) => {
                warn!("Error: Received invalid register address request");
                Err(LinkStateError::InvalidOperation)
            }
        }
    }

    /// Initiate a link shutdown
    /// Transitions to Closed from any running state
    #[allow(dead_code)]
    pub fn close(&self, asm: &Assembly) -> Result<(), LinkStateError> {
        info!("{}: Shutting down link {}", asm.system_name, self.id);
        self.set_state(LinkState::Closing);
        // TODO: Send terminate
        Ok(())
    }

    pub fn run_active(&self, asm: &Assembly) -> Result<(), LinkStateError> {
        info!(
            "{}: Link {} entering active state",
            asm.system_name, self.id
        );
        // TODO send echoes
        Ok(())
    }
}
