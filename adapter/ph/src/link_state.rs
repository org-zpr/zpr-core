use crate::zpr::LinkId;

/// State machine for links and docking sessions

#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum LinkType {
    AdapterToNode,
    NodeToNode,
    NodeToAdapter,
}

#[allow(dead_code)]
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum LinkState {
    Initial,
    Inactive,
    Keying,
    Helloing,
    Closing,
    Active,
    Listening,
    RegisterAA,
    Error,
}

#[allow(dead_code)]
#[derive(Copy, Clone, Debug)]
pub enum LinkStatus {
    Up,
    Down,
}

#[allow(dead_code)]
pub struct LinkStateMachine {
    link_id: LinkId,
    link_type: LinkType,
    link_state: LinkState,
    link_status: LinkStatus,
    silent: bool,
}

impl LinkStateMachine {
    pub fn new(new_link_type: LinkType) -> Self {
        Self {
            link_id: 0, // Invalid link ID
            link_type: new_link_type,
            link_state: LinkState::Initial,
            link_status: LinkStatus::Down,
            silent: false,
        }
    }
}
