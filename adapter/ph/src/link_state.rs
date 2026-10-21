use crate::counters::ManagementCounterType;
use crate::km::ZPIPair;
use crate::km_multiplexor;
use crate::mgmt;
use crate::pki;
use crate::prelude::*;
use crate::sample_ring::SampleRing;
use crate::special_peers;
use crate::special_peers::SpecialPeerName;
use crate::zdp::{ResponseCode, TerminateReason};

use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::num::NonZero;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use thiserror::Error;
use zpr::addrs::ZPRNET_PREFIX_LEN;
use zpr_utils::net_defs::IpAddress;

/// Encrypted link lifecycle; actor authorization is independent.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum LinkState {
    Inactive,
    Keying,
    Helloing,
    /// disconnecting from visa service; only entered for the node->VS adapter link
    Disconnecting(TerminateReason),
    Closing,
    Resetting,
    Active,
    Error,
}

#[allow(dead_code)]
#[derive(Clone, Debug, strum::IntoStaticStr)]
pub enum LinkEvent {
    Start,
    KeyingDone,
    ReceivedHelloRequest,
    AssignedAAA(IpAddress), // Assigned AAA address for this link
    ReceivedHelloResponse(
        ResponseCode,
        Option<IpAddress>,
        Option<Vec<SocketAddr>>,
        bool,
    ), // response, AAA, ASA, VS bootstrap link

    ReceivedKeepAliveResponse,
    ReceivedTerminateLink(TerminateReason),
    ReceivedTerminateAck,
    ReceivedDisconnectAck, // from visa service
    Close(TerminateReason),
    CloseDone,
    Error,
    Timeout {
        logical_clock: u64,
    },
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
    #[allow(dead_code)]
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
    installed_aaa: bool,
}

impl LinkData {
    pub fn new() -> Self {
        Self {
            echo_success: 0,
            echo_timeout: 0,
            latency_data: SampleRing::new(Duration::ZERO),
            asa_addresses: None,
            aaa_address: None,
            installed_aaa: false,
        }
    }
}

pub struct LinkStateMachine {
    id: LinkId,
    state: LinkState,
    status: LinkStatus,
    silent: bool,

    last_state_change: Instant,
    /// used to prevent A/B/A errors with timeouts
    logical_clock: u64,
    timeout_handle: Option<tokio::task::AbortHandle>,
    /// Counter available for use by states which wish to count timeouts.
    /// Reset to 0 on any state transition.
    timeout_count: usize,
    /// Handle to an outstanding echo/keepalive task; used only during Active.
    /// Instant is time at which the echo was sent.
    echo_handle: Option<(Instant, tokio::task::AbortHandle)>,
    shutting_down: bool, // only ever goes from False -> True once
}

impl LinkStateMachine {
    pub fn new(link_id: LinkId) -> Self {
        Self {
            id: link_id,
            state: LinkState::Inactive,
            status: LinkStatus::Down,
            silent: false,
            last_state_change: std::time::Instant::now(),
            logical_clock: 0,
            timeout_handle: None,
            timeout_count: 0,
            echo_handle: None,
            shutting_down: false,
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
        let jh = tokio::task::spawn_local(async move {
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

pub struct LinkStateWrapper {
    pub id: LinkId, // set at constructor, never changes.
    link_type: LinkType,
    locked_fsm: Mutex<LinkStateMachine>,
    pub locked_data: Mutex<LinkData>,
    /// Internal links _may_ be associated with another internal link
    /// representing its remote side.
    pub internal_peer_id: Option<NonZero<LinkId>>,
}

impl LinkStateWrapper {
    pub fn new(new_id: LinkId, new_link_type: LinkType) -> Self {
        let mut lsm = LinkStateMachine::new(new_id);

        if matches!(new_link_type, LinkType::Internal) {
            // Internal links are always up and active, that is, `is_ready()`.
            lsm.state = LinkState::Active;
            lsm.status = LinkStatus::Up;
        }

        Self {
            id: new_id,
            link_type: new_link_type,
            locked_fsm: Mutex::new(lsm),
            locked_data: Mutex::new(LinkData::new()),
            internal_peer_id: None,
        }
    }

    pub fn is_internal(&self) -> bool {
        matches!(self.link_type, LinkType::Internal)
    }

    /// Get the link's current state
    pub fn get_state(&self) -> LinkState {
        self.locked_fsm.lock().unwrap().state
    }

    pub fn is_ready(&self) -> bool {
        let locked_fsm = self.locked_fsm.lock().unwrap();
        locked_fsm.status == LinkStatus::Up && locked_fsm.state == LinkState::Active
    }

    pub fn get_link_type(&self) -> LinkType {
        self.link_type
    }

    pub fn aaa_address(&self) -> Option<IpAddress> {
        self.locked_data.lock().unwrap().aaa_address
    }

    fn process_hello_request(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let locked_fsm = self.locked_fsm.lock().unwrap();
        if self.link_type != LinkType::NodeToAdapter || locked_fsm.state != LinkState::Helloing {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedHelloRequest",
            ));
        }
        let is_vs = asm
            .peer_table
            .lookup_special_peer(SpecialPeerName::VisaServiceAdapter)
            .is_some_and(|id| id.get() == self.id);
        let aaa = asm.address_pool.lock().unwrap().as_mut().map(|pool| {
            let aaa = pool.get_aaa_address();
            debug!(target: LINK_STATE, "allocated AAA {aaa}; {} active reservations", pool.len());
            aaa
        });
        if aaa.is_none() && !is_vs {
            mgmt::requests::send_hello_error_response(
                asm,
                self.id,
                ResponseCode::TemporarilyUnavailable,
            )
            .enqueue();
            drop(locked_fsm);
            return self.initiate_close(asm, TerminateReason::Other);
        }
        if let Some(aaa) = aaa {
            self.process_assigned_aaa(asm, aaa)?;
        }
        mgmt::requests::send_hello_success_response(
            asm,
            self.id,
            0,
            &get_available_asa_addresses(asm, self.id),
            aaa,
            is_vs,
        )
        .enqueue();
        self.run_active(asm, locked_fsm)
    }

    fn process_hello_response(
        &self,
        asm: &Arc<Assembly>,
        code: ResponseCode,
        aaa: Option<IpAddress>,
        asa: Option<Vec<SocketAddr>>,
        vs_bootstrap: bool,
    ) -> Result<(), LinkStateError> {
        if code != ResponseCode::Success {
            warn!(target: LINK_STATE, "{}: Hello failed: {code:?}", asm.formatted_link_id(self.id));
            return self.initiate_close(asm, TerminateReason::Other);
        }
        let locked_fsm = self.locked_fsm.lock().unwrap();
        if self.link_type != LinkType::AdapterToNode || locked_fsm.state != LinkState::Helloing {
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedHelloResponse",
            ));
        }
        if aaa.is_none() && !vs_bootstrap {
            return Err(LinkStateError::InvalidOperation(
                "ordinary link established without AAA".into(),
            ));
        }
        {
            let mut data = self.locked_data.lock().unwrap();
            data.aaa_address = aaa;
            data.asa_addresses = asa;
        }
        if let Some(aaa) = aaa {
            let exists = asm
                .tun_ctl
                .has_address(aaa.into())
                .map_err(|e| LinkStateError::InvalidOperation(format!("inspect AAA: {e}")))?;
            asm.tun_ctl
                .add_authentication_address(aaa.into(), ZPRNET_PREFIX_LEN)
                .map_err(|e| LinkStateError::InvalidOperation(format!("configure AAA: {e}")))?;
            self.locked_data.lock().unwrap().installed_aaa = !exists;
        }
        asm.tun_ctl
            .set_carrier(true)
            .map_err(|e| LinkStateError::InvalidOperation(format!("enable AAA carrier: {e}")))?;
        self.run_active(asm, locked_fsm)?;
        if let Some(peer) = asm.peer_table.get(self.id) {
            peer.actor_auth.link_ready(asm);
        }
        Ok(())
    }

    /// Schedule a `Timeout` event to occur after the specified duration.
    ///
    /// Any existing timeout is canceled atomically.
    ///
    /// The timeout will also be canceled automatically and atomically at the next state change.
    ///
    /// The timeout may be cancelled manually using `LinkStateMachine::cancel_timeout()`.
    /// It will be cancelled atomically.
    fn set_timeout(
        &self,
        asm: &Arc<Assembly>,
        locked_fsm: &mut MutexGuard<'_, LinkStateMachine>,
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

    pub fn process_event(
        &self,
        asm: &Arc<Assembly>,
        event: LinkEvent,
    ) -> Result<(), LinkStateError> {
        match event {
            LinkEvent::ReceivedKeepAliveResponse | LinkEvent::Timeout { .. } => {
                trace!(target: LINK_STATE, "{}: *EVENT* {event:?}", asm.formatted_link_id(self.id))
            }

            _ => {
                debug!(target: LINK_STATE, "{}: *EVENT* {event:?}", asm.formatted_link_id(self.id))
            }
        }

        match event {
            LinkEvent::Start => self.process_start(asm),
            LinkEvent::KeyingDone => self.process_keying_done(asm),
            LinkEvent::ReceivedHelloRequest => self.process_hello_request(asm),
            LinkEvent::AssignedAAA(addr) => self.process_assigned_aaa(asm, addr),
            LinkEvent::ReceivedHelloResponse(code, aaa_addr, maybe_asa_addrs, vs_bootstrap) => {
                self.process_hello_response(asm, code, aaa_addr, maybe_asa_addrs, vs_bootstrap)
            }

            LinkEvent::ReceivedKeepAliveResponse => self.process_keep_alive_response(asm),
            LinkEvent::ReceivedTerminateLink(code) => self.process_terminate_link(asm, code),
            LinkEvent::ReceivedTerminateAck => self.process_terminate_ack(asm),
            LinkEvent::ReceivedDisconnectAck => self.process_disconnect_ack(asm),
            LinkEvent::Close(code) => self.initiate_close(asm, code),
            LinkEvent::CloseDone => Ok(self.complete_close(asm)),
            LinkEvent::Error => self.process_error_response(asm),
            LinkEvent::Timeout { logical_clock } => self.process_timeout(asm, logical_clock),
        }
    }

    /// Start an inactive link/tether
    /// Transitions from Inactive -> Keying
    /// Will trigger key management messages to be sent if this is an adapter
    fn process_start(&self, asm: &Assembly) -> Result<(), LinkStateError> {
        assert!(self.id != LINK_ID_UNKNOWN);
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

        info!(target: LINK_STATE, "{} started.  Keying in progress", asm.formatted_link_id(link_id));

        match self.link_type {
            LinkType::AdapterToNode => {
                km_multiplexor::add_adapter_link(
                    asm,
                    link_id,
                    ZPIPair::new(ZPI_ENCRYPTED_HEADER_FLAG | 5, 6),
                    asm.self_noise_keypair.clone().unwrap(),
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
            let cert = peer_cert.get_cert();
            let is_verified = peer_cert.is_verified();

            // Note, keying will have failed if we requested verification (i.e. were
            // connecting to node) but the cert couldn't be verified.  So here,
            // we only need to verify the case that we are only conditionally verifying
            // (i.e., we are being connected to by a special adapter).

            if is_verified {
                info!(target: LINK_STATE, "{} has verified name {}", asm.formatted_link_id(link_id), pki::subject_name(cert));
            } else {
                warn!(target: LINK_STATE, "{} has unverified name {}", asm.formatted_link_id(link_id), pki::subject_name(cert));
            }

            let subject_der = match pki::subject_der(cert) {
                Ok(der) => der,
                Err(e) => {
                    warn!(target: LINK_STATE, "{} cannot encode certificate subject DN: {e}", asm.formatted_link_id(link_id));
                    Vec::new()
                }
            };

            if !is_verified {
                for name in special_peers::special_peer_names_from_subject_der(&subject_der) {
                    warn!(
                        target: LINK_STATE,
                        "{} presented unverified certificate claiming special peer name {name:?}; ignoring", asm.formatted_link_id(link_id)
                    );
                }
            } else {
                // assign special-peer name if this peer is special
                for name in special_peers::special_peer_names_from_subject_der(&subject_der) {
                    match asm.peer_table.assign_special_name(name, link_id) {
                        Ok(()) => {
                            info!(target: LINK_STATE, "{} assigned special name {name:?}", asm.formatted_link_id(link_id))
                        }
                        Err(_) => {
                            warn!(target: LINK_STATE, "Unable to assign {} special name {name:?}", asm.formatted_link_id(link_id))
                        }
                    }
                }
            }
        }

        debug!(target: LINK_STATE, "{} finished keying.  Starting hello", asm.formatted_link_id(link_id));

        locked_fsm.set_state(LinkState::Helloing);

        // IF this is an adapter, it's expected to issue the hello
        if self.link_type == LinkType::AdapterToNode {
            // Grab public key from keypair to send in hello request
            let pubkey = x25519_dalek::PublicKey::from(&asm.a2a_dh_keypair);
            mgmt::requests::send_hello_request(asm, self.id, pubkey).enqueue();
            self.set_timeout(asm, &mut locked_fsm, config::LINK_HELLO_TIMEOUT);
            debug!(
                target: LINK_STATE,
                "{} sent HelloRequest.  Waiting for other side to respond.", asm.formatted_link_id(link_id)
            );
        }
        // Otherwise we are a node so wait for an adapter to reach out
        Ok(())
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

    fn process_error_response(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        asm.counters.management[ManagementCounterType::PeerHandshakeFailure].increment();
        warn!(target: LINK_STATE, "{}: bringup failed at state {:?}",
            asm.formatted_link_id(link_id),
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
            (LinkType::AdapterToNode, LinkState::Helloing) => {
                // Timeout here means we give up on the link.
                error!(target: LINK_STATE, "{}: timed out in state {:?}", asm.formatted_link_id(self.id), locked_fsm.state);
                locked_fsm.set_state(LinkState::Error);
                drop(locked_fsm);
                return self.initiate_close(asm, TerminateReason::RequestTimedOut);
            }

            (_, LinkState::Active) => {
                match locked_fsm.echo_handle.take() {
                    Some((_start_time, echo_handle)) => {
                        // there was an outstanding echo, and we've timed out
                        echo_handle.abort();
                        self.locked_data.lock().unwrap().echo_timeout += 1;
                        error!(target: LINK_STATE, "{} failed to respond to keep-alive messages", asm.formatted_link_id(self.id));
                        locked_fsm.set_state(LinkState::Error);
                        drop(locked_fsm);
                        return self.initiate_close(asm, TerminateReason::RequestTimedOut);
                    }

                    None => {
                        // no outstanding echo, time for a new one!
                        let link_id = self.id;
                        let task_asm = asm.clone();
                        let jh = tokio::task::spawn_local(async move {
                            match mgmt::requests::send_echo_request(&task_asm, link_id)
                                .acked()
                                .await
                            {
                                Ok(()) => {
                                    // success! poke the state machine
                                    // ignore any errors, that just means we've left Active and are already shutting down the link
                                    let _ = task_asm.process_link_state_event(
                                        link_id,
                                        LinkEvent::ReceivedKeepAliveResponse,
                                    );
                                }

                                // ignore link closed, we are already shutting down
                                Err(mgmt::core::MgmtSendError::LinkClosed) => (),
                            }
                        });

                        // store new echo handle and kick off timeout
                        locked_fsm.echo_handle = Some((Instant::now(), jh.abort_handle()));
                        self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_KEEP_ALIVE_TIMEOUT);
                        Ok(())
                    }
                }
            }

            (_, LinkState::Closing) => {
                // This is a timeout while we are waiting for a terminate response post initiate close.
                // Now we finish the job,
                debug!(target: LINK_STATE, "{} received timeout waiting on terminate response, shutting down link", asm.formatted_link_id(self.id));
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

    /// Nodes only. Check if this is the link to the adapter in front of the visa service
    /// and if so try to de-register this node from the VS and also stop the VSConn.
    ///
    /// If the link is still working then this can also try to send a polite
    /// "de-register" message to the visa service before we shut off our
    /// VSConn processor.
    fn maybe_disconnect_visa_service_client(
        &self,
        asm: &Arc<Assembly>,
        deregister: bool,
        reason: TerminateReason,
    ) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();

        if matches!(reason, TerminateReason::Shutdown) {
            locked_fsm.shutting_down = true;
        }

        if matches!(self.link_type, LinkType::NodeToAdapter) {
            let link_id = self.id;
            let vs_id = asm
                .peer_table
                .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);
            if vs_id.is_some() && vs_id.unwrap().get() == link_id {
                if let Some(vsconn) = asm.vsconn.as_ref() {
                    locked_fsm.set_state(LinkState::Disconnecting(reason));

                    let task_asm = asm.clone();
                    let spawn_hndl = vsconn.clone();
                    tokio::task::spawn_local(async move {
                        debug!(target: LINK_STATE, "deregister of VS peer detected, stopping VSConn (deregister:{deregister})");
                        if let Err(e) = spawn_hndl.stop(deregister).await {
                            error!(target: LINK_STATE, "stop command to VSConn failed: {e}");
                        }
                        debug!(target: LINK_STATE, "VSConn shut down");

                        // ignore error here, it just means we've moved on to another state and got the ACK (very) late
                        let _ = task_asm
                            .process_link_state_event(link_id, LinkEvent::ReceivedDisconnectAck);
                    });

                    return Ok(());
                } // else fallthrough
            } // else fallthrough
        } // else fallthrough

        // else all the above...
        self.continue_close(asm, locked_fsm, reason)
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
        if matches!(self.link_type, LinkType::Internal) {
            return Err(LinkStateError::InvalidOperation(
                "cannot shutdown internal link".to_owned(),
            ));
        }

        let link_id = self.id;
        info!(target: LINK_STATE,"Initiating shutdown on {}", asm.formatted_link_id(link_id));

        self.maybe_disconnect_visa_service_client(asm, true, reason)
    }

    fn process_disconnect_ack(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let locked_fsm = self.locked_fsm.lock().unwrap();
        match (self.link_type, locked_fsm.state) {
            (LinkType::NodeToAdapter, LinkState::Disconnecting(reason)) => {
                debug!(target: LINK_STATE, "{} received disconnect ack", asm.formatted_link_id(self.id));
                self.continue_close(asm, locked_fsm, reason)
            }
            (_, _) => Err(LinkStateError::InvalidOperation(
                "Discarded unsolicited init auth ack".to_string(),
            )),
        }
    }

    /// Continue shutdown of the link.  Occurs after having disconnected
    /// from the visa service (if applicable).
    fn continue_close(
        &self,
        asm: &Arc<Assembly>,
        mut locked_fsm: MutexGuard<LinkStateMachine>,
        reason: TerminateReason,
    ) -> Result<(), LinkStateError> {
        locked_fsm.set_state(LinkState::Closing);

        // If this timeout fires, we end up going to `clean_up_link_state`.
        // If we get a response to our terminate we also go to `clean_up_link_state`.
        self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_TERMINATE_TIMEOUT);
        drop(locked_fsm);
        if let Some(peer) = asm.peer_table.get(self.id) {
            peer.actor_auth.link_down(asm).detach_all();
        }
        let task_asm = asm.clone();
        let ingress_link_id = self.id;
        tokio::task::spawn_local(async move {
            let acked = mgmt::requests::send_terminate_link_or_docking_session(
                &task_asm,
                ingress_link_id,
                reason,
            )
            .acked();
            match acked.await {
                // FIXME why do we never get an ACK?
                Ok(()) => {
                    let _ = task_asm
                        .process_link_state_event(ingress_link_id, LinkEvent::ReceivedTerminateAck);
                }
                Err(mgmt::core::MgmtSendError::LinkClosed) => (),
            }
        });
        Ok(())
    }

    /// Tear down link state.
    /// This sends notice to the visa service that we have lost an actor.
    /// Sends a CloseDone event (which triggers [LinkStateWrapper::complete_close])
    fn clean_up_link_state(&self, asm: &Arc<Assembly>) -> tokio::task::JoinSet<()> {
        let link_id = self.id;
        let mut join_set = tokio::task::JoinSet::new();

        let locked_fsm = self.locked_fsm.lock().unwrap();

        match locked_fsm.state {
            LinkState::Closing | LinkState::Resetting => {
                drop(locked_fsm);
                info!(target: LINK_STATE, "{} is clearing its state", asm.formatted_link_id(link_id));
                if let Some(peer) = asm.peer_table.get(link_id) {
                    join_set = peer.actor_auth.link_down(asm);
                }

                let mut link_data = self.locked_data.lock().unwrap();
                if let Some(aaa_addr) = link_data.aaa_address.take() {
                    if self.link_type == LinkType::AdapterToNode && link_data.installed_aaa {
                        if let Err(err) = asm
                            .tun_ctl
                            .clear_address(aaa_addr.into(), ZPRNET_PREFIX_LEN)
                        {
                            error!(target: LINK_STATE, "cannot clear AAA address: {err}");
                        }
                    }
                    if let Some(pool) = asm.address_pool.lock().unwrap().as_mut() {
                        match pool.release_address(aaa_addr) {
                            Ok(_) => {
                                debug!(target: LINK_STATE, "{} released AAA address {aaa_addr}", asm.formatted_link_id(link_id))
                            }
                            Err(e) => {
                                error!(target: LINK_STATE, "Failed to release AAA address {aaa_addr}: {e:?}")
                            }
                        };
                    }
                }
                link_data.asa_addresses = None;
                link_data.installed_aaa = false;
                drop(link_data);

                asm.peer_table.clear_peer_state(link_id);

                match self.link_type {
                    LinkType::AdapterToNode => {
                        if let Err(err) = asm.tun_ctl.set_carrier(false) {
                            error!(target: LINK_STATE, "cannot disable TUN carrier: {err}");
                        }
                    }
                    LinkType::NodeToAdapter => {}
                    _ => {}
                }

                let task_asm = asm.clone();
                join_set.spawn_local(async move {
                    // NOTE: Any mgmt messages MUST have been sent before this is called
                    km_multiplexor::drop_link(&task_asm, link_id).await;

                    if let Err(e) = task_asm.process_link_state_event(link_id, LinkEvent::CloseDone)
                    {
                        error!(target: LINK_STATE, "Error shutting down {}: {e:?}", task_asm.formatted_link_id(link_id));
                    }
                });
            }
            _ => {
                // Unexpcted call.
                warn!(target: LINK_STATE, "cannot clean_up_link_state in state {:?}", locked_fsm.state);
            }
        }
        join_set
    }

    /// Complete a link shutdown, upon receiving a terminate request or response
    /// Transitions from Closing to Inactive
    /// Generates no packets
    fn complete_close(&self, asm: &Arc<Assembly>) {
        let link_id = self.id;
        info!(target: LINK_STATE, "Shutting down {}", asm.formatted_link_id(link_id));
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
                info!(target: LINK_STATE, "{} has fully shut down", asm.formatted_link_id(link_id));
                if !locked_fsm.shutting_down {
                    drop(locked_fsm);
                    self.setup_restart(asm);
                } else {
                    drop(locked_fsm);
                    asm.drop_peer(link_id); // buh bye!
                }
            }
            _ => {
                error!(
                    target: LINK_STATE,
                    "{} tried to close from state {:?}",
                    asm.formatted_link_id(link_id),
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
            info!(target: LINK_STATE, "Attempting to restart {}", task_asm.formatted_link_id(link_id));
            let _ = task_asm.process_link_state_event(link_id, LinkEvent::Start);
        });
    }

    /// Reset the link, shutting it down and wiping its configuration
    /// Instead of transitioning, the state machine will be destroyed
    /// Sends a Terminate Indication
    pub async fn reset(&self, asm: &Arc<Assembly>) {
        let link_id = self.id;
        info!(target: LINK_STATE,
            "Resetting {} from state {:?}",
            asm.formatted_link_id(link_id),
            self.locked_fsm.lock().unwrap().state
        );
        self.locked_fsm
            .lock()
            .unwrap()
            .set_state(LinkState::Resetting);
        mgmt::requests::send_terminate_link_or_docking_session(
            asm,
            link_id,
            TerminateReason::Reset,
        )
        .enqueue();
        let _ = self.clean_up_link_state(asm).join_all().await;
    }

    /// Handle a terminate link acknowledgement.
    /// This means we sent a terminate request and set a timeout. Timeout is cancelled here
    /// before we proceed with shutting down the link.
    fn process_terminate_ack(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let link_id = self.id;
        info!(target: LINK_STATE,"Received terminate response for {}", asm.formatted_link_id(link_id));
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        match locked_fsm.state {
            LinkState::Closing => {
                locked_fsm.cancel_timeout();
                drop(locked_fsm);
                self.clean_up_link_state(asm).detach_all();
                Ok(())
            }
            _ => Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedTerminateAck",
            )),
        }
    }

    /// Peer has sent a terminate-link message.
    /// May generate an RPC message (over TUN) to the visa service.
    /// Peer has shut down or shutting down so don't expect it to be there anymore.
    ///
    /// Returns Ok unless this is in a state that cannot handle this message.
    fn process_terminate_link(
        &self,
        asm: &Arc<Assembly>,
        reason: TerminateReason,
    ) -> Result<(), LinkStateError> {
        let link_id = self.id;
        info!(target: LINK_STATE,
            "Received terminate for {} with reason {:?}", asm.formatted_link_id(link_id), reason
        );
        self.locked_fsm
            .lock()
            .unwrap()
            .set_state(LinkState::Closing);
        self.clean_up_link_state(asm).detach_all();
        Ok(())
    }

    pub fn process_keep_alive_response(&self, asm: &Arc<Assembly>) -> Result<(), LinkStateError> {
        let mut locked_fsm = self.locked_fsm.lock().unwrap();
        if !matches!(locked_fsm.state, LinkState::Active) {
            // we only expect keep alives responses in Active
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedKeepAliveResponse",
            ));
        }

        let Some((start_time, _echo_handle)) = locked_fsm.echo_handle.take() else {
            // we do not have an outstanding echo request
            return Err(LinkStateError::UnexpectedTransition(
                locked_fsm.state,
                "ReceivedKeepAliveResponse",
            ));
        };

        // we got a successful echo response, track it
        let mut link_data = self.locked_data.lock().unwrap();
        link_data.echo_success += 1;
        link_data
            .latency_data
            .add(Instant::now().duration_since(start_time));
        drop(link_data);

        // delay before kicking off next echo request
        self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_KEEP_ALIVE_PERIOD);

        Ok(())
    }

    /// Common code to enter the `Active` state and kick off our keepalive mechanism
    fn run_active(
        &self,
        asm: &Arc<Assembly>,
        mut locked_fsm: MutexGuard<'_, LinkStateMachine>,
    ) -> Result<(), LinkStateError> {
        locked_fsm.set_state(LinkState::Active);
        asm.counters.management[ManagementCounterType::PeerHandshakeSuccess].increment();
        debug!(target: LINK_STATE, "{} entering active state", asm.formatted_link_id(self.id));

        // kick off our keepalive mechanism
        locked_fsm.echo_handle.take().inspect(|(_, h)| h.abort()); // should already be None (indicating no echo outstanding) but let's be sure
        self.set_timeout(asm, &mut locked_fsm, config::DEFAULT_KEEP_ALIVE_TIMEOUT);

        Ok(())
    }
}

pub(crate) fn get_available_asa_addresses(asm: &Assembly, link_id: LinkId) -> Vec<SocketAddr> {
    let mut asa_addresses = Vec::new();

    let svclist = asm.vs_auth_services.read().unwrap();
    if svclist.is_valid() {
        // If we have a list of services, include them in the response.
        // TODO: The ASA is set as a SocketAddr which doesn't feel quite right.  Maybe should be a URI.
        for authservice in &svclist.services {
            if let Some(sa) = authservice.get_socket_addr() {
                debug!(target: LINK_STATE, "{}: HelloResponse - adding ASA address: {sa}", asm.formatted_link_id(link_id));
                asa_addresses.push(sa);
            } else {
                warn!(target: LINK_STATE, "{}: HelloResponse - service {} has no valid ASA address", asm.formatted_link_id(link_id), authservice.service_id);
            }
        }
    } else {
        warn!(target: LINK_STATE, "{}: HelloResponse - no valid auth services available", asm.formatted_link_id(link_id));
    }

    asa_addresses
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
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::sync::oneshot;
    use tokio::task::LocalSet;

    fn hello_link(link_type: LinkType) -> LinkStateWrapper {
        let link = LinkStateWrapper::new(3, link_type);
        {
            let mut fsm = link.locked_fsm.lock().unwrap();
            fsm.state = LinkState::Helloing;
            fsm.status = LinkStatus::Up;
        }
        link
    }

    #[tokio::test]
    async fn hello_activates_link_and_keepalives_before_actor_authorization() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let link = hello_link(LinkType::AdapterToNode);
                let aaa = "fd5a:5052:0:aaa::1"
                    .parse::<std::net::IpAddr>()
                    .unwrap()
                    .into();
                link.process_hello_response(&asm, ResponseCode::Success, Some(aaa), None, false)
                    .unwrap();
                assert!(link.is_ready());
                assert_eq!(link.aaa_address(), Some(aaa));
                assert!(link.locked_fsm.lock().unwrap().timeout_handle.is_some());
                assert!(asm.get_local_zpr_addrs_std().is_empty());
            })
            .await;
    }

    #[tokio::test]
    async fn ordinary_hello_cannot_succeed_without_aaa() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                let adapter = hello_link(LinkType::AdapterToNode);
                assert!(
                    adapter
                        .process_hello_response(&asm, ResponseCode::Success, None, None, false)
                        .is_err()
                );
                assert!(!adapter.is_ready());
                let node = hello_link(LinkType::NodeToAdapter);
                node.process_hello_request(&asm).unwrap();
                assert!(!node.is_ready());
                assert_eq!(node.get_state(), LinkState::Closing);
            })
            .await;
    }

    #[tokio::test]
    async fn only_designated_vs_bootstrap_can_establish_without_pool() {
        LocalSet::new()
            .run_until(async {
                let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
                asm.peer_table
                    .assign_special_name(SpecialPeerName::VisaServiceAdapter, 3)
                    .unwrap();
                let node = hello_link(LinkType::NodeToAdapter);
                node.process_hello_request(&asm).unwrap();
                assert!(node.is_ready());
                assert!(node.aaa_address().is_none());
                let adapter = hello_link(LinkType::AdapterToNode);
                adapter
                    .process_hello_response(&asm, ResponseCode::Success, None, None, true)
                    .unwrap();
                assert!(adapter.is_ready());
            })
            .await;
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_test() {
        LocalSet::new()
            .run_until(async {
                let sm = Arc::new(Mutex::new(LinkStateMachine::new(1)));
                let (tx, rx) = oneshot::channel();

                set_timeout(&sm, Duration::from_secs(5), tx);

                tokio::time::sleep(Duration::from_secs(4)).await;

                assert!(rx.is_empty());

                tokio::time::sleep(Duration::from_secs(2)).await;

                assert!(rx.await.is_ok());
            })
            .await
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_explicit_cancel_test() {
        LocalSet::new()
            .run_until(async {
                let sm = Arc::new(Mutex::new(LinkStateMachine::new(1)));
                let (tx, rx) = oneshot::channel();

                set_timeout(&sm, Duration::from_secs(5), tx);

                tokio::time::sleep(Duration::from_secs(4)).await;

                sm.lock().unwrap().cancel_timeout();

                tokio::time::sleep(Duration::from_secs(2)).await;

                assert!(rx.await.is_err());
            })
            .await
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_implicit_cancel_test() {
        LocalSet::new()
            .run_until(async {
                let sm = Arc::new(Mutex::new(LinkStateMachine::new(1)));
                let (tx, rx) = oneshot::channel();

                set_timeout(&sm, Duration::from_secs(5), tx);

                tokio::time::sleep(Duration::from_secs(4)).await;

                sm.lock().unwrap().set_state(LinkState::Keying);

                tokio::time::sleep(Duration::from_secs(2)).await;

                assert!(rx.await.is_err());
            })
            .await
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_reschedule_test() {
        LocalSet::new()
            .run_until(async {
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
            })
            .await
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
