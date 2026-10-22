//! Single-actor authorization, independent of the encrypted dock link.

use crate::auth::{self, AuthBlob, AuthError};
use crate::counters::ManagementCounterType;
use crate::link_state::LinkType;
use crate::mgmt::handlers::{HandleMgmtError, HandleMgmtResult};
use crate::mgmt::txn_mgr::{TxnHandle, TxnId};
use crate::prelude::*;
use crate::special_peers::SpecialPeerName;
use crate::zdp::AuthenticationStatus;
use crate::{mgmt, pki, visa_mgmt};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::oneshot;
use zerocopy::IntoBytes;
use zpr::addrs::ZPRNET_PREFIX_LEN;
use zpr::vsapi_types::Connection;
use zpr_utils::net_defs::IpAddress;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorState {
    WaitingForLink,
    RequestingAuthentication,
    AwaitingEvidence,
    Authenticating,
    AcquiringAddress,
    Authorizing,
    AbandoningAuthentication,
    RetryBackoff,
    Rejected,
    Authorized,
}

pub struct AuthenticationOffer {
    pub status: AuthenticationStatus,
    pub challenge: Option<auth::ZdpInitAuthenticationPayload>,
    pub asa_addresses: Vec<SocketAddr>,
}

enum Reply {
    Offer(AuthenticationOffer),
    Grant(AuthenticationStatus, Vec<IpAddress>),
}

struct ActorData {
    state: ActorState,
    generation: u64,
    txn: Option<TxnHandle>,
    remote_txn: Option<TxnId>,
    challenge: Option<auth::ZdpInitAuthenticationPayload>,
    reply: Option<oneshot::Sender<Reply>>,
    worker: Option<tokio::task::AbortHandle>,
    reason: Option<String>,
    installed_address: Option<IpAddress>,
}

pub struct ActorAuthorization {
    id: LinkId,
    link_type: LinkType,
    data: Mutex<ActorData>,
    addresses: rcu::RcuBox<Vec<IpAddress>>,
}

impl ActorAuthorization {
    pub fn new(id: LinkId, link_type: LinkType) -> Self {
        Self {
            id,
            link_type,
            data: Mutex::new(ActorData {
                state: ActorState::WaitingForLink,
                generation: 0,
                txn: None,
                remote_txn: None,
                challenge: None,
                reply: None,
                worker: None,
                reason: None,
                installed_address: None,
            }),
            addresses: rcu::RcuBox::new(Vec::new()),
        }
    }

    pub fn addresses(&self) -> Vec<IpAddress> {
        self.addresses.get().clone()
    }

    pub fn owns_address(&self, addr: &IpAddress) -> bool {
        self.addresses.get().contains(addr)
    }

    pub fn add_internal_address(&self, addr: IpAddress) {
        assert_eq!(self.link_type, LinkType::Internal);
        self.addresses
            .update(|old| {
                let mut addresses = old.clone();
                addresses.push(addr);
                Some(addresses)
            })
            .unwrap();
    }

    fn set_addresses(&self, addresses: Vec<IpAddress>) {
        self.addresses.update(|_| Some(addresses.clone())).unwrap();
    }

    pub fn link_ready(self: &Arc<Self>, asm: &Arc<Assembly>) {
        if self.link_type != LinkType::AdapterToNode {
            return;
        }
        let mut data = self.data.lock().unwrap();
        if data
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            return;
        }
        data.generation = data.generation.wrapping_add(1);
        if asm.actor_rejected.load(Ordering::Acquire) {
            data.state = ActorState::Rejected;
            return;
        }
        let actor = self.clone();
        let asm = asm.clone();
        data.worker = Some(
            tokio::task::spawn_local(async move {
                actor.run(&asm).await;
            })
            .abort_handle(),
        );
    }

    fn prepare_reply(&self, txn: &TxnHandle, state: ActorState) -> oneshot::Receiver<Reply> {
        let (tx, rx) = oneshot::channel();
        let mut data = self.data.lock().unwrap();
        data.state = state;
        data.txn = Some(txn.clone());
        data.reply = Some(tx);
        rx
    }

    async fn run(self: &Arc<Self>, asm: &Arc<Assembly>) {
        let mut backoff = config::ACTOR_AUTH_RETRY_INITIAL;
        loop {
            let Some(peer) = asm.peer_table.get(self.id) else {
                return;
            };
            let txn = peer.txn_mgr.open().await;
            drop(peer);
            let reply = self.prepare_reply(&txn, ActorState::RequestingAuthentication);
            if mgmt::requests::send_start_authentication(asm, self.id, txn.id())
                .await
                .is_err()
            {
                return;
            }
            let Ok(Reply::Offer(offer)) = reply.await else {
                error!(target: LINK_STATE, "{}: actor exchange ended without an authentication offer", asm.formatted_link_id(self.id));
                return;
            };
            let outcome = if offer.status == AuthenticationStatus::Success {
                self.data.lock().unwrap().state = ActorState::Authenticating;
                let evidence = self.authenticate(asm, offer).await.and_then(|blob| {
                    mgmt::requests::validate_acquire_zpr_address_request(
                        &asm.config.get().zpr_addr,
                        blob.as_bytes(),
                    )?;
                    Ok(blob)
                });
                match evidence {
                    Ok(blob) => {
                        let requested = asm.config.get().zpr_addr.clone();
                        let reply = self.prepare_reply(&txn, ActorState::AcquiringAddress);
                        if mgmt::requests::send_acquire_zpr_address_request(
                            asm,
                            self.id,
                            txn.id(),
                            &requested,
                            Some(blob.as_bytes()),
                        )
                        .await
                        .is_err()
                        {
                            return;
                        }
                        match reply.await {
                            Ok(Reply::Grant(status, addresses))
                                if status == AuthenticationStatus::Success =>
                            {
                                self.install_address(asm, addresses[0]);
                                return;
                            }
                            Ok(Reply::Grant(status, _)) => {
                                self.data.lock().unwrap().reason = Some(format!(
                                    "node returned {status:?} for actor authorization"
                                ));
                                status
                            }
                            _ => {
                                error!(target: LINK_STATE, "{}: actor exchange ended without an address grant", asm.formatted_link_id(self.id));
                                return;
                            }
                        }
                    }
                    Err(err) => {
                        warn!(target: LINK_STATE, "{}: actor authentication failed: {err}", asm.formatted_link_id(self.id));
                        if matches!(err, AuthError::Rejected(_)) {
                            // Link loss during abandonment must not undo an explicit denial.
                            asm.actor_rejected.store(true, Ordering::Release);
                        }
                        self.data.lock().unwrap().reason = Some(err.to_string());
                        self.data.lock().unwrap().state = ActorState::AbandoningAuthentication;
                        if mgmt::requests::send_abandon_authentication(asm, self.id, txn.id())
                            .acked()
                            .await
                            .is_err()
                        {
                            return;
                        }
                        if matches!(err, AuthError::Rejected(_)) {
                            AuthenticationStatus::Rejected
                        } else {
                            AuthenticationStatus::Retryable
                        }
                    }
                }
            } else {
                self.data.lock().unwrap().reason = Some(format!(
                    "node returned {:?} for authentication start",
                    offer.status
                ));
                offer.status
            };
            {
                let mut data = self.data.lock().unwrap();
                data.txn = None;
                data.reply = None;
            }
            drop(txn);
            if outcome == AuthenticationStatus::Rejected {
                asm.actor_rejected.store(true, Ordering::Release);
                self.data.lock().unwrap().state = ActorState::Rejected;
                asm.counters.management[ManagementCounterType::ActorAuthorizationRejected]
                    .increment();
                warn!(target: LINK_STATE, "{}: actor authorization rejected; restart adapter to retry", asm.formatted_link_id(self.id));
                return;
            }
            self.data.lock().unwrap().state = ActorState::RetryBackoff;
            asm.counters.management[ManagementCounterType::ActorAuthorizationRetry].increment();
            warn!(target: LINK_STATE, "{}: actor authorization temporarily unavailable; retrying after backoff", asm.formatted_link_id(self.id));
            let mut random = [0u8; 2];
            aws_lc_rs::rand::fill(&mut random).expect("retry jitter entropy");
            let (delay, next) = retry_delay(backoff, u16::from_be_bytes(random));
            tokio::time::sleep(delay).await;
            backoff = next;
        }
    }

    async fn authenticate(
        &self,
        asm: &Arc<Assembly>,
        offer: AuthenticationOffer,
    ) -> Result<String, AuthError> {
        let cfg = asm.config.get();
        if let (Some(bootstrap), Some(challenge)) = (&cfg.bootstrap, &offer.challenge) {
            return bootstrap.authenticate(challenge);
        }
        let Some(auth) = cfg.rsaoauth.as_ref() else {
            return Err(AuthError::Rejected(
                "no supported actor authentication method configured".into(),
            ));
        };
        let Some(asa) = offer.asa_addresses.first() else {
            return Err(AuthError::AuthError(
                "no authentication service available".into(),
            ));
        };
        let aaa = asm
            .peer_table
            .get(self.id)
            .and_then(|p| p.link_state_machine.aaa_address())
            .ok_or_else(|| AuthError::AuthError("external authentication requires AAA".into()))?;
        let cert = pki::from_pem(auth::HARD_CODED_BAS_TLS_CERT_PEM.as_bytes())
            .map_err(|e| AuthError::FormatError(e.to_string()))?;
        let blob = tokio::time::timeout(
            config::ACTOR_AUTHENTICATION_TIMEOUT,
            auth.authenticate(*asa, cert, aaa.into()),
        )
        .await
        .map_err(|_| AuthError::AuthError("authentication service timed out".into()))??;
        Ok(blob.encode())
    }

    fn install_address(&self, asm: &Arc<Assembly>, addr: IpAddress) {
        let mut data = self.data.lock().unwrap();
        data.txn = None;
        let install = asm.tun_ctl.has_address(addr.into()).and_then(|existing| {
            if existing {
                Ok(false)
            } else {
                asm.tun_ctl
                    .add_address(addr.into(), ZPRNET_PREFIX_LEN)
                    .map(|()| true)
            }
        });
        let owned = match install {
            Ok(owned) => owned,
            Err(err) => {
                error!(target: LINK_STATE, "{}: cannot install authorized actor address: {err}", asm.formatted_link_id(self.id));
                data.reason = Some(err.to_string());
                drop(data);
                // The node has committed this registration. Link teardown reconciles it.
                if let Err(err) =
                    asm.process_link_state_event(self.id, crate::link_state::LinkEvent::Error)
                {
                    error!(target: LINK_STATE, "cannot close link after address installation failure: {err}");
                }
                return;
            }
        };
        data.installed_address = owned.then_some(addr);
        data.state = ActorState::Authorized;
        data.reason = None;
        self.set_addresses(vec![addr]);
        asm.counters.management[ManagementCounterType::ActorAuthorizationSuccess].increment();
        info!(target: LINK_STATE, "{}: actor authorized as {addr}", asm.formatted_link_id(self.id));
    }

    pub fn receive_offer(&self, txn: TxnId, offer: AuthenticationOffer) -> HandleMgmtResult {
        self.deliver_reply(
            txn,
            ActorState::RequestingAuthentication,
            Reply::Offer(offer),
        )
    }

    pub fn receive_grant(
        &self,
        txn: TxnId,
        status: AuthenticationStatus,
        addresses: Vec<IpAddress>,
    ) -> HandleMgmtResult {
        if (status == AuthenticationStatus::Success && addresses.len() != 1)
            || (status != AuthenticationStatus::Success && !addresses.is_empty())
        {
            return Err(HandleMgmtError::BadStructure);
        }
        self.deliver_reply(
            txn,
            ActorState::AcquiringAddress,
            Reply::Grant(status, addresses),
        )
    }

    fn deliver_reply(&self, txn: TxnId, state: ActorState, reply: Reply) -> HandleMgmtResult {
        let mut data = self.data.lock().unwrap();
        if self.link_type != LinkType::AdapterToNode
            || data.state != state
            || data.txn.as_ref().map(TxnHandle::id) != Some(txn)
        {
            return Err(HandleMgmtError::UnknownTransaction);
        }
        data.reply
            .take()
            .ok_or(HandleMgmtError::UnknownTransaction)?
            .send(reply)
            .map_err(|_| HandleMgmtError::UnknownTransaction)
    }

    pub fn start_remote(&self, asm: &Arc<Assembly>, txn: TxnId) -> HandleMgmtResult {
        self.require_node_link(asm)?;
        let peer = asm
            .peer_table
            .get(self.id)
            .ok_or(HandleMgmtError::LinkClosed)?;
        let mut data = self.data.lock().unwrap();
        if data.remote_txn.is_some() || !self.addresses.get().is_empty() {
            return Err(HandleMgmtError::MessageNotPermitted);
        }
        let challenge = auth::ZdpInitAuthenticationPayload::new(&peer.auth_key);
        data.generation = data.generation.wrapping_add(1);
        data.state = ActorState::AwaitingEvidence;
        data.remote_txn = Some(txn);
        data.challenge = Some(challenge.clone());
        drop(data);
        mgmt::requests::send_init_authentication_request(
            asm,
            self.id,
            txn,
            AuthenticationStatus::Success,
            crate::zdp::init_authentication_flags::BOOTSTRAP_SUPPORT,
            challenge,
            &crate::link_state::get_available_asa_addresses(asm, self.id),
        )
        .enqueue();
        Ok(())
    }

    pub fn abandon_remote(&self, asm: &Arc<Assembly>, txn: TxnId) -> HandleMgmtResult {
        self.require_node_link(asm)?;
        let mut data = self.data.lock().unwrap();
        if data.state != ActorState::AwaitingEvidence || data.remote_txn != Some(txn) {
            return Err(HandleMgmtError::UnknownTransaction);
        }
        data.remote_txn = None;
        data.challenge = None;
        data.state = ActorState::WaitingForLink;
        Ok(())
    }

    fn require_node_link(&self, asm: &Assembly) -> HandleMgmtResult {
        if self.link_type != LinkType::NodeToAdapter || !asm.is_link_ready(self.id) {
            return Err(HandleMgmtError::MessageNotPermitted);
        }
        Ok(())
    }

    pub fn acquire_remote(
        self: &Arc<Self>,
        asm: &Arc<Assembly>,
        txn: TxnId,
        addrs: Option<Vec<IpAddress>>,
        blob: String,
    ) -> HandleMgmtResult {
        self.require_node_link(asm)?;
        if addrs.as_ref().is_some_and(|addresses| addresses.len() > 1) {
            return Err(HandleMgmtError::BadStructure);
        }
        let (generation, challenge) = {
            let mut data = self.data.lock().unwrap();
            if data.state != ActorState::AwaitingEvidence || data.remote_txn != Some(txn) {
                return Err(HandleMgmtError::UnknownTransaction);
            }
            data.state = ActorState::Authorizing;
            (
                data.generation,
                data.challenge
                    .take()
                    .ok_or(HandleMgmtError::MessageNotPermitted)?,
            )
        };
        let requested_addr = addrs
            .and_then(|a| a.first().copied())
            .unwrap_or(IpAddress::UNSPECIFIED);
        let peer = asm
            .peer_table
            .get(self.id)
            .ok_or(HandleMgmtError::LinkClosed)?;
        let blob = match auth::decode_blob(&blob) {
            Ok(blob) => blob,
            Err(err) => {
                warn!(target: LINK_STATE, "{}: invalid actor evidence: {err}", asm.formatted_link_id(self.id));
                return self.finish_remote(
                    asm,
                    generation,
                    txn,
                    AuthenticationStatus::Rejected,
                    None,
                );
            }
        };
        if let AuthBlob::SelfSigned(ss) = &blob {
            let expected = BASE64_STANDARD.encode(challenge.as_bytes());
            if ss.challenge != expected || ss.verify_blob_challenge(&peer.auth_key).is_err() {
                warn!(target: LINK_STATE, "{}: actor challenge verification failed", asm.formatted_link_id(self.id));
                return self.finish_remote(
                    asm,
                    generation,
                    txn,
                    AuthenticationStatus::Rejected,
                    None,
                );
            }
        }
        let req = match visa_mgmt::build_connect_request(
            asm,
            requested_addr,
            &blob,
            *peer.a2a_dh_pubkey.get(),
        ) {
            Ok(req) => req,
            Err(err) => {
                warn!(target: LINK_STATE, "{}: invalid actor authorization request: {err}", asm.formatted_link_id(self.id));
                return self.finish_remote(
                    asm,
                    generation,
                    txn,
                    AuthenticationStatus::Rejected,
                    None,
                );
            }
        };
        let is_vs = asm
            .peer_table
            .lookup_special_peer(SpecialPeerName::VisaServiceAdapter)
            .is_some_and(|id| id.get() == self.id);
        if is_vs {
            if requested_addr == IpAddress::UNSPECIFIED || !matches!(blob, AuthBlob::SelfSigned(_))
            {
                return self.finish_remote(
                    asm,
                    generation,
                    txn,
                    AuthenticationStatus::Rejected,
                    None,
                );
            }
            *asm.deferred_vs_connect.lock().unwrap() = Some((self.id, requested_addr, req));
            return self.finish_remote(
                asm,
                generation,
                txn,
                AuthenticationStatus::Success,
                Some(requested_addr),
            );
        }
        let actor = self.clone();
        let asm = asm.clone();
        let worker_asm = asm.clone();
        let handle = tokio::task::spawn_local(async move {
            let result = visa_mgmt::authorize_connect(&worker_asm, req).await;
            actor
                .authorization_result(&worker_asm, generation, txn, result)
                .await;
        });
        // Keep in-flight VS work alive on link loss so late success can be deregistered.
        let _ = handle;
        Ok(())
    }

    async fn authorization_result(
        &self,
        asm: &Arc<Assembly>,
        generation: u64,
        txn: TxnId,
        result: Result<Connection, libnode::error::VSApiError>,
    ) {
        let current = {
            let data = self.data.lock().unwrap();
            data.generation == generation
                && data.remote_txn == Some(txn)
                && data.state == ActorState::Authorizing
        };
        match result {
            Ok(conn) if !current => {
                visa_mgmt::actor_disconnect(asm.clone(), IpAddress::new_from_std(&conn.zpr_addr))
                    .await;
            }
            Ok(conn) => {
                let addr = IpAddress::new_from_std(&conn.zpr_addr);
                if !conn.zpr_addr.is_ipv6() || conn.zpr_addr.is_unspecified() {
                    error!(target: LINK_STATE, "{}: VS returned an invalid actor address", asm.formatted_link_id(self.id));
                    visa_mgmt::actor_disconnect(asm.clone(), addr).await;
                    self.report_finish(asm, generation, txn, AuthenticationStatus::Retryable, None);
                } else if let Err(err) = self.finish_remote(
                    asm,
                    generation,
                    txn,
                    AuthenticationStatus::Success,
                    Some(addr),
                ) {
                    warn!(target: LINK_STATE, "{}: actor link closed before registration could be committed: {err}", asm.formatted_link_id(self.id));
                    visa_mgmt::actor_disconnect(asm.clone(), addr).await;
                }
            }
            Err(err) if current => {
                warn!(target: LINK_STATE, "{}: VS actor authorization failed: {err}", asm.formatted_link_id(self.id));
                let status = visa_mgmt::authorization_error_status(&err);
                self.report_finish(asm, generation, txn, status, None);
            }
            Err(err) => {
                warn!(target: LINK_STATE, "{}: abandoned VS authorization failed: {err}", asm.formatted_link_id(self.id));
            }
        }
    }

    fn report_finish(
        &self,
        asm: &Arc<Assembly>,
        generation: u64,
        txn: TxnId,
        status: AuthenticationStatus,
        addr: Option<IpAddress>,
    ) {
        if let Err(err) = self.finish_remote(asm, generation, txn, status, addr) {
            error!(target: LINK_STATE, "{}: cannot complete actor authorization: {err}", asm.formatted_link_id(self.id));
        }
    }

    fn finish_remote(
        &self,
        asm: &Arc<Assembly>,
        generation: u64,
        txn: TxnId,
        status: AuthenticationStatus,
        addr: Option<IpAddress>,
    ) -> HandleMgmtResult {
        let mut data = self.data.lock().unwrap();
        if data.generation != generation || data.remote_txn != Some(txn) {
            return Err(HandleMgmtError::UnknownTransaction);
        }
        data.remote_txn = None;
        data.challenge = None;
        data.state = if status == AuthenticationStatus::Success {
            ActorState::Authorized
        } else {
            ActorState::WaitingForLink
        };
        if let Some(addr) = addr {
            self.set_addresses(vec![addr]);
        }
        drop(data);
        let addrs: Vec<IpAddr> = addr.into_iter().map(Into::into).collect();
        mgmt::requests::send_grant_zpr_address_request(asm, self.id, txn, status, &addrs).enqueue();
        Ok(())
    }

    pub fn link_down(&self, asm: &Arc<Assembly>) -> tokio::task::JoinSet<()> {
        let mut data = self.data.lock().unwrap();
        data.generation = data.generation.wrapping_add(1);
        if let Some(worker) = data.worker.take() {
            worker.abort();
        }
        data.reply = None;
        data.txn = None;
        data.remote_txn = None;
        data.challenge = None;
        data.state = ActorState::WaitingForLink;
        if let Some(addr) = data.installed_address.take() {
            if let Err(err) = asm.tun_ctl.clear_address(addr.into(), ZPRNET_PREFIX_LEN) {
                error!(target: LINK_STATE, "{}: cannot clear actor address: {err}", asm.formatted_link_id(self.id));
            }
        }
        let mut work = tokio::task::JoinSet::new();
        if self.link_type == LinkType::NodeToAdapter {
            let is_vs = asm
                .peer_table
                .lookup_special_peer(SpecialPeerName::VisaServiceAdapter)
                .is_some_and(|id| id.get() == self.id);
            if !is_vs {
                for addr in self.addresses() {
                    work.spawn_local(visa_mgmt::actor_disconnect(asm.clone(), addr));
                }
            }
        }
        self.set_addresses(Vec::new());
        if self.link_type == LinkType::AdapterToNode {
            asm.elt.clear();
            asm.dlt.clear();
        }
        work
    }
}

fn retry_delay(backoff: Duration, random: u16) -> (Duration, Duration) {
    let backoff = backoff.min(config::ACTOR_AUTH_RETRY_MAX);
    let jitter = Duration::from_millis(u64::from(random) % 250);
    (
        (backoff + jitter).min(config::ACTOR_AUTH_RETRY_MAX),
        (backoff * 2).min(config::ACTOR_AUTH_RETRY_MAX),
    )
}

impl fmt::Display for ActorAuthorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let data = self.data.lock().unwrap();
        writeln!(f, "  Actor state: {:?}", data.state)?;
        writeln!(f, "  Actor addresses: {:?}", &*self.addresses.get())?;
        if let Some(reason) = &data.reason {
            writeln!(f, "  Actor failure: {reason}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::mgmt::txn_mgr::TxnMgr;
    use crate::tun_ctl::TunCtl;

    fn actor() -> Arc<ActorAuthorization> {
        Arc::new(ActorAuthorization::new(
            DOCK_LINK_ID,
            LinkType::AdapterToNode,
        ))
    }

    fn offer() -> AuthenticationOffer {
        AuthenticationOffer {
            status: AuthenticationStatus::Success,
            challenge: Some(auth::ZdpInitAuthenticationPayload::new(&[42; 32])),
            asa_addresses: Vec::new(),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn transaction_spans_offer_and_delayed_grant() {
        let actor = actor();
        let mgr = Arc::new(TxnMgr::new());
        let txn = mgr.open().await;
        let unrelated = mgr.open().await;
        let offer_rx = actor.prepare_reply(&txn, ActorState::RequestingAuthentication);
        assert!(actor.receive_offer(unrelated.id(), offer()).is_err());
        actor.receive_offer(txn.id(), offer()).unwrap();
        assert!(matches!(offer_rx.await.unwrap(), Reply::Offer(_)));
        let mut grant_rx = actor.prepare_reply(&txn, ActorState::AcquiringAddress);
        tokio::time::advance(Duration::from_secs(600)).await;
        assert!(matches!(
            grant_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(
            actor.data.lock().unwrap().state,
            ActorState::AcquiringAddress
        );
        assert_eq!(actor.data.lock().unwrap().txn.as_ref().unwrap(), &txn);
        let address: IpAddress = "::42".parse::<IpAddr>().unwrap().into();
        actor
            .receive_grant(txn.id(), AuthenticationStatus::Success, vec![address])
            .unwrap();
        assert!(matches!(
            grant_rx.await.unwrap(),
            Reply::Grant(AuthenticationStatus::Success, _)
        ));
    }

    #[tokio::test]
    async fn invalid_grant_does_not_consume_reply() {
        let actor = actor();
        let mgr = Arc::new(TxnMgr::new());
        let txn = mgr.open().await;
        let rx = actor.prepare_reply(&txn, ActorState::AcquiringAddress);
        assert!(
            actor
                .receive_grant(txn.id(), AuthenticationStatus::Success, Vec::new())
                .is_err()
        );
        assert!(
            actor
                .receive_grant(
                    txn.id(),
                    AuthenticationStatus::Rejected,
                    vec![IpAddress::UNSPECIFIED],
                )
                .is_err()
        );
        actor
            .receive_grant(txn.id(), AuthenticationStatus::Retryable, Vec::new())
            .unwrap();
        assert!(matches!(
            rx.await.unwrap(),
            Reply::Grant(AuthenticationStatus::Retryable, _)
        ));
    }

    #[tokio::test]
    async fn teardown_releases_transaction_and_rejects_stale_reply() {
        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        let actor = actor();
        let mgr = Arc::new(TxnMgr::new());
        let txn = mgr.open().await;
        let id = txn.id();
        let reply = actor.prepare_reply(&txn, ActorState::RequestingAuthentication);
        drop(txn);
        assert!(mgr.get(id).is_some());
        let generation = actor.data.lock().unwrap().generation;
        assert!(actor.link_down(&asm).is_empty());
        assert!(mgr.get(id).is_none());
        assert!(reply.await.is_err());
        assert!(actor.receive_offer(id, offer()).is_err());
        assert_ne!(actor.data.lock().unwrap().generation, generation);
    }

    #[tokio::test]
    async fn actor_transaction_remains_reserved_across_allocator_wraparound() {
        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        let actor = actor();
        let mgr = Arc::new(TxnMgr::new());
        let txn = mgr.open().await;
        let id = txn.id();
        let _reply = actor.prepare_reply(&txn, ActorState::AcquiringAddress);
        drop(txn);
        for _ in 0..u16::MAX {
            let unrelated = mgr.try_open().unwrap();
            assert_ne!(unrelated.id(), id);
        }
        assert!(mgr.try_open().is_none());
        actor.link_down(&asm);
        assert_eq!(mgr.try_open().unwrap().id(), id);
    }

    #[tokio::test]
    async fn stale_node_completion_cannot_install_an_address() {
        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        let actor = ActorAuthorization::new(3, LinkType::NodeToAdapter);
        {
            let mut data = actor.data.lock().unwrap();
            data.remote_txn = Some(42);
            data.generation = 1;
            data.state = ActorState::Authorizing;
        }
        assert!(actor.link_down(&asm).is_empty());
        assert!(
            actor
                .finish_remote(
                    &asm,
                    1,
                    42,
                    AuthenticationStatus::Success,
                    Some("::42".parse::<IpAddr>().unwrap().into()),
                )
                .is_err()
        );
        assert!(actor.addresses().is_empty());
    }

    #[tokio::test]
    async fn rejection_latch_survives_link_reconnect() {
        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        let actor = actor();
        asm.actor_rejected.store(true, Ordering::Release);
        actor.link_down(&asm);
        actor.link_ready(&asm);
        let data = actor.data.lock().unwrap();
        assert_eq!(data.state, ActorState::Rejected);
        assert!(data.worker.is_none());
        assert!(data.txn.is_none());
    }

    #[test]
    fn retry_backoff_and_jitter_have_a_hard_cap() {
        let mut backoff = config::ACTOR_AUTH_RETRY_INITIAL;
        for _ in 0..20 {
            let (delay, next) = retry_delay(backoff, 249);
            assert!(delay >= backoff);
            assert!(delay <= config::ACTOR_AUTH_RETRY_MAX);
            assert_eq!(next, (backoff * 2).min(config::ACTOR_AUTH_RETRY_MAX));
            backoff = next;
        }
        assert_eq!(retry_delay(backoff, 249), (backoff, backoff));
    }

    #[derive(Default)]
    struct TunState {
        addresses: Vec<IpAddr>,
        additions: usize,
        removals: usize,
    }

    struct RecordingTun(Arc<Mutex<TunState>>);

    impl TunCtl for RecordingTun {
        fn has_address(&self, addr: IpAddr) -> std::io::Result<bool> {
            Ok(self.0.lock().unwrap().addresses.contains(&addr))
        }
        fn set_carrier(&self, _: bool) -> std::io::Result<()> {
            Ok(())
        }
        fn add_address(&self, addr: IpAddr, _: u8) -> std::io::Result<()> {
            let mut state = self.0.lock().unwrap();
            state.additions += 1;
            state.addresses.push(addr);
            Ok(())
        }
        fn add_authentication_address(&self, addr: IpAddr, prefix_len: u8) -> std::io::Result<()> {
            self.add_address(addr, prefix_len)
        }
        fn clear_address(&self, addr: IpAddr, _: u8) -> std::io::Result<()> {
            let mut state = self.0.lock().unwrap();
            state.removals += 1;
            state.addresses.retain(|a| *a != addr);
            Ok(())
        }
    }

    #[tokio::test]
    async fn teardown_preserves_external_addresses_and_removes_owned_addresses() {
        let address: IpAddr = "fd5a:5052::42".parse().unwrap();
        for external in [false, true] {
            let tun = Arc::new(Mutex::new(TunState {
                addresses: if external { vec![address] } else { Vec::new() },
                ..TunState::default()
            }));
            let asm = Arc::new(create_assembly(TestAssemblyBuilder {
                tun_ctl: Some(Box::new(RecordingTun(tun.clone()))),
                ..TestAssemblyBuilder::new()
            }));
            let actor = actor();
            actor.install_address(&asm, address.into());
            assert!(actor.owns_address(&address.into()));
            assert_eq!(actor.data.lock().unwrap().state, ActorState::Authorized);
            assert_eq!(tun.lock().unwrap().additions, usize::from(!external));
            actor.link_down(&asm);
            assert!(!actor.owns_address(&address.into()));
            let tun = tun.lock().unwrap();
            assert_eq!(tun.addresses.contains(&address), external);
            assert_eq!(tun.removals, usize::from(!external));
        }
    }
}
