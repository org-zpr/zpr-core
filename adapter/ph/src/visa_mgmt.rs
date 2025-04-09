use crate::assembly::Assembly;
use crate::counters::CounterType;
use crate::link_state::{LinkEvent, LinkStateError};
use crate::logging::targets::VISA_MGMT;
use crate::net_defs::IpAddress;
use crate::visa_table;
use libnode::vsapi;
use std::num::NonZero;
use std::sync::Arc;
use tracing::*;
use zpr::{LinkId, VisaId};

pub fn authorize_connect(
    asm: &Arc<Assembly>,
    link_id: LinkId,
    connect_req: libnode::vsapi::ConnectRequest,
) {
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
                info!(target: VISA_MGMT, "link {link_id} authorized");
                task_asm.process_link_state_event(link_id, LinkEvent::ReceivedAuthorizeResponse)
            }

            Ok(cr) => {
                warn!(
                    target: VISA_MGMT,
                    "link {link_id} authorization rejected: {}",
                    cr.reason.unwrap_or("(no reason given)".to_owned())
                );
                task_asm.process_link_state_event(link_id, LinkEvent::Error)
            }

            Err(err) => {
                warn!(target: VISA_MGMT, "link {link_id} authorization failed: {err}");
                task_asm.process_link_state_event(link_id, LinkEvent::Error)
            }
        }
    });
}

/// Creates a ConnectionRequest, unless none is necessary because the link is
/// to the visa service itself.
pub fn build_connect_request(
    asm: &Arc<Assembly>,
    id: LinkId,
    addr: IpAddress,
) -> Result<Option<libnode::vsapi::ConnectRequest>, LinkStateError> {
    let cn = get_common_name(asm, id)?;

    if cn == zpr::VISA_SERVICE_CN {
        return Ok(None);
    }

    // issue an Authorize Connect Request to the visa service for this adapter
    let connect_req = libnode::vsapi::ConnectRequest {
        connection_id: Some(123), // unused
        dock_addr: Some(
            IpAddress::new_from_std(&asm.local_zpr_addresses[0])
                .v6
                .to_vec(),
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
    Ok(Some(connect_req))
}

fn get_common_name(asm: &Arc<Assembly>, id: LinkId) -> Result<String, LinkStateError> {
    let Some(peer_state) = asm.peer_table.get(id) else {
        return Err(LinkStateError::NotFound(id));
    };

    let Some(sa) = peer_state.get_established_transport_association() else {
        return Err(LinkStateError::InvalidOperation(
            "Attempted to Register Actor Address when SA not established".to_owned(),
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

    debug!(target: VISA_MGMT, "Link {id} CN is {cn}");

    Ok(cn)
}

pub async fn actor_disconnect(asm: Arc<Assembly>, addr: IpAddress) {
    match asm
        .vsconn
        .as_ref()
        .unwrap()
        .actor_disconnect(addr.into())
        .await
    {
        Err(e) => {
            warn!(target: VISA_MGMT, "Failed to disconnect actor {addr} with error {e:?}")
        }
        Ok(()) => debug!(target: VISA_MGMT, "Successfully disconnected actor {addr}"),
    }
}

pub async fn parse_visa(
    asm: &Arc<Assembly>,
    visa: vsapi::VisaHop,
) -> Result<(VisaId, NonZero<LinkId>), visa_table::VisaTableError> {
    let Some(visa) = visa.visa else {
        asm.counters[CounterType::VisaRequestError].increment();
        error!(target: VISA_MGMT, "visa request error: Could not parse visa");
        return Err(visa_table::VisaTableError::ParseError("all".into()));
    };
    // for now, just pull the destination address tether to set up forwarding
    let Some(octets) = visa.dest.clone() else {
        asm.counters[CounterType::VisaRequestError].increment();
        error!(target: VISA_MGMT, "visa request error: Could not parse visa");
        return Err(visa_table::VisaTableError::ParseError(
            "destination address".into(),
        ));
    };
    let Ok(addr) = IpAddress::try_from(octets) else {
        asm.counters[CounterType::VisaRequestError].increment();
        return Err(visa_table::VisaTableError::ParseError(
            "destination address".into(),
        ));
    };
    let Some(link_id) = asm.find_egress_link(addr) else {
        asm.counters[CounterType::VisaRequestError].increment();
        return Err(visa_table::VisaTableError::DestNotFound(addr));
    };
    let visa_id = asm.visa_table.write().await.insert_visa(visa)?;
    Ok((visa_id, link_id))
}

pub async fn handle_revocation(
    asm: &Arc<Assembly>,
    revocation: vsapi::VisaRevocation,
) -> Result<(), visa_table::VisaTableError> {
    let Some(visa_id) = revocation.issuer_id else {
        error!(target: VISA_MGMT, "Visa revocation with no ID");
        return Err(visa_table::VisaTableError::ParseError("issuer_id".into()));
    };

    asm.visa_table
        .write()
        .await
        .revoke(&asm.peer_table, visa_id)
}
