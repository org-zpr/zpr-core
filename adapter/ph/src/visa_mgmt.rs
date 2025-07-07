use crate::assembly::Assembly;
use crate::counters::CounterType;
use crate::link_state::{LinkEvent, LinkStateError};
use crate::logging::targets::VISA_MGMT;
use crate::net_defs::IpAddress;
use crate::visa_table;
use crate::vs_types;
use libnode::vsapi;
use std::num::NonZero;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
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
    blob: &str,
) -> Result<Option<libnode::vsapi::ConnectRequest>, LinkStateError> {
    let cn = get_common_name(asm, id)?;

    if cn == zpr::VISA_SERVICE_CN {
        return Ok(None);
    }

    // The visa service expects to find the BLOBs in the challenge response buffers.
    let crbufs: Vec<Vec<u8>> = vec![blob.as_bytes().to_vec()];

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
                ("device.zpr.adapter.cn".to_owned(), cn),
            ]
            .into(),
        ),
        challenge: None, // unused
        challenge_responses: Some(crbufs),
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

/// Figure out egress link and insert visa into table.
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

/// Given a visa ID, look up the visa in our table to find the destination address
/// then use that to find an egress link.
pub async fn get_egress_link_for_visa(
    asm: &Arc<Assembly>,
    visa_id: VisaId,
) -> Result<NonZero<LinkId>, visa_table::VisaTableError> {
    let addr = asm.visa_table.read().await.get_visa_dest_addr(visa_id)?;
    let Some(link_id) = asm.find_egress_link(addr) else {
        return Err(visa_table::VisaTableError::DestNotFound(addr));
    };
    Ok(link_id)
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

pub async fn handle_services_update(
    asm: &Arc<Assembly>,
    services: vsapi::ServicesList,
) -> Result<(), visa_table::VisaTableError> {
    let expiration = if let Some(unixts) = services.expiration {
        if unixts == 0 {
            // 0 is a special case, meaning "no expiration"
            None
        } else {
            Some(UNIX_EPOCH + Duration::from_secs(unixts as u64))
        }
    } else {
        error!(target: VISA_MGMT, "visa service sends services list with no expiration set");
        Some(UNIX_EPOCH) // not present? Already expired then.
    };

    let mut vs_auth_services = Vec::new();

    if let Some(services) = services.services {
        debug!(target: VISA_MGMT, "received services update with {} entries", services.len());
        for service in services {
            if service.type_ != vsapi::ServiceType::ACTOR_AUTHENTICATION {
                continue;
            }
            if service.address.is_none() {
                error!(target: VISA_MGMT, "service descriptor with no address (id={}", service.service_id.unwrap_or_default());
                continue;
            }
            match vs_types::ServiceDescriptor::try_from(service) {
                Ok(sd) => {
                    vs_auth_services.push(sd);
                }
                Err(e) => {
                    error!(target: VISA_MGMT, "failed to parse vsapi service descriptor: {e}");
                    continue;
                }
            }
        }
    } else {
        // Got update with nothing.
        debug!(target: VISA_MGMT, "received empty services update, clearing vs_auth_services");
    }
    debug!(target: VISA_MGMT, "updating auth services with {} entries, expires at {expiration:?}", vs_auth_services.len());
    // The update is always a complete replacement of the list of services, and may be empty.
    let mut svcs = asm.vs_auth_services.write().unwrap();
    svcs.update(expiration, vs_auth_services);
    Ok(())
}
