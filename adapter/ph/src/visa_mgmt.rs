use crate::assembly::Assembly;
use crate::counters::ManagementCounterType;
use crate::link_state::{LinkEvent, LinkStateError};
use crate::logging::targets::VISA_MGMT;
use crate::visa_table;
use crate::vs_types;
use libnode::{claims, vsapi};
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::num::NonZero;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use tracing::*;
use zpr::vsapi_types;
use zpr::{LinkId, VisaId};
use zpr_utils::net_defs::{IPV6_ADDRESS_SIZE, IpAddress};

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
            Ok(cr) => match cr.status {
                Some(vsapi::StatusCode::SUCCESS) => {
                    if let Some(actor) = cr.actor {
                        info!(target: VISA_MGMT, "link {link_id}: VS authorize_connect returns SUCCESS");
                        if actor.zpr_addr.is_none() {
                            // Really this is a bug in visa service I think.
                            error!(target: VISA_MGMT, "link {link_id} authorized, but no zpr address present in actor");
                            let _ignore_error =
                                task_asm.process_link_state_event(link_id, LinkEvent::Error);
                            return;
                        }
                        let addr_bytes = actor.zpr_addr.unwrap();
                        if addr_bytes.len() != IPV6_ADDRESS_SIZE {
                            // Our ZPR addresses should be IPv6 -- at least for now.
                            error!(target: VISA_MGMT, "link {link_id} authorized, but zpr address is not 16 bytes long: {} bytes", addr_bytes.len());
                            let _ignore_error =
                                task_asm.process_link_state_event(link_id, LinkEvent::Error);
                            return;
                        }
                        let addr_buf: [u8; IPV6_ADDRESS_SIZE] = addr_bytes
                            .try_into()
                            .expect("actor.zpr_addr should be exactly 16 bytes");
                        let zpr_addr = IpAddress::new_from_std(&IpAddr::from(addr_buf));
                        let _ignore_error = task_asm.process_link_state_event(
                            link_id,
                            LinkEvent::ReceivedAuthorizeResponse(zpr_addr),
                        );
                    } else {
                        // This is also a bug in visa service. It must set an access if status == success.
                        error!(target: VISA_MGMT, "link {link_id} authorized, but no actor present");
                        let _ignore_error =
                            task_asm.process_link_state_event(link_id, LinkEvent::Error);
                    }
                }
                Some(vsapi::StatusCode::FAIL) => {
                    warn!(
                        target: VISA_MGMT,
                        "link {link_id}: VS authorize_connect FAILED: {}",
                        cr.reason.unwrap_or("(no reason given)".to_owned())
                    );
                    let _ignore_error =
                        task_asm.process_link_state_event(link_id, LinkEvent::Error);
                }
                _ => {
                    warn!(
                        target: VISA_MGMT,
                        "link {link_id}: VS authorize_connect failed with unexpected status: {:?}",
                        cr.status
                    );
                    let _ignore_error =
                        task_asm.process_link_state_event(link_id, LinkEvent::Error);
                }
            },

            Err(err) => {
                warn!(target: VISA_MGMT, "link {link_id}: VS authorize_connect failed with error: {err}");
                let _ignore_error = task_asm.process_link_state_event(link_id, LinkEvent::Error);
            }
        }
    });
}

/// Creates a ConnectionRequest, unless none is necessary because the link is
/// to the visa service itself.
///
/// `addr` is either UNSPECIFIED or an address requested by the client adapter.
/// If it is a specified address we pass it as the "zpr.addr" claim.
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

    let mut claims = BTreeMap::new();
    if addr != IpAddress::UNSPECIFIED {
        claims.insert(claims::KATTR_EPID.into(), addr.to_string());
    }
    claims.insert(claims::KATTR_CN.into(), cn);

    // issue an Authorize Connect Request to the visa service for this adapter
    let connect_req = libnode::vsapi::ConnectRequest {
        connection_id: Some(123), // unused
        dock_addr: Some(
            IpAddress::new_from_std(&asm.get_local_dock_addr())
                .v6
                .to_vec(),
        ),
        claims: Some(claims),
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
pub fn insert_visa(
    asm: &Arc<Assembly>,
    visa: vsapi_types::Visa,
) -> Result<(VisaId, NonZero<LinkId>), visa_table::VisaTableError> {
    let addr = visa.dst_addr.clone();
    let Some(link_id) = asm.find_egress_link(addr.into()) else {
        asm.counters.management[ManagementCounterType::VisaRequestError].increment();
        return Err(visa_table::VisaTableError::DestNotFound(addr.into()));
    };
    let visa_id = asm.visa_table.write().unwrap().insert_visa(visa)?;
    Ok((visa_id, link_id))
}

/// Given a visa ID, look up the visa in our table to find the destination address
/// then use that to find an egress link.
pub fn get_egress_link_for_visa(
    asm: &Arc<Assembly>,
    visa_id: VisaId,
) -> Result<NonZero<LinkId>, visa_table::VisaTableError> {
    let addr = asm.visa_table.read().unwrap().get_visa_dest_addr(visa_id)?;
    let Some(link_id) = asm.find_egress_link(addr) else {
        return Err(visa_table::VisaTableError::DestNotFound(addr));
    };
    Ok(link_id)
}

pub fn handle_revocation(
    asm: &Arc<Assembly>,
    visa_id: VisaId,
) -> Result<(), visa_table::VisaTableError> {
    asm.visa_table
        .write()
        .unwrap()
        .revoke(&asm.peer_table, visa_id)
}

pub fn handle_services_update(
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
                error!(target: VISA_MGMT, "service descriptor with no address (id={})", service.service_id.unwrap_or_default());
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
