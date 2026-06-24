use crate::auth::AuthBlob;
use crate::counters::ManagementCounterType;
use crate::link_state::{LinkEvent, LinkStateError};
use crate::prelude::*;
use crate::special_peers::SpecialPeerName;
use crate::visa_table;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use libnode::claims;
use std::net::IpAddr;
use std::num::NonZero;
use zpr::packet_info::{LinkId, VisaId};
use zpr::vsapi_types::{self, DisconnectNotice, DisconnectReason};
use zpr_utils::net_defs::IpAddress;

pub fn authorize_connect(
    asm: &Arc<Assembly>,
    link_id: LinkId,
    connect_req: vsapi_types::ConnectRequest,
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
            Ok(cr) => {
                info!(target: VISA_MGMT, "link {link_id}: VS authorize_connect returned successfully");
                match cr.zpr_addr {
                    IpAddr::V4(_) => {
                        // Our ZPR addresses should be IPv6 -- at least for now.
                        error!(target: VISA_MGMT, "link {link_id} authorized, but zpr address is not IPv6");
                        let _ignore_error =
                            task_asm.process_link_state_event(link_id, LinkEvent::Error);
                        return;
                    }
                    IpAddr::V6(_) => {
                        let zpr_addr = IpAddress::new_from_std(&cr.zpr_addr);
                        let _ignore_error = task_asm.process_link_state_event(
                            link_id,
                            LinkEvent::ReceivedAuthorizeResponse(zpr_addr),
                        );
                    }
                }
            }

            Err(err) => {
                warn!(target: VISA_MGMT, "link {link_id}: VS authorize_connect failed with error: {err}");
                let _ignore_error = task_asm.process_link_state_event(link_id, LinkEvent::Error);
            }
        }
    });
}

/// Creates a ConnectRequest, unless none is necessary because the link is
/// to the visa service itself.
///
/// `addr` is either UNSPECIFIED or an address requested by the client adapter.
/// If it is a specified address we pass it as the "zpr.addr" claim.
pub fn build_connect_request(
    asm: &Arc<Assembly>,
    id: LinkId,
    addr: IpAddress,
    blob: &AuthBlob,
) -> Result<Option<vsapi_types::ConnectRequest>, LinkStateError> {
    // Check if this link is "blessed" as the visa service. This happens in link_state and is sensitive
    // to whether the certificate was verified or not.
    {
        let vs_peer = asm
            .peer_table
            .lookup_special_peer(SpecialPeerName::VisaServiceAdapter);
        if let Some(vs_peer_id) = vs_peer {
            if vs_peer_id.get() == id {
                // This link is to the visa service itself, so no connect request is needed.
                return Ok(None);
            }
        }
    }

    let cn = get_common_name(asm, id)?;

    // Convert the adapter's AuthBlob to the vsapi_types AuthBlob for the v2 protocol.
    let vsapi_blob = match blob {
        AuthBlob::SelfSigned(ss) => vsapi_types::AuthBlob::SS(vsapi_types::SelfSignedBlob {
            alg: vsapi_types::ChallengeAlg::RsaSha256Pkcs1v15,
            challenge: BASE64_STANDARD.decode(&ss.challenge).unwrap_or_default(),
            cn: ss.cn.clone(),
            timestamp: ss.ts,
            signature: BASE64_STANDARD.decode(&ss.sig).unwrap_or_default(),
        }),
        AuthBlob::AuthCode(ac) => vsapi_types::AuthBlob::AC(vsapi_types::AuthCodeBlob {
            asa_addr: ac
                .asa
                .parse()
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            code: ac.code.clone(),
            pkce: ac.pkce.clone(),
            client_id: ac.client_id.clone(),
        }),
    };

    let mut request_claims = Vec::new();
    if addr != IpAddress::UNSPECIFIED {
        request_claims.push(vsapi_types::Claim {
            key: claims::key::ZPR_ADDR.into(),
            value: addr.to_string(),
        });
    }
    request_claims.push(vsapi_types::Claim {
        key: claims::key::CN.into(),
        value: cn,
    });

    let connect_req = vsapi_types::ConnectRequest {
        blobs: vec![vsapi_blob],
        claims: request_claims,
        substrate_addr: asm.get_local_dock_addr(),
        dock_interface: 0,
    };
    Ok(Some(connect_req))
}

/// WARNING! Using this ignores whether the certificate was verified or not.
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

/// This uses "RemoteDisconnect" as the reason passed to the visa service.
pub async fn actor_disconnect(asm: Arc<Assembly>, addr: IpAddress) {
    let notice = DisconnectNotice {
        zpr_addr: Some(addr.into()),
        reason: DisconnectReason::RemoteDisconnect,
    };
    match asm.vsconn.as_ref().unwrap().notify_disconnect(notice).await {
        Err(e) => {
            warn!(target: VISA_MGMT, "Failed to disconnect actor {addr} with error {e:?}")
        }
        Ok(()) => debug!(target: VISA_MGMT, "Successfully disconnected actor {addr}"),
    }
}

/// Insert visa into table.
pub fn insert_visa(
    asm: &Arc<Assembly>,
    visa: vsapi_types::Visa,
) -> Result<VisaId, visa_table::VisaTableError> {
    if visa.visa_type != vsapi_types::VisaType::Full {
        panic!("Forward only visas not yet supported")
    }
    let addr = visa.dock_pep.clone().unwrap().dest_addr;
    if asm.find_egress_link(addr.into()).is_none() {
        asm.counters.management[ManagementCounterType::VisaRequestError].increment();
        return Err(visa_table::VisaTableError::DestNotFound(addr.into()));
    }
    let visa_id = asm.visa_table.write().unwrap().insert_visa(visa)?;
    Ok(visa_id)
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
