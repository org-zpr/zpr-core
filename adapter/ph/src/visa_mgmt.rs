use crate::auth::AuthBlob;
use crate::counters::ManagementCounterType;
use crate::link_state::LinkStateError;
use crate::prelude::*;
use crate::visa_table;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use libnode::claims;
use libnode::error::VSApiError;
use std::num::NonZero;
use zpr::vsapi_types::{self, DisconnectNotice, DisconnectReason};
use zpr_utils::net_defs::IpAddress;

/// Register the visa service adapter with the visa service, now that the node can reach it.
pub async fn send_deferred_vs_connect(
    asm: &Arc<Assembly>,
    link_id: LinkId,
    assigned_addr: IpAddress,
    connect_req: vsapi_types::ConnectRequest,
) -> Result<(), VSApiError> {
    let conn = asm
        .vsconn
        .as_ref()
        .unwrap()
        .authorize_connect(connect_req)
        .await?;

    if IpAddress::new_from_std(&conn.zpr_addr) != assigned_addr {
        return Err(VSApiError::CommandFailed(format!(
            "visa service granted {} to the visa service adapter, which is already assigned {assigned_addr}",
            conn.zpr_addr
        )));
    }

    info!(target: VISA_MGMT, "{}: visa service adapter registered with the visa service as {}",
        asm.formatted_link_id(link_id), conn.zpr_addr);
    Ok(())
}

pub async fn authorize_connect(
    asm: &Arc<Assembly>,
    connect_req: vsapi_types::ConnectRequest,
) -> Result<vsapi_types::Connection, VSApiError> {
    asm.vsconn
        .as_ref()
        .ok_or(VSApiError::ConnClosed)?
        .authorize_connect(connect_req)
        .await
}

pub fn authorization_error_status(err: &VSApiError) -> crate::zdp::AuthenticationStatus {
    use crate::zdp::AuthenticationStatus;
    use vsapi_types::ErrorCode;
    match err {
        VSApiError::AuthFailed(_) => AuthenticationStatus::Rejected,
        VSApiError::CodedError(e)
            if matches!(
                e.code,
                ErrorCode::AuthRequired
                    | ErrorCode::InvalidSignature
                    | ErrorCode::AuthError
                    | ErrorCode::ParamError
                    | ErrorCode::InvalidOperation
                    | ErrorCode::NotFound
            ) =>
        {
            AuthenticationStatus::Rejected
        }
        _ => AuthenticationStatus::Retryable,
    }
}

/// Creates a ConnectRequest, unless none is necessary because the link is
/// to the visa service itself.
///
/// `addr` is either UNSPECIFIED or an address requested by the client adapter.
/// If it is a specified address we pass it as the "zpr.addr" claim.
pub fn build_connect_request(
    asm: &Arc<Assembly>,
    addr: IpAddress,
    blob: &AuthBlob,
    a2a_dh_public_key: Option<x25519_dalek::PublicKey>,
) -> Result<vsapi_types::ConnectRequest, LinkStateError> {
    // Convert the adapter's AuthBlob to the vsapi_types AuthBlob for the v2 protocol.
    let vsapi_blob = match blob {
        AuthBlob::SelfSigned(ss) => vsapi_types::AuthBlob::SS(vsapi_types::SelfSignedBlob {
            alg: vsapi_types::ChallengeAlg::RsaSha256Pkcs1v15,
            challenge: BASE64_STANDARD.decode(&ss.challenge).map_err(|err| {
                LinkStateError::InvalidOperation(format!("invalid actor challenge: {err}"))
            })?,
            cn: ss.cn.clone(),
            timestamp: ss.ts,
            signature: BASE64_STANDARD.decode(&ss.sig).map_err(|err| {
                LinkStateError::InvalidOperation(format!("invalid actor signature: {err}"))
            })?,
        }),
        AuthBlob::AuthCode(ac) => vsapi_types::AuthBlob::AC(vsapi_types::AuthCodeBlob {
            asa_addr: ac
                .asa
                .parse::<std::net::SocketAddr>()
                .map(|addr| addr.ip())
                .or_else(|_| ac.asa.parse::<std::net::IpAddr>())
                .map_err(|err| {
                    LinkStateError::InvalidOperation(format!(
                        "invalid authentication service address: {err}"
                    ))
                })?,
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
    // The CN claim always comes from the AuthBlob certificate, never from the
    // SA cert: the SA cert only validates the node-adapter link, while the
    // AuthBlob cert authenticates an actor to the VS (and multiple actors may
    // sit behind one adapter, so the two CNs must be independent). With an
    // AuthCode blob there is no AuthBlob cert, so no CN claim is sent.
    if let AuthBlob::SelfSigned(ss) = blob {
        request_claims.push(vsapi_types::Claim {
            key: claims::key::CN.into(),
            value: ss.cn.clone(),
        });
    }

    //stuff key into a vsapi_types::PublicKey so it can be sent in the connect request
    let a2a_dh_public_key = a2a_dh_public_key
        .map(|key| vsapi_types::PublicKey::new(key.as_bytes()))
        .unwrap_or_else(|| vsapi_types::PublicKey::new(&[]));

    let connect_req = vsapi_types::ConnectRequest {
        blobs: vec![vsapi_blob],
        claims: request_claims,
        substrate_addr: asm.get_local_dock_addr(),
        dock_interface: 0,
        a2a_dh_public_key,
    };
    Ok(connect_req)
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
    asm: &Assembly,
    visa: vsapi_types::Visa,
) -> Result<VisaId, visa_table::VisaTableError> {
    if visa.visa_type != vsapi_types::VisaType::Full {
        panic!("Forward only visas not yet supported")
    }
    let dest_addr = visa.dock_pep.as_ref().unwrap().dest_addr;
    let next_hop = visa
        .fwd_pep
        .as_ref()
        .map(|p| p.next_hop)
        .unwrap_or(dest_addr);
    if asm.find_egress_link(next_hop.into()).is_none() {
        asm.counters.management[ManagementCounterType::VisaRequestError].increment();
        return Err(visa_table::VisaTableError::DestNotFound(next_hop.into()));
    }
    let visa_id = asm.visa_table.write().unwrap().insert_visa(visa)?;
    Ok(visa_id)
}

/// Given a visa ID, look up the visa in our table to find the destination address
/// then use that to find an egress link.
pub fn get_egress_link_for_visa(
    asm: &Assembly,
    visa_id: VisaId,
) -> Result<NonZero<LinkId>, visa_table::VisaTableError> {
    let addr = asm
        .visa_table
        .read()
        .unwrap()
        .get_visa_next_hop_addr(visa_id)?;
    let Some(link_id) = asm.find_egress_link(addr) else {
        return Err(visa_table::VisaTableError::DestNotFound(addr));
    };
    Ok(link_id)
}

pub fn handle_revocation(
    asm: &Assembly,
    visa_id: VisaId,
) -> Result<(), visa_table::VisaTableError> {
    asm.visa_table
        .write()
        .unwrap()
        .revoke(&asm.peer_table, visa_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assembly::test::{TestAssemblyBuilder, create_assembly};
    use crate::auth::{BLOB_TYPE_AC, ZdpAuthCodeBlob};
    use crate::zdp::AuthenticationStatus;
    use vsapi_types::{ApiResponseError, ErrorCode};

    #[test]
    fn auth_code_preserves_evidence_and_accepts_ip_or_socket_service_addresses() {
        let asm = Arc::new(create_assembly(TestAssemblyBuilder::new()));
        for (asa, ip) in [
            ("192.0.2.1:443", "192.0.2.1"),
            ("[fd5a:5052::3]:443", "fd5a:5052::3"),
            ("192.0.2.1", "192.0.2.1"),
            ("fd5a:5052::3", "fd5a:5052::3"),
            ("invalid", ""),
        ] {
            let blob = AuthBlob::AuthCode(ZdpAuthCodeBlob {
                blob_type: BLOB_TYPE_AC.into(),
                code: "auth-code".into(),
                pkce: "pkce".into(),
                client_id: "actor.identity".into(),
                asa: asa.into(),
            });
            let result = build_connect_request(&asm, IpAddress::UNSPECIFIED, &blob, None);
            if ip.is_empty() {
                assert!(result.is_err());
                continue;
            }
            let req = result.unwrap();
            assert!(req.claims.is_empty());
            let [vsapi_types::AuthBlob::AC(evidence)] = req.blobs.as_slice() else {
                panic!("expected auth-code evidence");
            };
            assert_eq!(evidence.asa_addr, ip.parse::<std::net::IpAddr>().unwrap());
            assert_eq!(evidence.code, "auth-code");
            assert_eq!(evidence.pkce, "pkce");
            assert_eq!(evidence.client_id, "actor.identity");
        }
    }

    #[test]
    fn explicit_vs_denials_are_distinct_from_service_failures() {
        for code in [
            ErrorCode::AuthRequired,
            ErrorCode::InvalidSignature,
            ErrorCode::AuthError,
            ErrorCode::ParamError,
            ErrorCode::InvalidOperation,
            ErrorCode::NotFound,
        ] {
            let err = VSApiError::CodedError(ApiResponseError::new_code_msg(code, "denied"));
            assert_eq!(
                authorization_error_status(&err),
                AuthenticationStatus::Rejected
            );
        }
        assert_eq!(
            authorization_error_status(&VSApiError::AuthFailed("denied".into())),
            AuthenticationStatus::Rejected
        );
        for err in [
            VSApiError::ConnClosed,
            VSApiError::Timeout("service".into()),
            VSApiError::CodedError(ApiResponseError::new_code_msg(ErrorCode::Internal, "retry")),
        ] {
            assert_eq!(
                authorization_error_status(&err),
                AuthenticationStatus::Retryable
            );
        }
    }
}
