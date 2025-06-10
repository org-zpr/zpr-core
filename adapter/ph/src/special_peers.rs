use crate::assembly::Assembly;
use crate::defs::FiveTuple;
use crate::logging::targets::FLOW_MGMT;
use crate::mgmt::dock::BindActorAddressError;
use crate::net_defs::{ip_number, IpAddress};

use enum_map::Enum;
use enumset::{enum_set, EnumSet, EnumSetType};
use libnode::vss;
use std::num::NonZero;
use std::sync::Arc;
use tracing::debug;
use zpr_ext::std::num::NonZeroExt;

/// Some peers are "special", e.g. the visa service adapter attached to the initial node.
/// These names let us identify them.
#[derive(Debug, Enum, EnumSetType /* implies Clone, Copy */)]
pub enum SpecialPeerName {
    VisaServiceAdapter,
}

/// Returns the special names associated with the peer with the given X.509 subject name.
pub fn special_peer_names_from_x509_subject_name(
    subject: &openssl::x509::X509NameRef,
) -> EnumSet<SpecialPeerName> {
    let Ok(dn_der) = subject.to_der() else {
        return enum_set!();
    };
    match dn_der.as_slice() {
        zpr::VISA_SERVICE_DN => enum_set!(SpecialPeerName::VisaServiceAdapter),
        _ => enum_set!(),
    }
}

const VISA_SERVICE_IP_ADDRESS: IpAddress = IpAddress::new_from_std(&zpr::VISA_SERVICE_ADDR);

pub struct PolicyForwardingDecision {
    pub spname: Option<SpecialPeerName>,
    pub egress_link_id: NonZero<zpr::LinkId>,
    pub visa_id: zpr::VisaId,
}

/// Based on the given ingress link ID and five tuple, look up whether there
/// is a default policy to allow such traffic.
///
/// TODO: This is a temporary hack until we have a proper visa table that we can search.
pub fn default_policy_lookup(
    asm: &Arc<Assembly>,
    ingress_link_id: NonZero<zpr::LinkId>,
    five_tuple: &FiveTuple,
) -> Result<Option<PolicyForwardingDecision>, BindActorAddressError> {
    let visa_server_id = asm
        .peer_table
        .lookup_special_peer(crate::special_peers::SpecialPeerName::VisaServiceAdapter)
        .unwrap_or_zero();

    let self_addr: IpAddress = asm.local_zpr_addresses[0].into();

    // Let the local actor send _ANYTHING_ to the visa service. TODO: fix this hack!
    if ingress_link_id.get() == zpr::LOCAL_ACTOR_LINK_ID
        && five_tuple.dst_address == VISA_SERVICE_IP_ADDRESS
    {
        if let Some(id) = asm
            .peer_table
            .lookup_special_peer(SpecialPeerName::VisaServiceAdapter)
        {
            Ok(Some(PolicyForwardingDecision {
                spname: Some(SpecialPeerName::VisaServiceAdapter),
                egress_link_id: id,
                visa_id: zpr::SPECIAL_VISA_ID,
            }))
        } else {
            Err(BindActorAddressError::PolicyError)
        }
    } else
    // Visa service is allowed to talk TCP to the nodes VS-SUPPORT-API port.
    // Visa service is allowed to talk to the node FROM the VS-API port
    if ingress_link_id.get() == visa_server_id
        && five_tuple.dst_address == self_addr
        && five_tuple.l4_protocol == ip_number::TCP
        && (five_tuple.dst_port == vss::DEFAULT_VSS_PORT
            || five_tuple.src_port == zpr::VISA_SERVICE_PORT)
    {
        Ok(Some(PolicyForwardingDecision {
            spname: None,
            egress_link_id: NonZero::new(zpr::LOCAL_ACTOR_LINK_ID).unwrap(),
            visa_id: zpr::SPECIAL_VISA_ID,
        }))
    } else if ingress_link_id.get() == zpr::LOCAL_ACTOR_LINK_ID {
        // Reject packets from the local actor.
        // (Packets destined to the Visa Service Adapter fall under special-peer policy.)
        debug!(
            target: FLOW_MGMT,
            "rejecting a packet from the LOCAL-ACTOR, 5-typle: {five_tuple}",
        );
        Err(BindActorAddressError::PolicyError)
    } else {
        Ok(None)
    }
}
