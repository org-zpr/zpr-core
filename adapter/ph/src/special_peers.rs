use crate::defs::FiveTuple;
use crate::net_defs::IpAddress;
use enum_map::Enum;
use enumset::{enum_set, EnumSet, EnumSetType};

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

/// Based on the given ingress link ID and five tuple, look up whether there
/// is a default policy to allow such traffic to a special peer.  If so,
/// returns the special peer's name, otherwise returns None.
pub fn default_policy_lookup(
    ingress_link_id: zpr::LinkId,
    five_tuple: &FiveTuple,
) -> Option<SpecialPeerName> {
    match (ingress_link_id, five_tuple) {
        (
            zpr::LOCAL_AGENT_LINK_ID,
            FiveTuple {
                dst_address: VISA_SERVICE_IP_ADDRESS,
                l4_protocol: zpr::VISA_SERVICE_PROTO,
                dst_port: zpr::VISA_SERVICE_PORT,
                ..
            },
        ) => Some(SpecialPeerName::VisaServiceAdapter),

        _ => None,
    }
}
