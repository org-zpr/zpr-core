use enum_map::Enum;
use enumset::{EnumSet, EnumSetType, enum_set};
use zpr::dn::VISA_SERVICE_DN;

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
        VISA_SERVICE_DN => enum_set!(SpecialPeerName::VisaServiceAdapter),
        _ => enum_set!(),
    }
}
