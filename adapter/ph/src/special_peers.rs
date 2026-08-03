use enum_map::Enum;
use enumset::{EnumSet, EnumSetType, enum_set};
use zpr::dn::VISA_SERVICE_DN;

/// Some peers are "special", e.g. the visa service adapter attached to the initial node.
/// These names let us identify them.
#[derive(Debug, Enum, EnumSetType /* implies Clone, Copy */)]
pub enum SpecialPeerName {
    VisaServiceAdapter,
}

/// Returns the special names associated with the peer whose subject distinguished
/// name has the given DER encoding
pub fn special_peer_names_from_subject_der(dn_der: &[u8]) -> EnumSet<SpecialPeerName> {
    match dn_der {
        VISA_SERVICE_DN => enum_set!(SpecialPeerName::VisaServiceAdapter),
        _ => enum_set!(),
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::km_noise::NoiseKeypair;
    use crate::pki::{self, generate_self_signed_noise_cert};
    use zpr::dn::VISA_SERVICE_CN;

    #[test]
    fn matches_visa_service_dn() {
        let keypair = NoiseKeypair::generate();
        let cert = generate_self_signed_noise_cert(VISA_SERVICE_CN, &keypair).unwrap();
        assert_eq!(pki::subject_der(&cert).as_slice(), VISA_SERVICE_DN);
        let names = special_peer_names_from_subject_der(&pki::subject_der(&cert));
        assert!(names.contains(SpecialPeerName::VisaServiceAdapter));
    }

    #[test]
    fn ignores_other_dn() {
        let keypair = NoiseKeypair::generate();
        let cert = generate_self_signed_noise_cert("not-special.zpr", &keypair).unwrap();
        assert!(special_peer_names_from_subject_der(&pki::subject_der(&cert)).is_empty());
    }
}
