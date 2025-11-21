use crate::vss::VSSMsg;
use std::fmt::{self, Formatter};
use std::net::IpAddr;
use zpr::vsapi_types;

/// Human readable version of the MSSMsg which includes some interior details of the visa.
impl fmt::Display for VSSMsg {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            VSSMsg::PolicyInstall(pi) => write!(f, "PolicyInstall(policy_id: {:?})", pi.policy_id),
            VSSMsg::PushedRevocation(r) => match r {
                vsapi_types::VisaOp::RevokeVisaId(id) => write!(f, "Revocation(issuer_id: {})", id),
                _ => write!(f, "Revocation bad format, non RevokeVisaId"),
            },
            VSSMsg::PushedVisa(v) => {
                write!(f, "PushedVisa(")?;
                summarize_visa(f, v)?;
                write!(f, ")")
            }
            VSSMsg::PushedServices(services) => match services.services {
                Some(ref s) => {
                    write!(f, "PushedServices(services: [")?;
                    for (i, service) in s.iter().enumerate() {
                        if i > 0 {
                            write!(f, ", ")?;
                        }
                        write!(
                            f,
                            "{}",
                            service.uri.as_ref().unwrap_or(&"NO_URI".to_string())
                        )?;
                        write!(
                            f,
                            "/id={}",
                            service.service_id.as_ref().unwrap_or(&"NO_ID".to_string())
                        )?;
                        write!(f, "/type={:?}", service.type_)?;
                    }
                    write!(f, "])")
                }
                None => write!(f, "PushedServices(services: (none))"),
            },
        }
    }
}

#[allow(dead_code)]
/// Human readable version of the MSSMsg which includes some interior details of the visa.
fn summarize_visa_hop(f: &mut Formatter<'_>, vh: &vsapi::VisaHop) -> fmt::Result {
    write!(
        f,
        "VisaHop(issuer_id: {}, hop_count: {}, visa: ",
        to_string_or(&vh.issuer_id, "(none)"),
        to_string_or(&vh.hop_count, "(none)")
    )?;
    match vh.visa {
        Some(ref v) => summarize_vsapi_visa(f, v),
        None => write!(f, "(none)"),
    }
}

/// Attempt to surface the most critical bits of a visa.
fn summarize_visa(f: &mut Formatter<'_>, v: &vsapi_types::Visa) -> fmt::Result {
    let mut icmp = false;
    let proto: String;
    let sport: String;
    let dport: String;

    match &v.dock_pep {
        vsapi_types::DockPep::TCP(args) => {
            sport = args.source_port.to_string();
            dport = args.dest_port.to_string();
            proto = "TCP".to_string();
        }
        vsapi_types::DockPep::UDP(args) => {
            sport = args.source_port.to_string();
            dport = args.dest_port.to_string();
            proto = "UDP".to_string();
        }
        vsapi_types::DockPep::ICMP(args) => {
            icmp = true;
            proto = "ICMP".to_string();

            sport = args.icmp_type.to_string();
            dport = args.icmp_code.to_string();
        }
    };

    if icmp {
        write!(f, "{}<{}>/->[{}]", proto, sport, v.dst_addr,)
    } else {
        write!(f, "{}/[{}]->[{}]:{}", proto, sport, v.dst_addr, dport,)
    }
}

#[allow(dead_code)]
/// Attempt to surface the most critical bits of a visa.
fn summarize_vsapi_visa(f: &mut Formatter<'_>, v: &vsapi::Visa) -> fmt::Result {
    let mut icmp = false;
    let proto: String;
    let sport: String;
    let dport: String;

    match v.dock_pep {
        Some(pep) => match pep {
            vsapi::PEPIndex::UDP | vsapi::PEPIndex::TCP => {
                match &v.tcpudp_pep_args {
                    Some(args) => {
                        sport = to_string_or(&args.source_port, "(?)");
                        dport = to_string_or(&args.dest_port, "(?)");
                    }
                    None => {
                        sport = "(none)".to_string();
                        dport = "(none)".to_string();
                    }
                }
                if pep == vsapi::PEPIndex::UDP {
                    proto = "UDP".to_string();
                } else {
                    proto = "TCP".to_string();
                }
            }
            vsapi::PEPIndex::ICMP => {
                icmp = true;
                proto = "ICMP".to_string();
                match &v.icmp_pep_args {
                    Some(args) => {
                        sport = to_string_or(&args.icmp_type_code, "(?)");
                        dport = "".to_string();
                    }
                    None => {
                        sport = "(none)".to_string();
                        dport = "(none)".to_string();
                    }
                }
            }
            _ => {
                proto = "(invalid)".to_string();
                sport = "(?)".to_string();
                dport = "(?)".to_string();
            }
        },
        None => {
            proto = "(none)".to_string();
            sport = "(?)".to_string();
            dport = "(?)".to_string();
        }
    };

    if icmp {
        write!(
            f,
            "{}<{}>/[{}]->[{}]",
            proto,
            sport,
            opt_ip_to_str(&v.source),
            opt_ip_to_str(&v.dest)
        )
    } else {
        write!(
            f,
            "{}/[{}]:{}->[{}]:{}",
            proto,
            opt_ip_to_str(&v.source),
            sport,
            opt_ip_to_str(&v.dest),
            dport
        )
    }
}

#[allow(dead_code)]
/// Return string form of an optional IP address.
fn opt_ip_to_str(ipa: &Option<Vec<u8>>) -> String {
    match ipa {
        Some(ip) if ip.len() == 4 => {
            let ip_addr = IpAddr::from([ip[0], ip[1], ip[2], ip[3]]);
            ip_addr.to_string()
        }
        Some(ip) if ip.len() == 16 => {
            let ip_addr = IpAddr::from([
                ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], ip[8], ip[9], ip[10],
                ip[11], ip[12], ip[13], ip[14], ip[15],
            ]);
            ip_addr.to_string()
        }
        Some(_) => "(invalid IP address)a".to_string(),
        None => "(none)".to_string(),
    }
}

#[allow(dead_code)]
/// Get a string representation of an optional value or a default `none_str` as provided.
fn to_string_or<T>(opt: &Option<T>, none_str: &str) -> String
where
    T: fmt::Display + Sized,
{
    match opt {
        Some(v) => v.to_string(),
        None => none_str.to_string(),
    }
}
