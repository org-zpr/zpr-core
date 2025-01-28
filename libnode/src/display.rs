use std::net::IpAddr;
use std::fmt::{self, Formatter};

use crate::vss::VSSMsg;


/// Very terse string format of a VSSMsg.
impl fmt::Display for VSSMsg {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            VSSMsg::PolicyInstall(pi) => write!(f, "PolicyInstall(policy_id: {:?})", pi.policy_id),
            VSSMsg::PushedVisa(v) => write!(f, "Visa(issuer_id: {:?})", v.issuer_id),
            VSSMsg::PushedRevocation(r) => write!(f, "Revocation(issuer_id: {:?})", r.issuer_id),
        }
    }
}

impl fmt::Debug for VSSMsg {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            VSSMsg::PolicyInstall(pi) => write!(f, "PolicyInstall({:?})", pi),
            VSSMsg::PushedVisa(v) => {
                write!(f, "PushedVisa(issuer_id: {}, hop_count: {}, visa: ",
                    to_string_or(&v.issuer_id, "(none)"), to_string_or(&v.hop_count, "(none)"))?;
                summarize_visa(f, &v.visa)?;
                write!(f, ")")
            }
            VSSMsg::PushedRevocation(r) => write!(f, "Revocation({:?})", r),
        }
    }
}


/// Attempt to surface the most critical bits of a visa ... for use in our debug log.
fn summarize_visa(f: &mut Formatter<'_>, visa: &Option<vsapi::Visa>) -> fmt::Result {
    match visa {
        Some(v) => {
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
                }
                None => {
                    proto = "(none)".to_string();
                    sport = "(?)".to_string();
                    dport = "(?)".to_string();
                }
            };

            if icmp {
                write!(f, "{} / [{}] -> [{}] type {}", proto,
                    opt_ip_to_str(&v.source), opt_ip_to_str(&v.dest), sport)
            } else {
                write!(f, "{} / [{}]:{} -> [{}]:{}", proto,
                    opt_ip_to_str(&v.source), sport,
                    opt_ip_to_str(&v.dest), dport)
            }
        }
        None => write!(f, "(None)"),
    }
}


/// Return string form of an optional IP address.
fn opt_ip_to_str(ipa: &Option<Vec<u8>>) -> String {
    match ipa {
        Some(ip) if ip.len() == 4 => {
            let ip_addr = IpAddr::from([ip[0], ip[1], ip[2], ip[3]]);
            ip_addr.to_string()
        }
        Some(ip) if ip.len() == 16 => {
            let ip_addr = IpAddr::from([ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7],
                                        ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15]]);
            ip_addr.to_string()
        }
        Some(_) => {
            "(invalid IP address)a".to_string()
        }
        None => "(none)".to_string(),
    }
}


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
