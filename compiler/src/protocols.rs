use core::fmt;

#[derive(Debug, Clone, PartialEq, Copy)]
pub enum IanaProtocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    ICMPv6 = 58,
}

impl fmt::Display for IanaProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IanaProtocol::ICMP => write!(f, "icmp"),
            IanaProtocol::TCP => write!(f, "tcp"),
            IanaProtocol::UDP => write!(f, "udp"),
            IanaProtocol::ICMPv6 => write!(f, "icmp6"),
        }
    }
}

impl Into<u32> for IanaProtocol {
    fn into(self) -> u32 {
        self as u32
    }
}

/// Convert a ZPL string (without leading 'iana') to an IANA protocol number enum.
pub fn parse(s: &str) -> Option<IanaProtocol> {
    match s.to_lowercase().as_str() {
        "icmp" | "icmp4" | "icmpv4" => Some(IanaProtocol::ICMP),
        "tcp" => Some(IanaProtocol::TCP),
        "udp" => Some(IanaProtocol::UDP),
        "icmp6" | "icmpv6" => Some(IanaProtocol::ICMPv6),
        _ => None,
    }
}

impl IanaProtocol {
    pub fn is_icmp(&self) -> bool {
        matches!(self, IanaProtocol::ICMP | IanaProtocol::ICMPv6)
    }

    pub fn takes_port_arg(&self) -> bool {
        !self.is_icmp()
    }
}

#[derive(Debug, Clone)]
pub struct Protocol {
    pub protocol: IanaProtocol,
    pub port: Option<String>, // TODO: using string for now but needs to be a "port spec"
    pub icmp: Option<IcmpFlowType>,
}

/// Part of a Protocol description.
#[derive(Debug, Clone, PartialEq)]
pub enum IcmpFlowType {
    RequestResponse(u8, u8),
    OneShot(Vec<u8>),
}

impl Protocol {
    pub fn to_endpoint_str(&self) -> String {
        let mut s = String::new();
        let protname = self.protocol.to_string().to_uppercase();
        if self.protocol.is_icmp() {
            if let Some(ref icmp) = self.icmp {
                match icmp {
                    IcmpFlowType::RequestResponse(req, resp) => {
                        s.push_str(&format!("{}/{}", protname, req));
                        s.push_str(&format!(",{}/{}", protname, resp));
                    }
                    IcmpFlowType::OneShot(ref codes) => {
                        for c in codes {
                            s.push_str(&format!("{}/{}", protname, c));
                        }
                    }
                }
            } else {
                s.push_str(&format!("{}/0", protname));
            }
        } else {
            s.push_str(&format!("{}/", protname));
            if let Some(ref port) = self.port {
                s.push_str(port);
            } else {
                s.push_str("0");
            }
        }
        s
    }
}
