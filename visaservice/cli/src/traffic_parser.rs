use rand::Rng;
use regex::Captures;
use regex::Regex;
use std::net::IpAddr;

use crate::vsapi;

#[derive(Debug, PartialEq)]
pub enum Protocol {
    TCP = 6,
    UDP = 17,
}

const TCP_FLAGS_SYN: u8 = 0x02;
const TCP_FLAGS_ACK: u8 = 0x10;

// Input form is:
//
//   <SRC_ADDR>  ":" <SRC_PORT> ">" <DST_ADDR> ":" <DST_PORT> "[" <FLAGS> "]"
//
//   IPv6 addresses should be enclosed in square brackets.
//   Flags are optional
//   Source port is optiona, and if omitted a high number port is randomly chosen.
//
pub fn parse_traffic(input: &str, prot: Protocol) -> Result<vsapi::TrafficDesc, std::io::Error> {
    let input = input.trim();
    // let capts: Captures;

    let capts: Captures = if input.starts_with('[') {
        // IPv6
        let re =
            Regex::new(r"\[([0-9a-fA-F:]+)\](?::(\d+))?>\[([0-9a-fA-F:]+)\]:(\d+)(?:\[([SA]+)\])?")
                .unwrap();
        match re.captures(input) {
            Some(caps) => caps,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid input",
                ))
            }
        }
    } else {
        // IPv4
        let re = Regex::new(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::(\d+))?>(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)(?:\[([SA]+)\])?").unwrap();
        match re.captures(input) {
            Some(caps) => caps,
            None => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid input",
                ))
            }
        }
    };

    let src_addr = match capts.get(1).unwrap().as_str().parse::<IpAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid source address",
            ))
        }
    };
    let dst_addr = match capts.get(3).unwrap().as_str().parse::<IpAddr>() {
        Ok(addr) => addr,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid destination address",
            ))
        }
    };

    if (src_addr.is_ipv4() && dst_addr.is_ipv6()) || (src_addr.is_ipv6() && dst_addr.is_ipv4()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Cannot mix IPv4 and IPv6 addresses",
        ));
    }

    let mut rng = rand::thread_rng();

    let src_port: u16 = match capts.get(2) {
        Some(port) => match port.as_str().parse::<u16>() {
            Ok(p) => p,
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Invalid source port",
                ))
            }
        },
        None => rng.gen(),
    };

    let dst_port: u16 = match capts.get(4).unwrap().as_str().parse::<u16>() {
        Ok(port) => port,
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Invalid destination port",
            ))
        }
    };

    let mut flags: u32 = 0;

    if let Some(fstr) = capts.get(5) {
        for c in fstr.as_str().chars() {
            match c {
                'S' => flags |= TCP_FLAGS_SYN as u32,
                'A' => flags |= TCP_FLAGS_ACK as u32,
                _ => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Invalid flags",
                    ))
                }
            }
        }
    };

    if flags > 0 && prot != Protocol::TCP {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Flags only valid for TCP",
        ));
    }

    let src_octets = match src_addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    let dst_octets = match dst_addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };

    let traffic = vsapi::TrafficDesc {
        source: Some(src_octets),
        dest: Some(dst_octets),
        protocol: Some(prot as i32),
        source_port: Some(src_port as i32),
        dest_port: Some(dst_port as i32),
        flags: Some(flags as i32),
        icmp_type: None,
        icmp_code: None,
        size: Some(rng.gen_range(1025..65534)),
        icmp_addr: None,
    };

    Ok(traffic)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_ipv6() {
        let valid_input = vec![
            "[2001:db8::1]:31337>[2001:db8::2]:80[S]",
            "[2001:db8::1]>[2001:db8::2]:80[S]",
            "[2001:db8::1]>[2001:db8::2]:80",
        ];

        for input in valid_input {
            let res = parse_traffic(input, Protocol::TCP);
            if res.is_err() {
                println!("failed to parse valid input '{}', Error: {:?}", input, res);
                assert!(false)
            }
        }
    }

    #[test]
    fn test_parse_ipv4() {
        let valid_input = vec![
            "192.168.0.1:31337>192.168.0.2:80[S]",
            "192.168.0.1>192.168.0.2:80[S]",
            "192.168.0.1>192.168.0.2:80[SA]",
            "192.168.0.1>192.168.0.2:80[A]",
            "192.168.0.1>192.168.0.2:80",
        ];

        for input in valid_input {
            let res = parse_traffic(input, Protocol::TCP);
            if res.is_err() {
                println!("failed to parse valid input '{}', Error: {:?}", input, res);
                assert!(false)
            }
        }
    }

    #[test]
    fn test_parse_questionable() {
        let questionable_input = vec![
            "192.168.0.1:31337>192.168.0.2:80[V]", // unknown flag
            "192.168.0.1:31337>192.168.0.2:80[S",  // malformed flag
        ];
        for input in questionable_input {
            let res = parse_traffic(input, Protocol::TCP);
            if res.is_err() {
                println!("parse has been improved!  Hazzah! Now patch this test!  used to succeed on ==> '{}', Error: {:?}", input, res);
                assert!(false)
            }
        }
    }

    #[test]
    fn test_parse_traffic_valid() {
        let valid_input = vec![
            "192.168.0.1:31337>192.168.0.2:80[S]",
            "192.168.0.1>192.168.0.2:80[S]",
            "192.168.0.1>192.168.0.2:80[SA]",
            "192.168.0.1>192.168.0.2:80[A]",
            "192.168.0.1>192.168.0.2:80[]",
            "192.168.0.1>192.168.0.2:80",
            "[2001:db8::1]:31337>[2001:db8::2]:80[S]",
            "[2001:db8::1]>[2001:db8::2]:80[S]",
            "[2001:db8::1]>[2001:db8::2]:80[]",
            "[2001:db8::1]>[2001:db8::2]:80",
        ];

        for input in valid_input {
            let res = parse_traffic(input, Protocol::TCP);
            if res.is_err() {
                println!("failed to parse valid input '{}', Error: {:?}", input, res);
                assert!(false)
            }
        }
    }

    #[test]
    fn test_parse_traffic_invalid() {
        let invalid_input = vec![
            "192.168.0.1.2:31337>192.168.0.2:80[S]",   // bad src addr
            "192.168.0.131337>192.168.0.2:80[S]",      // bad src addr
            "192.168.0.1:2331337>192.168.0.2:80[S]",   // bad src port
            "192.168.0.1:31337!192.168.0.2:80[S]",     // missing '>'
            "192.168.0.1:31337192.168.0.2:80[S]",      // missing '>'
            "192.168.0.1:31337     192.168.0.2:80[S]", // missing '>'
            "192.168.0.1:31337>9192.168.0.2:80[S]",    // bad dest addr
            "192.168.0.1:31337>192.168.0.2.3:80[S]",   // bad dest addr
            "192.168.0.1:31337>192.168.0.2:321380[S]", // bad dest port
            "[fc00:3001::1]:31337>192.168.0.2:80[S]",  // cannot compule v6 and v4
            "192.168.0.1:31337>[fc00:3001::1]:80",     // cannot compule v6 and v4
        ];

        for input in invalid_input {
            let res = parse_traffic(input, Protocol::TCP);
            if !res.is_err() {
                println!("failed to fail on ivalid input '{}'", input);
                println!("result = {:?}", res.unwrap());
                assert!(false)
            }
        }
    }
}
