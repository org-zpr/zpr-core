use etherparse;
use rand::Rng;
use regex::Captures;
use regex::Regex;
use std::net::IpAddr;

#[derive(Debug, PartialEq)]
pub enum Protocol {
    TCP = 6,
    UDP = 17,
}

const TCP_FLAGS_SYN: u8 = 0x02;
const TCP_FLAGS_ACK: u8 = 0x10;

#[derive(Debug)]
pub struct TrafficDesc {
    pub source: IpAddr,
    pub dest: IpAddr,
    pub protocol: Protocol,
    pub source_port: u16,
    pub dest_port: u16,
    pub flags: u8,
}

// This function parses a string from the user that describes traffic in a succinct way
// so that we can pass a visa-request to the visa service.
//
// This is a part of the visaservice/cli tool which is a DEVELOPMENT DEBUGGING TOOL.
// This parser and this format has nothing to do with production visa requesting.
// In production, a visa is requested based on a packet header.  The packet header is
// parsed into a description structure directly.
//
// Note that since this is development tool, not a lot of time has been spent on
// hardening the parser against spurious inputs.
//
// DO NOT COUNT ON THE PARSER TO BARF IF YOU GIVE IT BAD INPUT.
//
//
//
// Input form is:
//
//   <SRC_ADDR>  ":" <SRC_PORT> ">" <DST_ADDR> ":" <DST_PORT> "[" <FLAGS> "]"
//
//   IPv6 addresses should be enclosed in square brackets.
//   Flags are optional
//   Source port is optional, and if omitted a high number port is randomly chosen.
//
pub fn parse_traffic(input: &str, prot: Protocol) -> Result<TrafficDesc, std::io::Error> {
    let input = input.trim();
    // let capts: Captures;

    #[rustfmt::skip]
    let capts: Captures = if input.starts_with('[') {
        // IPv6
        let re =
            Regex::new(r"(?x)
              \[([0-9a-fA-F:]+)\] # something that looks like IPv6 address in square brackets
              (?::(\d+))?         # optionally followed by a port num
              >
              \[([0-9a-fA-F:]+)\] # another IPv6 looking thing
              :(\d+)              # dest port is required
              (?:\[([SA]+)\])?    # optional flags
              ").unwrap();
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
        let re = Regex::new(r"(?x)
          ^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) # An IPv4 address, four octets.
          (?::(\d+))?                           # optionally followed by a port num
          >
          (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})  # another IPv4 address
          :(\d+)                                # dest port number required
          (?:\[([SA]+)\])?                      # optional flags
          ").unwrap();
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

    let mut flags: u8 = 0;

    if let Some(fstr) = capts.get(5) {
        for c in fstr.as_str().chars() {
            match c {
                'S' => flags |= TCP_FLAGS_SYN,
                'A' => flags |= TCP_FLAGS_ACK,
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

    let traffic = TrafficDesc {
        source: src_addr,
        dest: dst_addr,
        protocol: prot,
        source_port: src_port,
        dest_port: dst_port,
        flags,
    };

    Ok(traffic)
}

impl TrafficDesc {
    /// Convert this [TrafficDesc] into a packet bytes with a dummy payload.
    pub fn build_packet(&self) -> Vec<u8> {
        let payload = [0, 1, 2, 3, 4, 5, 6, 7];
        let mut buf = Vec::<u8>::with_capacity(1500);

        let src_octets = match self.source {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        let dst_octets = match self.dest {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };

        let builder: etherparse::PacketBuilderStep<_>;
        if self.source.is_ipv6() {
            let src_a: [u8; 16] = src_octets.as_slice().try_into().unwrap();
            let dst_a: [u8; 16] = dst_octets.as_slice().try_into().unwrap();
            builder = etherparse::PacketBuilder::ipv6(src_a, dst_a, 0);
        } else {
            let src_a: [u8; 4] = src_octets.as_slice().try_into().unwrap();
            let dst_a: [u8; 4] = dst_octets.as_slice().try_into().unwrap();
            builder = etherparse::PacketBuilder::ipv4(src_a, dst_a, 0);
        }

        if self.protocol == Protocol::TCP {
            let builder = builder.tcp(self.source_port, self.dest_port, 1234, 4000);
            builder.write(&mut buf, &payload).unwrap();
        } else {
            let builder = builder.udp(self.source_port, self.dest_port);
            builder.write(&mut buf, &payload).unwrap();
        }

        // The very convenient builder interfaces does not give us direct access to the
        // flags field in the TCP header.  So we have to do it manually.  If checksums
        // were calculated, this will break them. (Visa service does not verify checksums).
        if self.protocol == Protocol::TCP {
            let ip_hdr_len = if self.source.is_ipv6() { 40 } else { 20 };
            let mut tcp_header = buf.split_off(ip_hdr_len);
            tcp_header[13] = self.flags;
            buf.append(&mut tcp_header);
        }

        buf
    }
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

    // These are cases that I have observed that the parser does allow.
    // These don't cause a crash, but they also don't raise any errors.
    //
    // NOT PART OF ANY PRODUCTION VISA REQUEST PATH!
    //
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
