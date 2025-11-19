use bytes::Buf;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use thiserror::Error;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};
use zpr_utils::net_defs::IpAddress;

const SOCKADDR_LEN_V4: u8 = 6; // 4 bytes for IPv4 + 2 bytes for port
const SOCKADDR_LEN_V6: u8 = 18; // 16 bytes for IPv6 + 2 bytes for port

#[derive(Debug, Error)]
pub enum TlvError {
    #[error("bad TLV structure")]
    BadStructure,
}

/// A single byte that identifies the type of TLV data.
type TlvType = u8;

/// Repository of all our TLV types.
pub struct DataType;
impl DataType {
    pub const NULL: TlvType = 0; // Note that Null type has no other fields. So is just one byte.

    pub const POLICY_ID: TlvType = 1;
    pub const VERSION: TlvType = 2;
    pub const AAA: TlvType = 3; // Actor Authentication Address - temporary address actor may use for authentication
    pub const ASA: TlvType = 4; // Authentication Service SocketAddress
    pub const STATIC_ADDR: TlvType = 5; // Static Address - used for static address requests from an adapter
    pub const WINDOW_SIZE: TlvType = 6;
}

/// TlvEncoding is a designed to be an easy way to create and write TLV data
/// into a buffer.
pub struct TlvEncoding {
    tlv_type: TlvType,
    value: TlvValue,
}

impl TlvEncoding {
    pub fn new_policy_id(policy_id: i64) -> TlvEncoding {
        TlvEncoding {
            tlv_type: DataType::POLICY_ID,
            value: TlvValue::I64(policy_id),
        }
    }

    pub fn new_version(version: &str) -> TlvEncoding {
        TlvEncoding {
            tlv_type: DataType::VERSION,
            value: TlvValue::Str(version.to_string()),
        }
    }

    /// Actor Authentication Address
    pub fn new_aaa(addr: IpAddress) -> TlvEncoding {
        let ipa: IpAddr = addr.into();
        match ipa {
            IpAddr::V4(ipa) => TlvEncoding {
                tlv_type: DataType::AAA,
                value: TlvValue::Ipv4Addr(ipa),
            },
            IpAddr::V6(ipa) => TlvEncoding {
                tlv_type: DataType::AAA,
                value: TlvValue::Ipv6Addr(ipa),
            },
        }
    }

    /// Actor requested static address for an adapter.
    #[allow(dead_code)]
    pub fn new_static_addr(addr: IpAddress) -> TlvEncoding {
        Self::new_static_addr_std(addr.into())
    }

    /// Actor requested static address for an adapter.
    pub fn new_static_addr_std(ipa: IpAddr) -> TlvEncoding {
        match ipa {
            IpAddr::V4(ipa) => TlvEncoding {
                tlv_type: DataType::STATIC_ADDR,
                value: TlvValue::Ipv4Addr(ipa),
            },
            IpAddr::V6(ipa) => TlvEncoding {
                tlv_type: DataType::STATIC_ADDR,
                value: TlvValue::Ipv6Addr(ipa),
            },
        }
    }

    /// Authentication Service Address
    pub fn new_asa(sock_addr: SocketAddr) -> TlvEncoding {
        TlvEncoding {
            tlv_type: DataType::ASA,
            value: TlvValue::SocketAddr(sock_addr),
        }
    }

    pub fn new_window_size(window_size: u16) -> TlvEncoding {
        TlvEncoding {
            tlv_type: DataType::WINDOW_SIZE,
            value: TlvValue::U16(window_size),
        }
    }

    /// Write this encoding to the buffer, advancing the buffer position.
    pub fn put(&self, buf: &mut dyn bytes::BufMut) {
        match &self.value {
            TlvValue::U16(v) => put_u16(buf, self.tlv_type, *v),
            TlvValue::I64(v) => put_i64(buf, self.tlv_type, *v),
            TlvValue::Str(v) => put_str(buf, self.tlv_type, v),
            TlvValue::Ipv6Addr(v) => put_ipv6addr(buf, self.tlv_type, v),
            TlvValue::Ipv4Addr(v) => put_ipv4addr(buf, self.tlv_type, v),
            TlvValue::SocketAddr(v) => put_socketaddr(buf, self.tlv_type, v),
        }
    }
}

#[derive(Clone, Debug)]
pub enum TlvValue {
    U16(u16),
    I64(i64),
    Str(String),
    Ipv6Addr(Ipv6Addr),
    Ipv4Addr(Ipv4Addr),
    SocketAddr(SocketAddr),
}

impl std::fmt::Display for TlvValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlvValue::U16(v) => write!(f, "{v}"),
            TlvValue::I64(v) => write!(f, "{v}"),
            TlvValue::Str(v) => write!(f, "{v}"),
            TlvValue::Ipv6Addr(v) => write!(f, "{v}"),
            TlvValue::Ipv4Addr(v) => write!(f, "{v}"),
            TlvValue::SocketAddr(v) => write!(f, "{v}"),
        }
    }
}

#[derive(Copy, Clone, Debug, FromBytes, IntoBytes, Immutable, KnownLayout, Unaligned)]
#[repr(packed)]
#[allow(dead_code)]
struct TLVHdr {
    pub tlv_type: TlvType,
    pub tlv_length: u8,
    // Followed by tlv_length bytes of value
}

fn put_u16(buf: &mut dyn bytes::BufMut, tlv_type: TlvType, value: u16) {
    let hdr = TLVHdr {
        tlv_type,
        tlv_length: 2, // Length of u16 is always 2 bytes
    };
    buf.put_slice(&hdr.as_bytes());
    buf.put_u16(value);
}

fn put_i64(buf: &mut dyn bytes::BufMut, tlv_type: TlvType, value: i64) {
    let hdr = TLVHdr {
        tlv_type,
        tlv_length: 8, // Length of i64 is always 8 bytes
    };
    buf.put_slice(&hdr.as_bytes());
    buf.put_i64(value);
}

/// Will truncate string value if it is longer than 255 bytes.
fn put_str(buf: &mut dyn bytes::BufMut, tlv_type: TlvType, value: &str) {
    let strlen = if value.len() > 255 {
        255
    } else {
        value.len() as u8
    };
    let hdr = TLVHdr {
        tlv_type,
        tlv_length: strlen,
    };
    buf.put_slice(&hdr.as_bytes());
    buf.put_slice(&value.as_bytes()[..strlen as usize]);
}

fn put_ipv6addr(buf: &mut dyn bytes::BufMut, tlv_type: TlvType, value: &Ipv6Addr) {
    let hdr = TLVHdr {
        tlv_type,
        tlv_length: 16,
    };
    buf.put_slice(&hdr.as_bytes());
    buf.put_slice(&value.octets());
}

fn put_ipv4addr(buf: &mut dyn bytes::BufMut, tlv_type: TlvType, value: &Ipv4Addr) {
    let hdr = TLVHdr {
        tlv_type,
        tlv_length: 4,
    };
    buf.put_slice(&hdr.as_bytes());
    buf.put_slice(&value.octets());
}

fn put_socketaddr(
    buf: &mut dyn bytes::BufMut,
    tlv_type: TlvType,
    sock_addr: &std::net::SocketAddr,
) {
    match sock_addr {
        std::net::SocketAddr::V4(v4) => {
            let hdr = TLVHdr {
                tlv_type,
                tlv_length: SOCKADDR_LEN_V4,
            };
            buf.put_slice(&hdr.as_bytes());
            buf.put_slice(&v4.ip().octets());
            buf.put_u16(v4.port());
        }
        std::net::SocketAddr::V6(v6) => {
            let hdr = TLVHdr {
                tlv_type,
                tlv_length: SOCKADDR_LEN_V6, // 16 bytes for IPv6 + 2 bytes for port
            };
            buf.put_slice(&hdr.as_bytes());
            buf.put_slice(&v6.ip().octets());
            buf.put_u16(v6.port());
        }
    }
}

/// Parse TLV data out of a buffer, advancing the internal position.  Only known
/// TLV types are parsed, unknown are skipped.
/// Null entries (type 0) are skipped over and not returned.
pub fn parse_from_buf(
    buf: &mut dyn bytes::Buf,
) -> Result<HashMap<TlvType, Vec<TlvValue>>, TlvError> {
    let mut tlv_map = HashMap::new();

    // The null type just uses 1 byte.
    while buf.remaining() >= 1 {
        // Read first byte to determine type.
        let tlv_type = buf.get_u8();
        if tlv_type == DataType::NULL {
            // Null type has no length or value, just skip it.
            continue;
        }
        if buf.remaining() < 1 {
            return Err(TlvError::BadStructure); // Not enough room for the length byte
        }
        let tlv_length = buf.get_u8();
        if buf.remaining() < tlv_length as usize {
            return Err(TlvError::BadStructure); // Not enough room for value
        }
        match tlv_type {
            DataType::POLICY_ID => {
                if tlv_length != 8 {
                    return Err(TlvError::BadStructure); // Policy ID must be 8 bytes
                }
                let value = buf.get_i64();
                tlv_map
                    .entry(tlv_type)
                    .or_insert_with(Vec::new)
                    .push(TlvValue::I64(value));
            }
            DataType::VERSION => {
                let strbuf = buf.copy_to_bytes(tlv_length as usize);
                let ver_str = String::from_utf8_lossy(&strbuf);
                tlv_map
                    .entry(tlv_type)
                    .or_insert_with(Vec::new)
                    .push(TlvValue::Str(ver_str.to_string()));
            }
            DataType::AAA | DataType::STATIC_ADDR => {
                let addr_val = parse_address_value(buf, tlv_length)?;
                tlv_map
                    .entry(tlv_type)
                    .or_insert_with(Vec::new)
                    .push(addr_val);
            }
            DataType::ASA => {
                // Parse a socket addr. Which in memory is the IPv4 or IPv6 address followed by a 16bit port number.
                match tlv_length {
                    6 => {
                        let ipv4u32 = buf.get_u32();
                        let port = buf.get_u16();
                        let ipv4_addr = Ipv4Addr::from(ipv4u32.to_be_bytes());
                        tlv_map.entry(tlv_type).or_insert_with(Vec::new).push(
                            TlvValue::SocketAddr(SocketAddr::V4(std::net::SocketAddrV4::new(
                                ipv4_addr, port,
                            ))),
                        );
                    }
                    18 => {
                        let mut addr_buf = [0u8; 16];
                        buf.copy_to_slice(&mut addr_buf); // Read 16 bytes for IPv6 address
                        let port = buf.get_u16();
                        let ipv6_addr = Ipv6Addr::from(addr_buf);
                        tlv_map.entry(tlv_type).or_insert_with(Vec::new).push(
                            TlvValue::SocketAddr(SocketAddr::V6(std::net::SocketAddrV6::new(
                                ipv6_addr, port, 0, 0,
                            ))),
                        );
                    }
                    _ => {
                        return Err(TlvError::BadStructure); // Invalid length for ASA
                    }
                }
            }
            DataType::WINDOW_SIZE => {
                if tlv_length != 2 {
                    return Err(TlvError::BadStructure);
                }
                let value = buf.get_u16();
                tlv_map
                    .entry(tlv_type)
                    .or_insert_with(Vec::new)
                    .push(TlvValue::U16(value));
            }
            _ => {
                // For unknown types, just skip the value.
                buf.advance(tlv_length as usize);
            }
        }
    }
    Ok(tlv_map)
}

fn parse_address_value(buf: &mut dyn bytes::Buf, tlv_length: u8) -> Result<TlvValue, TlvError> {
    if buf.remaining() < tlv_length as usize {
        return Err(TlvError::BadStructure); // Not enough data for address value
    }
    match tlv_length {
        4 => {
            let addr_bytes = buf.get_u32().to_be_bytes();
            let value = Ipv4Addr::from(addr_bytes);
            Ok(TlvValue::Ipv4Addr(value))
        }
        16 => {
            let mut addr_bytes = [0u8; 16];
            buf.copy_to_slice(&mut addr_bytes);
            let value = Ipv6Addr::from(addr_bytes);
            Ok(TlvValue::Ipv6Addr(value))
        }
        _ => {
            Err(TlvError::BadStructure) // Unsupported address length
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{BufMut, BytesMut};
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_put_and_parse_u16() {
        let mut buf = BytesMut::new();
        let test_value = 0x1234_u16;

        // Write the TLV
        put_u16(&mut buf, DataType::WINDOW_SIZE, test_value);

        // Parse it back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify the result
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::WINDOW_SIZE).unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TlvValue::U16(value) => assert_eq!(*value, test_value),
            _ => panic!("Expected U16 value for WINDOW_SIZE"),
        }
    }

    #[test]
    fn test_put_and_parse_i64() {
        let mut buf = BytesMut::new();
        let test_value = 0x0123456789abcdef_i64;

        // Write the TLV
        put_i64(&mut buf, DataType::POLICY_ID, test_value);

        // Parse it back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify the result
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::POLICY_ID).unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TlvValue::I64(value) => assert_eq!(*value, test_value),
            _ => panic!("Expected I64 value for POLICY_ID"),
        }
    }

    #[test]
    fn test_put_and_parse_string() {
        let mut buf = BytesMut::new();
        let test_value = "test_version_1.2.3";

        // Write the TLV
        put_str(&mut buf, DataType::VERSION, test_value);

        // Parse it back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify the result
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::VERSION).unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TlvValue::Str(value) => assert_eq!(value, test_value),
            _ => panic!("Expected Str value for VERSION"),
        }
    }

    #[test]
    fn test_put_and_parse_string_truncation() {
        let mut buf = BytesMut::new();
        let test_value = "a".repeat(300); // String longer than 255 bytes

        // Write the TLV
        put_str(&mut buf, DataType::VERSION, &test_value);

        // Parse it back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify the result is truncated to 255 bytes
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::VERSION).unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TlvValue::Str(value) => {
                assert_eq!(value.len(), 255);
                assert_eq!(value, &"a".repeat(255));
            }
            _ => panic!("Expected Str value for VERSION"),
        }
    }

    #[test]
    fn test_put_and_parse_ipv6() {
        let mut buf = BytesMut::new();
        let test_addr = Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
        );

        // Write the TLV
        put_ipv6addr(&mut buf, DataType::AAA, &test_addr);

        // Parse it back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify the result
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::AAA).unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TlvValue::Ipv6Addr(addr) => assert_eq!(*addr, test_addr),
            _ => panic!("Expected Ipv6Addr value for AAA"),
        }
    }

    #[test]
    fn test_put_and_parse_ipv4() {
        let mut buf = BytesMut::new();
        let test_addr = Ipv4Addr::new(10, 0, 0, 1);

        // Write the TLV using the helper function
        put_ipv4addr(&mut buf, DataType::AAA, &test_addr);

        // Parse it back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify the result
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::AAA).unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TlvValue::Ipv4Addr(addr) => assert_eq!(*addr, test_addr),
            _ => panic!("Expected Ipv4Addr value for ASA"),
        }
    }

    #[test]
    fn test_parse_ipv4_address() {
        let mut buf = BytesMut::new();
        let test_addr = Ipv4Addr::new(192, 168, 1, 1);

        // Manually construct IPv4 TLV (since we don't have a put_ipv4addr function)
        let hdr = TLVHdr {
            tlv_type: DataType::AAA,
            tlv_length: 4,
        };
        buf.put_slice(&hdr.as_bytes());
        buf.put_slice(&test_addr.octets());

        // Parse it back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify the result
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::AAA).unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TlvValue::Ipv4Addr(addr) => assert_eq!(*addr, test_addr),
            _ => panic!("Expected Ipv4Addr value for ASA"),
        }
    }

    #[test]
    fn test_parse_multiple_tlvs() {
        let mut buf = BytesMut::new();
        let policy_id = 12345_i64;
        let version = "v2.0.1";
        let ipv6_addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

        // Write multiple TLVs
        put_i64(&mut buf, DataType::POLICY_ID, policy_id);
        put_str(&mut buf, DataType::VERSION, version);
        put_ipv6addr(&mut buf, DataType::AAA, &ipv6_addr);

        // Parse them back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify all values
        assert_eq!(result.len(), 3);

        let policy_values = result.get(&DataType::POLICY_ID).unwrap();
        assert_eq!(policy_values.len(), 1);
        match &policy_values[0] {
            TlvValue::I64(value) => assert_eq!(*value, policy_id),
            _ => panic!("Expected I64 value for POLICY_ID"),
        }

        let version_values = result.get(&DataType::VERSION).unwrap();
        assert_eq!(version_values.len(), 1);
        match &version_values[0] {
            TlvValue::Str(value) => assert_eq!(value, version),
            _ => panic!("Expected Str value for VERSION"),
        }

        let aaa_values = result.get(&DataType::AAA).unwrap();
        assert_eq!(aaa_values.len(), 1);
        match &aaa_values[0] {
            TlvValue::Ipv6Addr(addr) => assert_eq!(*addr, ipv6_addr),
            _ => panic!("Expected Ipv6Addr value for AAA"),
        }
    }

    #[test]
    fn test_parse_with_null_types() {
        let mut buf = BytesMut::new();

        // Add a NULL type
        buf.put_u8(DataType::NULL);

        // Add a real TLV
        put_i64(&mut buf, DataType::POLICY_ID, 42);

        // Add another NULL type
        buf.put_u8(DataType::NULL);

        // Parse
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Should only have the POLICY_ID, nulls should be skipped
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::POLICY_ID).unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TlvValue::I64(value) => assert_eq!(*value, 42),
            _ => panic!("Expected I64 value for POLICY_ID"),
        }
    }

    #[test]
    fn test_parse_unknown_type() {
        let mut buf = BytesMut::new();

        // Add an unknown TLV type
        let unknown_type = 99_u8;
        let unknown_data = [0x01, 0x02, 0x03, 0x04];
        buf.put_u8(unknown_type);
        buf.put_u8(unknown_data.len() as u8);
        buf.put_slice(&unknown_data);

        // Add a known TLV
        put_i64(&mut buf, DataType::POLICY_ID, 123);

        // Parse
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Should only have the known TLV, unknown should be skipped
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::POLICY_ID).unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TlvValue::I64(value) => assert_eq!(*value, 123),
            _ => panic!("Expected I64 value for POLICY_ID"),
        }
    }

    #[test]
    fn test_parse_bad_structure_incomplete_length() {
        let mut buf = BytesMut::new();

        // Add a TLV type without length byte
        buf.put_u8(DataType::POLICY_ID);
        // Missing length byte

        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader);

        assert!(matches!(result, Err(TlvError::BadStructure)));
    }

    #[test]
    fn test_parse_bad_structure_incomplete_value() {
        let mut buf = BytesMut::new();

        // Add a TLV header claiming 8 bytes but only provide 4
        buf.put_u8(DataType::POLICY_ID);
        buf.put_u8(8); // Claims 8 bytes
        buf.put_u32(0x12345678); // Only provides 4 bytes

        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader);

        assert!(matches!(result, Err(TlvError::BadStructure)));
    }

    #[test]
    fn test_parse_bad_policy_id_length() {
        let mut buf = BytesMut::new();

        // Add a POLICY_ID with wrong length
        buf.put_u8(DataType::POLICY_ID);
        buf.put_u8(4); // Wrong length, should be 8
        buf.put_u32(0x12345678);

        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader);

        assert!(matches!(result, Err(TlvError::BadStructure)));
    }

    #[test]
    fn test_parse_bad_address_length() {
        let mut buf = BytesMut::new();

        // Add an address TLV with invalid length
        buf.put_u8(DataType::AAA);
        buf.put_u8(8); // Invalid length for address (should be 4 or 16)
        buf.put_u64(0x0123456789abcdef);

        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader);

        assert!(matches!(result, Err(TlvError::BadStructure)));
    }

    #[test]
    fn test_empty_buffer() {
        let buf = BytesMut::new();
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_multiple_values_same_type() {
        let mut buf = BytesMut::new();

        // Add multiple VERSION TLVs
        put_str(&mut buf, DataType::VERSION, "v1.0.0");
        put_str(&mut buf, DataType::VERSION, "v2.0.0");
        put_str(&mut buf, DataType::VERSION, "v3.0.0");

        // Add multiple POLICY_ID TLVs
        put_i64(&mut buf, DataType::POLICY_ID, 100);
        put_i64(&mut buf, DataType::POLICY_ID, 200);

        // Parse them back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify we have 2 different TLV types
        assert_eq!(result.len(), 2);

        // Check VERSION values
        let version_values = result.get(&DataType::VERSION).unwrap();
        assert_eq!(version_values.len(), 3);
        match &version_values[0] {
            TlvValue::Str(value) => assert_eq!(value, "v1.0.0"),
            _ => panic!("Expected Str value for VERSION[0]"),
        }
        match &version_values[1] {
            TlvValue::Str(value) => assert_eq!(value, "v2.0.0"),
            _ => panic!("Expected Str value for VERSION[1]"),
        }
        match &version_values[2] {
            TlvValue::Str(value) => assert_eq!(value, "v3.0.0"),
            _ => panic!("Expected Str value for VERSION[2]"),
        }

        // Check POLICY_ID values
        let policy_values = result.get(&DataType::POLICY_ID).unwrap();
        assert_eq!(policy_values.len(), 2);
        match &policy_values[0] {
            TlvValue::I64(value) => assert_eq!(*value, 100),
            _ => panic!("Expected I64 value for POLICY_ID[0]"),
        }
        match &policy_values[1] {
            TlvValue::I64(value) => assert_eq!(*value, 200),
            _ => panic!("Expected I64 value for POLICY_ID[1]"),
        }
    }

    #[test]
    fn test_put_and_parse_sockaddr_v4() {
        let mut buf = BytesMut::new();
        let test_addr = SocketAddr::V4(std::net::SocketAddrV4::new(
            Ipv4Addr::new(192, 168, 1, 100),
            8080,
        ));

        // Write the TLV
        put_socketaddr(&mut buf, DataType::ASA, &test_addr);

        // Parse it back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify the result
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::ASA).unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TlvValue::SocketAddr(addr) => assert_eq!(*addr, test_addr),
            _ => panic!("Expected SocketAddr value for ASA"),
        }
    }

    #[test]
    fn test_put_and_parse_sockaddr_v6() {
        let mut buf = BytesMut::new();
        let test_addr = SocketAddr::V6(std::net::SocketAddrV6::new(
            Ipv6Addr::new(
                0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
            ),
            9090,
            0,
            0,
        ));

        // Write the TLV
        put_socketaddr(&mut buf, DataType::ASA, &test_addr);

        // Parse it back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify the result
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::ASA).unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TlvValue::SocketAddr(addr) => assert_eq!(*addr, test_addr),
            _ => panic!("Expected SocketAddr value for ASA"),
        }
    }

    #[test]
    fn test_parse_multiple_sockaddrs() {
        let mut buf = BytesMut::new();
        let addr_v4_1 = SocketAddr::V4(std::net::SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, 1),
            3000,
        ));
        let addr_v4_2 = SocketAddr::V4(std::net::SocketAddrV4::new(
            Ipv4Addr::new(172, 16, 0, 1),
            4000,
        ));
        let addr_v6 = SocketAddr::V6(std::net::SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            5000,
            0,
            0,
        ));

        // Write multiple ASA TLVs with different socket addresses
        put_socketaddr(&mut buf, DataType::ASA, &addr_v4_1);
        put_socketaddr(&mut buf, DataType::ASA, &addr_v4_2);
        put_socketaddr(&mut buf, DataType::ASA, &addr_v6);

        // Parse them back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify all values
        assert_eq!(result.len(), 1); // Only one TLV type (ASA)
        let asa_values = result.get(&DataType::ASA).unwrap();
        assert_eq!(asa_values.len(), 3); // Three socket addresses

        match &asa_values[0] {
            TlvValue::SocketAddr(addr) => assert_eq!(*addr, addr_v4_1),
            _ => panic!("Expected SocketAddr value for ASA[0]"),
        }
        match &asa_values[1] {
            TlvValue::SocketAddr(addr) => assert_eq!(*addr, addr_v4_2),
            _ => panic!("Expected SocketAddr value for ASA[1]"),
        }
        match &asa_values[2] {
            TlvValue::SocketAddr(addr) => assert_eq!(*addr, addr_v6),
            _ => panic!("Expected SocketAddr value for ASA[2]"),
        }
    }

    #[test]
    fn test_sockaddr_tlv_structure() {
        let mut buf = BytesMut::new();
        let test_addr_v4 = SocketAddr::V4(std::net::SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            8443,
        ));

        // Write the TLV
        put_socketaddr(&mut buf, DataType::ASA, &test_addr_v4);

        // Verify the buffer structure manually
        let bytes = buf.as_ref();

        // Check header
        assert_eq!(bytes[0], DataType::ASA); // TLV type
        assert_eq!(bytes[1], SOCKADDR_LEN_V4); // TLV length (6 bytes for IPv4 + port)

        // Check IPv4 address bytes (127.0.0.1)
        assert_eq!(bytes[2], 127);
        assert_eq!(bytes[3], 0);
        assert_eq!(bytes[4], 0);
        assert_eq!(bytes[5], 1);

        // Check port bytes (8443 in big-endian)
        let port_bytes = &bytes[6..8];
        let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
        assert_eq!(port, 8443);
    }

    #[test]
    fn test_sockaddr_v6_tlv_structure() {
        let mut buf = BytesMut::new();
        let test_addr_v6 = SocketAddr::V6(std::net::SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            443,
            0,
            0,
        ));

        // Write the TLV
        put_socketaddr(&mut buf, DataType::ASA, &test_addr_v6);

        // Verify the buffer structure manually
        let bytes = buf.as_ref();

        // Check header
        assert_eq!(bytes[0], DataType::ASA); // TLV type
        assert_eq!(bytes[1], SOCKADDR_LEN_V6); // TLV length (18 bytes for IPv6 + port)

        // Check first few bytes of IPv6 address (2001:db8::1)
        assert_eq!(bytes[2], 0x20);
        assert_eq!(bytes[3], 0x01);
        assert_eq!(bytes[4], 0x0d);
        assert_eq!(bytes[5], 0xb8);

        // Check port bytes at the end (443 in big-endian)
        let port_bytes = &bytes[18..20];
        let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_bad_asa_length() {
        let mut buf = BytesMut::new();

        // Add an ASA TLV with invalid length (not 6 or 18)
        buf.put_u8(DataType::ASA);
        buf.put_u8(8); // Invalid length for ASA (should be 6 for IPv4 or 18 for IPv6)
        buf.put_u64(0x0123456789abcdef);

        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader);

        assert!(matches!(result, Err(TlvError::BadStructure)));
    }

    #[test]
    fn test_mixed_asa_and_aaa() {
        let mut buf = BytesMut::new();

        // Add an AAA (plain IP address)
        let ipv4_addr = Ipv4Addr::new(10, 0, 0, 1);
        put_ipv4addr(&mut buf, DataType::AAA, &ipv4_addr);

        // Add an ASA (socket address)
        let socket_addr = SocketAddr::V4(std::net::SocketAddrV4::new(
            Ipv4Addr::new(10, 0, 0, 2),
            8080,
        ));
        put_socketaddr(&mut buf, DataType::ASA, &socket_addr);

        // Parse them back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify we have 2 different TLV types
        assert_eq!(result.len(), 2);

        // Check AAA (plain IP address)
        let aaa_values = result.get(&DataType::AAA).unwrap();
        assert_eq!(aaa_values.len(), 1);
        match &aaa_values[0] {
            TlvValue::Ipv4Addr(addr) => assert_eq!(*addr, ipv4_addr),
            _ => panic!("Expected Ipv4Addr value for AAA"),
        }

        // Check ASA (socket address)
        let asa_values = result.get(&DataType::ASA).unwrap();
        assert_eq!(asa_values.len(), 1);
        match &asa_values[0] {
            TlvValue::SocketAddr(addr) => assert_eq!(*addr, socket_addr),
            _ => panic!("Expected SocketAddr value for ASA"),
        }
    }

    #[test]
    fn test_tlv_value_display_sockaddr() {
        let addr_v4 = SocketAddr::V4(std::net::SocketAddrV4::new(
            Ipv4Addr::new(192, 168, 1, 1),
            8080,
        ));
        let addr_v6 = SocketAddr::V6(std::net::SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            443,
            0,
            0,
        ));

        let tlv_v4 = TlvValue::SocketAddr(addr_v4);
        let tlv_v6 = TlvValue::SocketAddr(addr_v6);

        // Test that Display formatting works correctly
        assert_eq!(format!("{}", tlv_v4), "192.168.1.1:8080");
        assert_eq!(format!("{}", tlv_v6), "[2001:db8::1]:443");
    }

    #[test]
    fn test_new_aaa_ipv4_encoding() {
        let mut buf = BytesMut::new();
        let test_ipv4 = Ipv4Addr::new(192, 168, 1, 100);
        let ip_address = IpAddress::from(test_ipv4);

        // Create AAA TLV using new_aaa function
        let aaa_encoding = TlvEncoding::new_aaa(ip_address);
        aaa_encoding.put(&mut buf);

        // Parse it back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify the result
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::AAA).unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TlvValue::Ipv4Addr(addr) => assert_eq!(*addr, test_ipv4),
            _ => panic!("Expected Ipv4Addr value for AAA created with new_aaa"),
        }
    }

    #[test]
    fn test_new_static_addr_encoding_ipv4() {
        let mut buf = BytesMut::new();
        let test_ipv4 = Ipv4Addr::new(192, 168, 1, 100);
        let ip_address = IpAddress::from(test_ipv4);

        // Create STATIC_ADDR TLV using new_static_addr function
        let static_encoding = TlvEncoding::new_static_addr(ip_address);
        static_encoding.put(&mut buf);

        // Parse it back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify the result
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::STATIC_ADDR).unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TlvValue::Ipv4Addr(addr) => assert_eq!(*addr, test_ipv4),
            _ => panic!("Expected Ipv4Addr value for STATIC_ADDR created with new_static_addr"),
        }
    }

    #[test]
    fn test_new_aaa_ipv6_encoding() {
        let mut buf = BytesMut::new();
        let test_ipv6 = Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
        );
        let ip_address = IpAddress::from(test_ipv6);

        // Create AAA TLV using new_aaa function
        let aaa_encoding = TlvEncoding::new_aaa(ip_address);
        aaa_encoding.put(&mut buf);

        // Parse it back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify the result
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::AAA).unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TlvValue::Ipv6Addr(addr) => assert_eq!(*addr, test_ipv6),
            _ => panic!("Expected Ipv6Addr value for AAA created with new_aaa"),
        }
    }

    #[test]
    fn test_new_static_addr_encoding_ipv6() {
        let mut buf = BytesMut::new();
        let test_ipv6 = Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x0000, 0x0000, 0x8a2e, 0x0370, 0x7334,
        );
        let ip_address = IpAddress::from(test_ipv6);

        // Create STATIC_ADDR TLV using new_static_addr function
        let static_encoding = TlvEncoding::new_static_addr(ip_address);
        static_encoding.put(&mut buf);

        // Parse it back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify the result
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::STATIC_ADDR).unwrap();
        assert_eq!(values.len(), 1);
        match &values[0] {
            TlvValue::Ipv6Addr(addr) => assert_eq!(*addr, test_ipv6),
            _ => panic!("Expected Ipv6Addr value for STATIC_ADDR created with new_static_addr"),
        }
    }

    #[test]
    fn test_new_aaa_localhost_addresses() {
        let mut buf = BytesMut::new();

        // Test IPv4 localhost
        let ipv4_localhost = IpAddress::from(Ipv4Addr::LOCALHOST);
        let aaa_v4 = TlvEncoding::new_aaa(ipv4_localhost);
        aaa_v4.put(&mut buf);

        // Test IPv6 localhost
        let ipv6_localhost = IpAddress::from(Ipv6Addr::LOCALHOST);
        let aaa_v6 = TlvEncoding::new_aaa(ipv6_localhost);
        aaa_v6.put(&mut buf);

        // Parse both back
        let mut buf_reader = buf.as_ref();
        let result = parse_from_buf(&mut buf_reader).unwrap();

        // Verify we have one TLV type with two values
        assert_eq!(result.len(), 1);
        let values = result.get(&DataType::AAA).unwrap();
        assert_eq!(values.len(), 2);

        // Check IPv4 localhost
        match &values[0] {
            TlvValue::Ipv4Addr(addr) => assert_eq!(*addr, Ipv4Addr::LOCALHOST),
            _ => panic!("Expected Ipv4Addr value for IPv4 localhost AAA"),
        }

        // Check IPv6 localhost
        match &values[1] {
            TlvValue::Ipv6Addr(addr) => assert_eq!(*addr, Ipv6Addr::LOCALHOST),
            _ => panic!("Expected Ipv6Addr value for IPv6 localhost AAA"),
        }
    }

    #[test]
    fn test_new_aaa_tlv_structure_ipv4() {
        let mut buf = BytesMut::new();
        let test_ipv4 = Ipv4Addr::new(10, 0, 0, 1);
        let ip_address = IpAddress::from(test_ipv4);

        // Create AAA TLV using new_aaa function
        let aaa_encoding = TlvEncoding::new_aaa(ip_address);
        aaa_encoding.put(&mut buf);

        // Verify the buffer structure manually
        let bytes = buf.as_ref();

        // Check header
        assert_eq!(bytes[0], DataType::AAA); // TLV type
        assert_eq!(bytes[1], 4); // TLV length (4 bytes for IPv4)

        // Check IPv4 address bytes (10.0.0.1)
        assert_eq!(bytes[2], 10);
        assert_eq!(bytes[3], 0);
        assert_eq!(bytes[4], 0);
        assert_eq!(bytes[5], 1);
    }

    #[test]
    fn test_new_aaa_tlv_structure_ipv6() {
        let mut buf = BytesMut::new();
        let test_ipv6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
        let ip_address = IpAddress::from(test_ipv6);

        // Create AAA TLV using new_aaa function
        let aaa_encoding = TlvEncoding::new_aaa(ip_address);
        aaa_encoding.put(&mut buf);

        // Verify the buffer structure manually
        let bytes = buf.as_ref();

        // Check header
        assert_eq!(bytes[0], DataType::AAA); // TLV type
        assert_eq!(bytes[1], 16); // TLV length (16 bytes for IPv6)

        // Check first few bytes of IPv6 address (2001:db8::1)
        assert_eq!(bytes[2], 0x20);
        assert_eq!(bytes[3], 0x01);
        assert_eq!(bytes[4], 0x0d);
        assert_eq!(bytes[5], 0xb8);

        // Check that bytes 6-15 are zero (representing the compressed ::)
        for i in 6..17 {
            assert_eq!(bytes[i], 0);
        }

        // Check last byte is 1
        assert_eq!(bytes[17], 1);
    }
}
