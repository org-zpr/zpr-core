package ip

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Protocol uint8

const (
	ProtocolICMP4 Protocol = 1
	ProtocolTCP   Protocol = 6
	ProtocolUDP   Protocol = 17
	ProtocolICMP6 Protocol = 58
)

// Layer 3 type - for allowed values see `zpr.rs` file in ph crate.
type L3Type uint8

const (
	L3TypeIPv4 L3Type = 4
	L3TypeIPv6 L3Type = 6
)

var (
	ErrHopByHop = errors.New("IPv6HopByHop not supported")
)

type Traffic struct {
	SrcAddr           netip.Addr
	DstAddr           netip.Addr
	Proto             Protocol
	SrcPort           uint16
	DstPort           uint16
	Connect           bool // True if this is determinted to be a connection request. Only valid for TCP.
	Syn               bool // TODO: Remove these bools, just use FLAGS value.
	Fin               bool
	Rst               bool
	Urg               bool
	Psh               bool
	Ack               bool // True if ACK is set (for TCP only)
	ICMPType          byte
	ICMPCode          byte
	ICMPTargetAddress netip.Addr // For ICMP neighbor solicitation only
	Size              int        // length of packet under analysis (not from a header field)
	Flags             uint32     // for TCP bottom 9 bits are TCP flags.
}

func (p Protocol) String() string {
	switch p {
	case ProtocolICMP6:
		return "ICMP6"
	case ProtocolICMP4:
		return "ICMP4"
	case ProtocolTCP:
		return "TCP"
	case ProtocolUDP:
		return "UDP"
	default:
		return fmt.Sprintf("%d", uint8(p))
	}
}

func (p Protocol) Equal(o Protocol) bool {
	return uint8(p) == uint8(o)
}

func ProtocolFromString(ps string) (Protocol, error) {
	switch ps {
	case "tcp", "TCP":
		return ProtocolTCP, nil
	case "icmp6", "ICMP6":
		return ProtocolICMP6, nil
	case "icmp4", "ICMP4", "icmp", "ICMP":
		return ProtocolICMP4, nil
	case "udp", "UDP":
		return ProtocolUDP, nil
	default:
		return Protocol(0), fmt.Errorf("unknown protocol: %v", ps)
	}
}

func (p Protocol) Num() uint32 {
	return uint32(p)
}

func NewTCPConnect(source netip.Addr, sourcePort uint16, dest netip.Addr, destPort uint16) *Traffic {
	return &Traffic{
		SrcAddr: source,
		DstAddr: dest,
		Proto:   ProtocolTCP,
		SrcPort: sourcePort,
		DstPort: destPort,
		Connect: true,
		Syn:     true,
		Flags:   0x2,
	}
}

// Flow returns a string like "TCP/29212->80"
func (t *Traffic) Flow() string {
	if t.Proto == ProtocolICMP6 || t.Proto == ProtocolICMP4 {
		return fmt.Sprintf("ICMP/%d:%d", t.ICMPType, t.ICMPCode)
	}
	return fmt.Sprintf("%v/%d->%d", t.Proto, t.SrcPort, t.DstPort)
}

// Supports IPv4 or v6, TCP, UDP, ICMP, ICMP6.
// Note that original (prototype) visa service does not support IPv4.
func DescribePacket(l3Type L3Type, pkt []byte) (*Traffic, error) {

	var ip6 layers.IPv6
	var ip4 layers.IPv4
	var tcp layers.TCP
	var udp layers.UDP
	var icmp4 layers.ICMPv4
	var icmp6 layers.ICMPv6
	var icmp6ns layers.ICMPv6NeighborSolicitation

	var parser *gopacket.DecodingLayerParser

	switch l3Type {
	case L3TypeIPv4:
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv4, &ip4, &tcp, &udp, &icmp4)
	case L3TypeIPv6:
		parser = gopacket.NewDecodingLayerParser(layers.LayerTypeIPv6, &ip6, &tcp, &udp, &icmp6, &icmp6ns)
	default:
		return nil, fmt.Errorf("unsupported L3 type: %v", l3Type)
	}

	parser.DecodingLayerParserOptions.IgnoreUnsupported = true

	decodedLayers := make([]gopacket.LayerType, 0, 8)
	err := parser.DecodeLayers(pkt, &decodedLayers)
	if err != nil {
		return nil, err
	}

	t := new(Traffic)
	t.Size = len(pkt)
	var ok bool

	for _, typ := range decodedLayers {
		switch typ {
		case layers.LayerTypeIPv4:
			t.SrcAddr, ok = netip.AddrFromSlice(ip4.SrcIP)
			if !ok {
				return nil, fmt.Errorf("parse failed for source address")
			}
			t.DstAddr, ok = netip.AddrFromSlice(ip4.DstIP)
			if !ok {
				return nil, fmt.Errorf("parse failed for destination address")
			}

		case layers.LayerTypeIPv6:
			t.SrcAddr, ok = netip.AddrFromSlice(ip6.SrcIP)
			if !ok {
				return nil, fmt.Errorf("parse failed for source address")
			}
			t.DstAddr, ok = netip.AddrFromSlice(ip6.DstIP)
			if !ok {
				return nil, fmt.Errorf("parse failed for destination address")
			}

		case layers.LayerTypeTCP:
			t.SrcPort = uint16(tcp.SrcPort)
			t.DstPort = uint16(tcp.DstPort)
			t.Proto = ProtocolTCP
			if tcp.FIN {
				t.Flags |= 0x00000001
				t.Fin = true
			}
			if tcp.SYN {
				t.Flags |= 0x00000002
				t.Syn = true
				t.Connect = tcp.SYN && !tcp.ACK
			}
			if tcp.RST {
				t.Flags |= 0x00000004
				t.Rst = true
			}
			if tcp.PSH {
				t.Flags |= 0x00000008
				t.Psh = true
			}
			if tcp.ACK {
				t.Flags |= 0x00000010
				t.Ack = true
			}
			if tcp.URG {
				t.Flags |= 0x00000020
				t.Urg = true
			}
			if tcp.ECE {
				t.Flags |= 0x00000040
			}
			if tcp.CWR {
				t.Flags |= 0x00000080
			}
			if tcp.NS {
				t.Flags |= 0x00000100
			}

		case layers.LayerTypeUDP:
			t.SrcPort = uint16(udp.SrcPort)
			t.DstPort = uint16(udp.DstPort)
			t.Proto = ProtocolUDP

		case layers.LayerTypeICMPv4:
			t.Proto = ProtocolICMP4
			icmpTypeCode := uint16(icmp4.TypeCode)
			t.ICMPType = byte(icmpTypeCode >> 8)
			t.ICMPCode = byte(icmpTypeCode & 0x00ff)

		case layers.LayerTypeICMPv6:
			t.Proto = ProtocolICMP6
			icmpTypeCode := uint16(icmp6.TypeCode)
			t.ICMPType = byte(icmpTypeCode >> 8)
			t.ICMPCode = byte(icmpTypeCode & 0x00ff)

		case layers.LayerTypeICMPv6NeighborSolicitation:
			t.ICMPTargetAddress, _ = netip.AddrFromSlice(icmp6ns.TargetAddress)
		}
	}
	return t, nil
}
