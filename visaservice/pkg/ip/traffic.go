package ip

import (
	"errors"
	"fmt"
	"net/netip"
	// "github.com/google/gopacket"
	// "github.com/google/gopacket/layers"
)

type Protocol uint8

const (
	ProtocolICMP6 Protocol = 58
	ProtocolTCP   Protocol = 0x6
	ProtocolUDP   Protocol = 0x11
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
	if t.Proto == ProtocolICMP6 {
		return fmt.Sprintf("ICMP/%d:%d", t.ICMPType, t.ICMPCode)
	}
	return fmt.Sprintf("%v/%d->%d", t.Proto, t.SrcPort, t.DstPort)
}
