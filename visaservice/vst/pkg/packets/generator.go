package packets

import (
	"fmt"
	"math/rand"
	"net/netip"

	"zpr.org/vsx/polio"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const L3IPv4 = 4 // used for RequestVisa call
const L3IPv6 = 6 // used for RequestVisa call

const MaxPort = 65535
const MinSrcPort = 1024

const ProtocolTCP = uint32(6)

// For TCP, generates a SYN packet.
// Returns (PACKET, L3TYPE, ERROR)
func GeneratePacket(srcAddr, dstAddr netip.Addr, endpoint *polio.Scope) ([]byte, int, error) {
	if endpoint.Protocol != ProtocolTCP {
		return nil, 0, fmt.Errorf("only TCP is supported")
	}

	sport := RandPort()

	var dport int
	ps := endpoint.GetPspec().Spec[0]
	switch psarg := ps.GetParg().(type) {
	case *polio.PortSpec_Port:
		dport = int(psarg.Port)
	case *polio.PortSpec_Pr:
		dport = int(psarg.Pr.Low)
	}

	pkt, err := GenerateTCPPacket(srcAddr, sport, dstAddr, dport)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to generate packet: %w", err)
	}

	l3Type := L3IPv4
	if srcAddr.Is6() {
		l3Type = L3IPv6
	}
	return pkt, l3Type, nil
}

// RandPort return a TCP/UDP port between 1024 and 65535.
func RandPort() uint16 {
	return uint16(MinSrcPort + rand.Intn(MaxPort-MinSrcPort))
}

func GenerateTCPPacket(srcAddr netip.Addr, sport uint16, dstAddr netip.Addr, dport int) ([]byte, error) {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	payload := []byte("ZPR TEST PACKET PAYLOAD")

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(sport),
		DstPort: layers.TCPPort(dport),
		SYN:     true,
	}

	if srcAddr.Is6() {
		ip := &layers.IPv6{
			Version:    6,
			SrcIP:      srcAddr.AsSlice(),
			DstIP:      dstAddr.AsSlice(),
			NextHeader: layers.IPProtocolTCP,
		}
		tcp.SetNetworkLayerForChecksum(ip)
		if err := gopacket.SerializeLayers(buf, opts,
			ip,
			tcp,
			gopacket.Payload(payload)); err != nil {
			return nil, err
		}
	} else {
		ip := &layers.IPv4{
			SrcIP:    srcAddr.AsSlice(),
			DstIP:    dstAddr.AsSlice(),
			Protocol: layers.IPProtocolTCP,
		}
		tcp.SetNetworkLayerForChecksum(ip)
		if err := gopacket.SerializeLayers(buf, opts,
			ip,
			tcp,
			gopacket.Payload(payload)); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}
