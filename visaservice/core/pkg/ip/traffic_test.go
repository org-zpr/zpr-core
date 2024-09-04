package ip_test

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	snip "zpr.org/vs/pkg/ip"
)

// used as source and dest in IPv6 test packets
var testAddr = netip.MustParseAddr("fc00:9001::88")

// TCP SYN HTTP (IPv6)
var tcpHTTP = []byte{
	0x60, 0x08, 0x5a, 0xd2, 0x00, 0x28, 0x06, 0x40, 0xfc, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xfc, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xbc, 0x1c, 0x00, 0x50, 0x3a, 0x3e, 0xb7, 0xab,
	0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xff, 0xc4, 0x19, 0x43, 0x00, 0x00, 0x02, 0x04, 0xff, 0xc4,
	0x04, 0x02, 0x08, 0x0a, 0x1f, 0x90, 0x8e, 0x21, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
}

// UDP to 59913 -> 8787 (IPv6)
var udpMsg = []byte{
	0x60, 0x01, 0x54, 0xf6, 0x00, 0x15, 0x11, 0x40, 0xfc, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xfc, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0xea, 0x09, 0x22, 0x53, 0x00, 0x15, 0x19, 0x3b,
	0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x74, 0x6f, 0x20, 0x79, 0x6f, 0x75, 0x0a,
}

// TCP SYN  (IPv4)
// 192.168.86.54:60250 -> 192.168.0.1:31337
var tcp4 = []byte{
	0x45, 0x10, 0x00, 0x3c, 0xb6, 0x1b, 0x40, 0x00, 0x40, 0x06, 0xad, 0x08, 0xc0, 0xa8, 0x56, 0x36,
	0xc0, 0xa8, 0x00, 0x01, 0xeb, 0x5a, 0x7a, 0x69, 0xd5, 0xaa, 0x1c, 0x3e, 0x00, 0x00, 0x00, 0x00,
	0xa0, 0x02, 0xfa, 0xf0, 0xd7, 0xb6, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
	0xfd, 0xe2, 0x50, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
}

func TestDescribesICMP(t *testing.T) {

	src := netip.MustParseAddr("fc00:1001::33")
	dst := netip.MustParseAddr("fc00:1001::44")
	pkt := ICMPUnreachable(src, dst, 0, []byte("very nice"))

	td, err := snip.DescribePacket(snip.L3TypeIPv6, pkt)
	require.NoError(t, err)

	require.Equal(t, snip.ProtocolICMP6, td.Proto)
	require.Equal(t, uint8(0x01), td.ICMPType)
	require.Equal(t, uint8(0x00), td.ICMPCode)

}

func TestDescribeTCP(t *testing.T) {
	td, err := snip.DescribePacket(snip.L3TypeIPv6, tcpHTTP)
	require.NoError(t, err)

	require.Equal(t, snip.ProtocolTCP, td.Proto)
	require.Equal(t, testAddr, td.SrcAddr)
	require.Equal(t, testAddr, td.DstAddr)
	require.Equal(t, uint16(48156), td.SrcPort)
	require.Equal(t, uint16(80), td.DstPort)
	require.True(t, td.Syn)
}

func TestDescribeTCP4(t *testing.T) {
	td, err := snip.DescribePacket(snip.L3TypeIPv4, tcp4)
	require.NoError(t, err)

	src := netip.MustParseAddr("192.168.86.54")
	dst := netip.MustParseAddr("192.168.0.1")

	require.Equal(t, snip.ProtocolTCP, td.Proto)
	require.Equal(t, src, td.SrcAddr)
	require.Equal(t, dst, td.DstAddr)
	require.Equal(t, uint16(60250), td.SrcPort)
	require.Equal(t, uint16(31337), td.DstPort)
	require.True(t, td.Syn)
}

func TestDescribeUDP(t *testing.T) {
	td, err := snip.DescribePacket(snip.L3TypeIPv6, udpMsg)
	require.NoError(t, err)

	require.Equal(t, snip.ProtocolUDP, td.Proto)
	require.Equal(t, testAddr, td.SrcAddr)
	require.Equal(t, testAddr, td.DstAddr)
	require.Equal(t, uint16(59913), td.SrcPort)
	require.Equal(t, uint16(8787), td.DstPort)
}

const (
	MIN_IPV6_MTU       = 1280
	IPV6_HEADER_SIZE   = 40
	ICMPV6_HEADER_SIZE = 8
)

// ICMPUnreachable create an icmp unreachable IPv6 packet.
// `code` is the ICMP code to use. Normally should be zero.
//
// Code values:
//
//	0 - No route to destination
//	1 - Communication with destination
//	    administratively prohibited
//	2 - Beyond scope of source address
//	3 - Address unreachable
//	4 - Port unreachable
//	5 - Source address failed ingress/egress policy
//	6 - Reject route to destination
func ICMPUnreachable(source, dest netip.Addr, code uint8, origpacket []byte) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	sz := len(origpacket)
	if sz > MIN_IPV6_MTU-(IPV6_HEADER_SIZE+ICMPV6_HEADER_SIZE) {
		sz = MIN_IPV6_MTU - (IPV6_HEADER_SIZE + ICMPV6_HEADER_SIZE)
	}

	payload := gopacket.Payload(origpacket[:sz])

	icmp := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(1, code),
	}

	ipv6 := &layers.IPv6{
		Version:    6,
		SrcIP:      source.AsSlice(),
		DstIP:      dest.AsSlice(),
		NextHeader: layers.IPProtocolICMPv6,
		HopLimit:   254,
		Length:     1024,
	}

	icmp.SetNetworkLayerForChecksum(ipv6)

	if err := payload.SerializeTo(buf, opts); err != nil {
		panic(fmt.Sprintf("failed to serialize payload: %v", err))
	}
	if err := icmp.SerializeTo(buf, opts); err != nil {
		panic(fmt.Sprintf("failed to serialize icmp: %v", err))
	}
	if err := ipv6.SerializeTo(buf, opts); err != nil {
		panic(fmt.Sprintf("failed to serialize ipv6: %v", err))
	}

	return buf.Bytes()
}
