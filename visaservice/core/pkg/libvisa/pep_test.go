package libvisa_test

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/libvisa"
	"zpr.org/vs/pkg/policy"

	"zpr.org/vsx/polio"
)

func makeBWConstraint(bps uint64) *polio.Constraint {
	c := new(polio.BWConstraint)
	c.BitsPerSec = bps
	return &polio.Constraint{
		Carg: &polio.Constraint_Bw{c},
	}
}

func makeDataCapConstraint(cap, seconds uint64) *polio.Constraint {
	c := new(polio.DataCapConstraint)
	c.CapBytes = cap
	c.PeriodSeconds = seconds
	return &polio.Constraint{
		Carg: &polio.Constraint_Cap{c},
	}
}

func makeDurationConstraint(seconds uint64) *polio.Constraint {
	c := new(polio.DurConstraint)
	c.Seconds = seconds
	return &polio.Constraint{
		Carg: &polio.Constraint_Dur{c},
	}
}

func TestTCPPepCreate(t *testing.T) {
	traffic := new(snip.Traffic)
	traffic.Proto = snip.ProtocolTCP
	traffic.SrcPort = 12345
	traffic.DstPort = 80
	traffic.SrcAddr = netip.MustParseAddr("fc00:3001::8")
	traffic.DstAddr = netip.MustParseAddr("fc00:3001::9")

	var matchingPols []*policy.MatchedPolicy

	p := new(policy.MatchedPolicy)
	p.FWD = true
	matchingPols = append(matchingPols, p)

	vc, err := libvisa.InitPEP(traffic, matchingPols)
	require.Nil(t, err)
	require.NotNil(t, vc)

	// These could have to come from policy
	require.Zero(t, vc.Lifetime)
	require.False(t, vc.BWLimit)
	require.False(t, vc.DataCap)

	require.Equal(t, uint32(libvisa.PEPDockTCP), vc.DockPEP)

	require.NotEmpty(t, vc.DockPEPArgs)

	args := vc.DockPEPArgs.(*libvisa.PEPArgsTCP)
	require.NotNil(t, args)

	// Since this is forward (client to server) and client is high numbered, the matcher will
	// allow for any source port.
	require.Equal(t, uint16(0), uint16(args.SourcePort))

	require.Equal(t, traffic.DstPort, uint16(args.DestPort))
	require.Equal(t, traffic.DstAddr.AsSlice(), args.DestContactAddr)
	require.Equal(t, traffic.SrcAddr.AsSlice(), args.SourceContactAddr)

	require.False(t, args.Server) // This matched traffic from the client, not the server.

	// For TCP additional ICMP is also covered.
	require.Equal(t, len(libvisa.ICMPAllowIfTCPVisa), len(args.IcmpAllowed))
}

func TestTCPPepCreateWithBWLimit(t *testing.T) {
	traffic := new(snip.Traffic)
	traffic.Proto = snip.ProtocolTCP
	traffic.SrcPort = 12345
	traffic.DstPort = 80
	traffic.SrcAddr = netip.MustParseAddr("fc00:3001::8")
	traffic.DstAddr = netip.MustParseAddr("fc00:3001::9")

	var matchingPols []*policy.MatchedPolicy

	p := new(policy.MatchedPolicy)
	p.FWD = true
	p.CPol = &polio.CPolicy{
		Constraints: []*polio.Constraint{makeBWConstraint(1000)},
	}
	matchingPols = append(matchingPols, p)

	vc, err := libvisa.InitPEP(traffic, matchingPols)
	require.Nil(t, err)
	require.NotNil(t, vc)

	require.Zero(t, vc.Lifetime)
	require.False(t, vc.DataCap)
	require.True(t, vc.BWLimit)
	require.Equal(t, uint64(1000), vc.BitsPerSecond)
}

func TestTCPPepCreateWithDataCap(t *testing.T) {
	traffic := new(snip.Traffic)
	traffic.Proto = snip.ProtocolTCP
	traffic.SrcPort = 12345
	traffic.DstPort = 80
	traffic.SrcAddr = netip.MustParseAddr("fc00:3001::8")
	traffic.DstAddr = netip.MustParseAddr("fc00:3001::9")

	var matchingPols []*policy.MatchedPolicy

	p := new(policy.MatchedPolicy)
	p.FWD = true
	p.CPol = &polio.CPolicy{
		Constraints: []*polio.Constraint{makeDataCapConstraint(3000, 8000)}, // 3000 bytes over 8000 seconds
	}
	matchingPols = append(matchingPols, p)

	vc, err := libvisa.InitPEP(traffic, matchingPols)
	require.Nil(t, err)
	require.NotNil(t, vc)

	require.Zero(t, vc.Lifetime)
	require.False(t, vc.BWLimit)
	require.True(t, vc.DataCap)
	require.NotNil(t, vc.Cap)
	require.Equal(t, uint64(3000), vc.Cap.CapBytes)
	require.Equal(t, 8000*time.Second, vc.Cap.CapPeriod)
}

func TestTCPPepCreateWithDurationConstraint(t *testing.T) {
	traffic := new(snip.Traffic)
	traffic.Proto = snip.ProtocolTCP
	traffic.SrcPort = 12345
	traffic.DstPort = 80
	traffic.SrcAddr = netip.MustParseAddr("fc00:3001::8")
	traffic.DstAddr = netip.MustParseAddr("fc00:3001::9")

	var matchingPols []*policy.MatchedPolicy

	p := new(policy.MatchedPolicy)
	p.FWD = true
	p.CPol = &polio.CPolicy{
		Constraints: []*polio.Constraint{makeDurationConstraint(8000)}, // 8000 seconds
	}
	matchingPols = append(matchingPols, p)

	vc, err := libvisa.InitPEP(traffic, matchingPols)
	require.Nil(t, err)
	require.NotNil(t, vc)

	require.False(t, vc.BWLimit)
	require.False(t, vc.DataCap)
	require.Equal(t, 8000*time.Second, vc.Lifetime)
}

func TestUDPPepCreate(t *testing.T) {
	traffic := new(snip.Traffic)
	traffic.Proto = snip.ProtocolUDP
	traffic.SrcPort = 12345
	traffic.DstPort = 80
	traffic.SrcAddr = netip.MustParseAddr("fc00:3001::8")
	traffic.DstAddr = netip.MustParseAddr("fc00:3001::9")

	var matchingPols []*policy.MatchedPolicy

	p := new(policy.MatchedPolicy)
	p.FWD = true
	matchingPols = append(matchingPols, p)

	vc, err := libvisa.InitPEP(traffic, matchingPols)
	require.Nil(t, err)
	require.NotNil(t, vc)

	require.Zero(t, vc.Lifetime) // not touched

	// These could have to come from policy
	require.False(t, vc.BWLimit)
	require.False(t, vc.DataCap)

	require.Equal(t, uint32(libvisa.PEPDockUDP), vc.DockPEP)

	require.NotEmpty(t, vc.DockPEPArgs)

	args := vc.DockPEPArgs.(*libvisa.PEPArgsUDP)
	require.NotNil(t, args)

	// Since this is forward (client to server) and client is high numbered, the matcher will
	// allow for any source port.
	require.Equal(t, uint16(0), uint16(args.SourcePort))

	require.Equal(t, traffic.DstPort, uint16(args.DestPort))
	require.Equal(t, traffic.DstAddr.AsSlice(), args.DestContactAddr)
	require.Equal(t, traffic.SrcAddr.AsSlice(), args.SourceContactAddr)

	// For UDP additional ICMP is also covered.
	require.Equal(t, len(libvisa.ICMPAllowIfUDPVisa), len(args.IcmpAllowed))
}

func TestICMPPepCreate(t *testing.T) {
	traffic := new(snip.Traffic)
	traffic.Proto = snip.ProtocolICMP6
	traffic.SrcAddr = netip.MustParseAddr("fc00:3001::8")
	traffic.DstAddr = netip.MustParseAddr("fc00:3001::9")
	traffic.ICMPType = 128 // echo-request
	traffic.ICMPCode = 0

	var matchingPols []*policy.MatchedPolicy

	p := new(policy.MatchedPolicy)
	p.FWD = true
	p.Metadata = &policy.MatchMetadata{
		IcmpType:               polio.ICMPT_ICMPT_REQREP,
		IcmpRequiresAntecedent: false,
		IcmpAntecedent:         0,
	}
	matchingPols = append(matchingPols, p)

	vc, err := libvisa.InitPEP(traffic, matchingPols)
	require.Nil(t, err)
	require.NotNil(t, vc)

	require.Zero(t, vc.Lifetime) // not touched

	// These could have to come from policy
	require.False(t, vc.BWLimit)
	require.False(t, vc.DataCap)

	require.Equal(t, uint32(libvisa.PEPDockICMP), vc.DockPEP)

	require.NotEmpty(t, vc.DockPEPArgs)

	args := vc.DockPEPArgs.(*libvisa.PEPArgsICMP)
	require.NotNil(t, args)

	require.Equal(t, traffic.DstAddr.AsSlice(), args.DestContactAddr)
	require.Equal(t, traffic.SrcAddr.AsSlice(), args.SourceContactAddr)

	// Note that field name is TypeCode but we only store TYPE.
	require.Equal(t, uint32(0x80), args.IcmpTypeCode)

	require.Equal(t, libvisa.ICMPAntecedentNone, uint16(args.IcmpAntecedent))
	require.False(t, args.OneShot)
}
