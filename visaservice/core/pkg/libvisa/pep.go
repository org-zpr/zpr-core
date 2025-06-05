package libvisa

import (
	"errors"
	"fmt"
	"net/netip"
	"time"

	"golang.org/x/net/ipv6"

	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/policy"

	"zpr.org/vsx/polio"
)

var (
	// ICMPAllowIfTCPVisa these ICMP messages are allowed between hosts if they have an active TCP visa.
	// Note that these are ICMP type values (without code values).
	ICMPAllowIfTCPVisa = []ipv6.ICMPType{
		ipv6.ICMPTypeDestinationUnreachable,
		ipv6.ICMPTypePacketTooBig,
		ipv6.ICMPTypeTimeExceeded,
		ipv6.ICMPTypeParameterProblem,
	}

	// ICMPAllowIfTCPVisa these ICMP messages are allowed between hosts if they have an active UDP visa
	ICMPAllowIfUDPVisa = []ipv6.ICMPType{
		ipv6.ICMPTypeDestinationUnreachable,
		ipv6.ICMPTypePacketTooBig,
		ipv6.ICMPTypeTimeExceeded,
		ipv6.ICMPTypeParameterProblem,
	}
)

// Well known PEP indexes
const (
	PEPDockUDP  = 1
	PEPDockTCP  = 2
	PEPDockICMP = 3
)

const (
	ICMPAntecedentNone   uint16 = 0xffff // Used as antecedent ICMP-Type value when none is specified.
	DefaultICMPTimeoutMS        = 10000
)

// pepIdxForProto return the PEP index (referenced in the visa) based on the protocol in use.
func pepIdxForProto(p snip.Protocol) (uint32, error) {
	switch p {
	case snip.ProtocolTCP:
		return PEPDockTCP, nil
	case snip.ProtocolUDP:
		return PEPDockUDP, nil
	case snip.ProtocolICMP4:
		return PEPDockICMP, nil
	case snip.ProtocolICMP6:
		return PEPDockICMP, nil
	default:
		return 0, fmt.Errorf("unsupported protocol: %v", p)
	}
}

type MatchInfo struct {
	Protocol snip.Protocol
	ZPRSrc   netip.Addr
	SrcPort  uint16
	ZPRDst   netip.Addr
	DstPort  uint16
	TypeCode uint16
}

// initPEP use the traffic and policy to configure a visa PEP for matching.  Sets up PEP args, etc.
func InitPEP(td *snip.Traffic, cpols []*policy.MatchedPolicy) (*VConfig, error) {
	result := &VConfig{}
	px, err := pepIdxForProto(td.Proto)
	if err != nil {
		return nil, err
	}
	if len(cpols) < 1 {
		return nil, errors.New("cannot init PEP with no matching policies") // TODO: Should this just be a panic?
	}

	// The traffic matched policy, either as SRC->DST or as DST->SRC
	//
	// fwd means it matched SRC->DST, so the PEP needs to match traffic from "source"
	//
	// fwd=false means it matched DST->SRC so the PEP is for the "service side" and needs to match traffic destined for SRC, from "dst".

	matchy := &MatchInfo{
		Protocol: td.Proto,
		TypeCode: uint16(td.ICMPType), // Ignore code (XXX fix?)
	}

	matchy.ZPRSrc = td.SrcAddr
	matchy.ZPRDst = td.DstAddr

	// If TCP/UDP then allow for any client port when using a high numbered port.
	if cpols[0].FWD {
		if td.SrcPort > 1024 {
			matchy.SrcPort = 0
		} else {
			matchy.SrcPort = td.SrcPort
		}
		matchy.DstPort = td.DstPort
	} else {
		if td.DstPort > 1024 {
			matchy.DstPort = 0
		} else {
			matchy.DstPort = td.DstPort
		}
		matchy.SrcPort = td.SrcPort
	}

	var dockPEPArgs interface{}

	// invoke PEP first arg is always the PEP index
	switch px {
	case PEPDockUDP:
		dockPEPArgs, err = initUDP(matchy)
		if err != nil {
			return nil, err
		}

	case PEPDockTCP:
		dockPEPArgs, err = initTCP(matchy, cpols[0].FWD)
		if err != nil {
			return nil, err
		}

	case PEPDockICMP:
		var md *policy.MatchMetadata
		for _, cp := range cpols { // Not sure if the metadata is on all matching policies.
			if cp.Metadata != nil {
				md = cp.Metadata
				break // take first metadata
			}
		}
		if md == nil {
			return nil, fmt.Errorf("initPEP for ICMP but CPolicy match has no metadata info")
		}
		antecedent := ICMPAntecedentNone
		if md.IcmpRequiresAntecedent {
			antecedent = md.IcmpAntecedent // Is an ICMP type -- no code
		}
		dockPEPArgs, err = initICMP(matchy, md.IcmpType == polio.ICMPT_ICMPT_REQREP, antecedent)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("unknown PEP %d", px)
	}

	for _, cpol := range cpols {
		for _, constraint := range cpol.CPol.GetConstraints() {
			switch c := constraint.GetCarg().(type) {
			case *polio.Constraint_Bw:
				result.AddBandwidthConstraint(c)
			case *polio.Constraint_Dur:
				result.AddDurationConstraint(c)
			case *polio.Constraint_Cap:
				result.AddCapacityConstraint(cpol.CPol.GetServiceId(), constraint.GetGroup(), c)
			default:
				// hmm. What to do with an unknown constraint?
				return nil, fmt.Errorf("unsupported constraint: %v", c)
			}
		}
	}

	result.DockPEP = px
	result.DockPEPArgs = dockPEPArgs
	return result, nil
}

func MaxDurationConstraintFromPolicies(cpols []*policy.MatchedPolicy) (dur time.Duration) {
	for _, cpol := range cpols {
		for _, constraint := range cpol.CPol.GetConstraints() {
			if c := constraint.GetDur(); c != nil {
				s := time.Duration(c.GetSeconds()) * time.Second
				if s > dur {
					dur = s
				}
			}
		}
	}
	return
}

func MaximalDataCapFromPolicies(cpols []*policy.MatchedPolicy) (cap *DataCap) {
	for _, cpol := range cpols {
		for _, constraint := range cpol.CPol.GetConstraints() {
			if c := constraint.GetCap(); c != nil {

				sid := cpol.CPol.GetServiceId()
				group := constraint.GetGroup()

				thisCap := NewDataCap(sid, group, c.GetCapBytes(), c.GetPeriodSeconds())

				if cap == nil {
					cap = thisCap

				} else {
					if cap.CapGroup != "" && group == "" {
						cap = thisCap // Prefer the ungrouped cap
					}
					// Compare as BYTES/SECOND and pick largest.
					existing := (cap.CapBytes * 1.0) / uint64(cap.CapPeriod/time.Second)
					newone := (thisCap.CapBytes * 1.0) / uint64(thisCap.CapPeriod/time.Second)
					if newone > existing {
						cap = thisCap
					}
				}
			}
		}
	}
	return
}

type PEPArgsUDP struct {
	SourceContactAddr []byte
	DestContactAddr   []byte
	SourcePort        uint32
	DestPortMode      uint32 // 0=static, 1=req-port
	DestPort          uint32
	IcmpAllowed       []uint32 // ICMP types allowed if visa is active
}

func initUDP(m *MatchInfo) (*PEPArgsUDP, error) {
	pepArgs := &PEPArgsUDP{
		SourceContactAddr: m.ZPRSrc.AsSlice(),
		DestContactAddr:   m.ZPRDst.AsSlice(),
		SourcePort:        uint32(m.SrcPort),
		DestPortMode:      0, // his needs work. Need way to determine when we are creating client->server visa
		DestPort:          uint32(m.DstPort),
		IcmpAllowed:       []uint32{},
	}
	for _, icmpT := range ICMPAllowIfUDPVisa {
		pepArgs.IcmpAllowed = append(pepArgs.IcmpAllowed, uint32(icmpT))
	}
	return pepArgs, nil
}

type PEPArgsTCP struct {
	SourceContactAddr []byte
	DestContactAddr   []byte
	SourcePort        uint32
	DestPort          uint32
	Server            bool     // TRUE if this is for server side dock.
	IcmpAllowed       []uint32 // ICMP types allowed if visa is active
}

func initTCP(m *MatchInfo, isFWD bool) (*PEPArgsTCP, error) {
	pepArgs := &PEPArgsTCP{
		SourceContactAddr: m.ZPRSrc.AsSlice(),
		DestContactAddr:   m.ZPRDst.AsSlice(),
		SourcePort:        uint32(m.SrcPort),
		DestPort:          uint32(m.DstPort),
		Server:            !isFWD, // TRUE if this is for server side dock.
	}
	for _, icmpT := range ICMPAllowIfTCPVisa {
		pepArgs.IcmpAllowed = append(pepArgs.IcmpAllowed, uint32(icmpT))
	}
	return pepArgs, nil
}

type PEPArgsICMP struct {
	SourceContactAddr []byte
	DestContactAddr   []byte
	IcmpTypeCode      uint32 // the allowed ICMP type and code in lower 16 bits
	IcmpAntecedent    uint32 // use 0xFF for none
	StateTimeoutMs    uint32 // timeout for state in milliseconds
	OneShot           bool   // If we allow only on reply to a request
}

// initICMP `antecedent` is an ICMP type (no code)
func initICMP(m *MatchInfo, reqRep bool, antecedent uint16) (*PEPArgsICMP, error) {
	pepArgs := &PEPArgsICMP{
		SourceContactAddr: m.ZPRSrc.AsSlice(),
		DestContactAddr:   m.ZPRDst.AsSlice(),
		IcmpTypeCode:      uint32(m.TypeCode), // Actually just TYPE
		IcmpAntecedent:    uint32(antecedent), // Also just TYPE
		StateTimeoutMs:    uint32(DefaultICMPTimeoutMS),
		OneShot:           !reqRep,
	}
	return pepArgs, nil
}
