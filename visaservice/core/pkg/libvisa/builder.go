package libvisa

import (
	"crypto/md5"
	"fmt"
	"net/netip"
	"time"

	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vsapi"
)

type SessionKeyEncoding int

const (
	SKEv1 SessionKeyEncoding = iota // uses known, hardcoded secrets to encrypt the keys (basically proof of concept only!)
)

// DataCapFunc is used when you need to do extra work to get
// datacap constraint details.
// Arguments are (FWD, DataCap, clientActorIdent) and returns (capKey, remainBytes, error)
type DataCapFunc func(bool, *DataCap, string) (string, uint64, error)

type VisaBuilder struct {
	visaID             int32
	netConfig          uint64
	expiration         time.Time
	sourceTether       netip.Addr
	sourceContact      netip.Addr
	destTether         netip.Addr
	destContact        netip.Addr
	traffic            *snip.Traffic
	policies           []*policy.MatchedPolicy
	dynamicDataCapCBFn DataCapFunc
	capKey             string
	datacapRemain      uint64
	fwd                bool
	clientActorIdent   string
	sessionKey         []byte
	sessionKeyEncoding SessionKeyEncoding
}

type Constraints struct {
	Bw              bool
	BwLimitBps      uint64
	DataCapId       string // empty for no datacap
	DataCapBytes    uint64
	DataCapAffinity netip.Addr // address of service actor
}

func NewVisaBuilder(netConfig uint64, sourceTether, destTether netip.Addr) *VisaBuilder {
	return &VisaBuilder{
		netConfig:    netConfig,
		sourceTether: sourceTether,
		destTether:   destTether,
		fwd:          true,
	}
}

func (b *VisaBuilder) Visa() (*vsapi.Visa, error) {
	if b.visaID == 0 {
		return nil, fmt.Errorf("visa ID not set")
	}
	if !b.sourceTether.IsValid() {
		return nil, fmt.Errorf("source tether not set")
	}
	if !b.destTether.IsValid() {
		return nil, fmt.Errorf("dest tether not set")
	}
	if b.traffic == nil {
		return nil, fmt.Errorf("traffic not set")
	}
	if len(b.policies) == 0 {
		return nil, fmt.Errorf("policies not set")
	}

	visaConfig, err := InitPEP(b.traffic, b.policies)
	if err != nil {
		return nil, err
	}

	cons := &Constraints{
		Bw:         visaConfig.BWLimit,
		BwLimitBps: visaConfig.BitsPerSecond,
	}
	if visaConfig.DataCap {
		capID := visaConfig.Cap.SvcID
		if visaConfig.Cap.CapGroup != "" {
			capID = visaConfig.Cap.CapGroup
		}
		capVal := fmt.Sprintf("%v/%v", visaConfig.Cap.CapBytes, visaConfig.Cap.CapPeriod.String())

		if b.clientActorIdent == "" {
			return nil, fmt.Errorf("client actor ident not set")
		}

		if b.dynamicDataCapCBFn != nil {
			b.capKey, b.datacapRemain, err = b.dynamicDataCapCBFn(b.fwd, visaConfig.Cap, b.clientActorIdent)
			if err != nil {
				return nil, fmt.Errorf("dynamic datacap callback failed: %w", err)
			}
		} else {
			b.capKey = fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%v_%v_%v_%v", b.fwd, b.clientActorIdent, capID, capVal))))
			b.datacapRemain = visaConfig.Cap.CapBytes
		}
		if b.datacapRemain == 0 {
			return nil, fmt.Errorf("no datacap bytes remaining")
		}
		cons.DataCapId = b.capKey
		cons.DataCapBytes = b.datacapRemain

		var capAffinity netip.Addr
		capAffinity = b.destTether
		if !b.fwd {
			capAffinity = b.sourceTether
		}
		cons.DataCapAffinity = capAffinity
	}
	visa := &vsapi.Visa{
		IssuerID:      b.visaID,
		Configuration: int64(b.netConfig),
		Expires:       VToTimestamp(b.expiration),
		Source:        b.sourceTether.AsSlice(),
		Dest:          b.destTether.AsSlice(),
		SourceContact: b.sourceContact.AsSlice(),
		DestContact:   b.destContact.AsSlice(),
	}
	switch visaConfig.DockPEP {
	case PEPDockTCP:
		visa.DockPep = vsapi.PEPIndex_TCP
		var pargs *PEPArgsTCP
		pargs = visaConfig.DockPEPArgs.(*PEPArgsTCP)
		vsapiArgs := &vsapi.PEPArgsTCPUDP{
			SourceContactAddr: pargs.SourceContactAddr,
			DestContactAddr:   pargs.DestContactAddr,
			SourcePort:        int32(pargs.SourcePort),
			DestPort:          int32(pargs.DestPort),
			Server:            pargs.Server,
			IcmpAllowed:       make([]int32, len(pargs.IcmpAllowed)),
		}
		for i, v := range pargs.IcmpAllowed {
			vsapiArgs.IcmpAllowed[i] = int32(v)
		}
		visa.TcpudpPepArgs_ = vsapiArgs
	case PEPDockUDP:
		visa.DockPep = vsapi.PEPIndex_UDP
		var pargs *PEPArgsUDP
		pargs = visaConfig.DockPEPArgs.(*PEPArgsUDP)
		vsapiArgs := &vsapi.PEPArgsTCPUDP{
			SourceContactAddr: pargs.SourceContactAddr,
			DestContactAddr:   pargs.DestContactAddr,
			SourcePort:        int32(pargs.SourcePort),
			DestPort:          int32(pargs.DestPort),
			Server:            pargs.DestPortMode == 0,
			IcmpAllowed:       make([]int32, len(pargs.IcmpAllowed)),
		}
		for i, v := range pargs.IcmpAllowed {
			vsapiArgs.IcmpAllowed[i] = int32(v)
		}
		visa.TcpudpPepArgs_ = vsapiArgs
	case PEPDockICMP:
		visa.DockPep = vsapi.PEPIndex_ICMP
		var pargs *PEPArgsICMP
		pargs = visaConfig.DockPEPArgs.(*PEPArgsICMP)
		vsapiArgs := &vsapi.PEPArgsICMP{
			SourceContactAddr: pargs.SourceContactAddr,
			DestContactAddr:   pargs.DestContactAddr,
			IcmpTypeCode:      int32(pargs.IcmpTypeCode),
			IcmpAntecedent:    int32(pargs.IcmpAntecedent),
			StateTimeoutMs:    int32(pargs.StateTimeoutMs),
			OneShot:           pargs.OneShot,
		}
		visa.IcmpPepArgs_ = vsapiArgs
	default:
		panic(fmt.Sprintf("unknown dock pep: %v", visaConfig.DockPEP))
	}
	visa.Cons = &vsapi.Constraints{
		Bw:                  cons.Bw,
		BwLimitBps:          int64(cons.BwLimitBps),
		DataCapID:           cons.DataCapId,
		DataCapBytes:        int64(cons.DataCapBytes),
		DataCapAffinityAddr: cons.DataCapAffinity.AsSlice(),
	}
	switch b.sessionKeyEncoding {
	case SKEv1:
		ingressKey, egressKey, err := EncodeKeysFormat1(b.sessionKey)
		if err != nil {
			return nil, fmt.Errorf("encode keys failed: %w", err)
		}
		visa.SessionKey = &vsapi.KeySet{
			Format:     int32(1),
			IngressKey: ingressKey,
			EgressKey:  egressKey,
		}
	default:
		return nil, fmt.Errorf("unknown session key encoding: %v", b.sessionKeyEncoding)
	}

	// TODO: Signature
	visa.Sig = &vsapi.Signature{
		Type:      int32(0),
		Signature: []byte{0},
	}

	return visa, nil
}

func (b *VisaBuilder) WithExpiration(t time.Time) *VisaBuilder {
	b.expiration = t
	return b
}

func (b *VisaBuilder) WithTrafficAndPolicy(pkt *snip.Traffic, pol []*policy.MatchedPolicy) *VisaBuilder {
	b.sourceContact = pkt.SrcAddr
	b.destContact = pkt.DstAddr
	b.traffic = pkt
	b.policies = pol
	b.fwd = pol[0].FWD
	return b
}

// WithDatacapKeyAndRemain sets the datacap key and remaining bytes for use when you need to
// consult a database or something to figure that out. On its own, the build will set a
// datacap to its maximum value if one is specified in policy.
func (b *VisaBuilder) WithDatacapComputeFunc(callback DataCapFunc) *VisaBuilder {
	b.dynamicDataCapCBFn = callback
	return b
}

// WithClientActorIdent sets the client actor identifier. In a forward match, the client actor is the
// source actor, otherwise it is the destination actor.
//
// Required if a DataCap is used.
func (b *VisaBuilder) WithClientActorIdent(ident string) *VisaBuilder {
	b.clientActorIdent = ident
	return b
}

func (b *VisaBuilder) WithSessionKeyAndEncoding(key []byte, ske SessionKeyEncoding) *VisaBuilder {
	b.sessionKey = key
	b.sessionKeyEncoding = ske
	return b
}

func (b *VisaBuilder) WithIssuerID(id int32) *VisaBuilder {
	b.visaID = id
	return b
}
