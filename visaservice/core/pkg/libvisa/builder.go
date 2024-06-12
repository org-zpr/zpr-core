package libvisa

import (
	"crypto/md5"
	"fmt"
	"net/netip"
	"time"

	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vsx/polio"

	"zpr.org/vs/pkg/snio/vsio"
)

type SessionKeyEncoding int

const (
	SKEv1 SessionKeyEncoding = iota // uses known, hardcoded secrets to encrypt the keys (basically proof of concept only!)
)

// DataCapFunc is used when you need to do extra work to get
// datacap constraint details.
// Arguments are (FWD, DataCap, clientAgentIdent) and returns (capKey, remainBytes, error)
type DataCapFunc func(bool, *DataCap, string) (string, uint64, error)

type VisaBuilder struct {
	visaID             uint32
	netConfig          uint64
	expiration         time.Time
	sourceTether       netip.Addr
	sourceContact      netip.Addr
	destTether         netip.Addr
	destContact        netip.Addr
	traffic            *snip.Traffic
	policies           []*polio.MatchedPolicy
	dynamicDataCapCBFn DataCapFunc
	capKey             string
	datacapRemain      uint64
	fwd                bool
	clientAgentIdent   string
	sessionKey         []byte
	sessionKeyEncoding SessionKeyEncoding
}

func NewVisaBuilder(netConfig uint64, sourceTether, destTether netip.Addr) *VisaBuilder {
	return &VisaBuilder{
		netConfig:    netConfig,
		sourceTether: sourceTether,
		destTether:   destTether,
		fwd:          true,
	}
}

func (b *VisaBuilder) Visa() (*vsio.Visa, error) {
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
	if b.policies == nil || len(b.policies) == 0 {
		return nil, fmt.Errorf("policies not set")
	}

	visaConfig, err := InitPEP(b.traffic, b.policies)
	if err != nil {
		return nil, err
	}

	cons := &vsio.Visa_Constraints{
		Bw:         visaConfig.BWLimit,
		BwLimitBps: visaConfig.BitsPerSecond,
	}
	if visaConfig.DataCap {
		capID := visaConfig.Cap.SvcID
		if visaConfig.Cap.CapGroup != "" {
			capID = visaConfig.Cap.CapGroup
		}
		capVal := fmt.Sprintf("%v/%v", visaConfig.Cap.CapBytes, visaConfig.Cap.CapPeriod.String())

		if b.clientAgentIdent == "" {
			return nil, fmt.Errorf("client agent ident not set")
		}

		if b.dynamicDataCapCBFn != nil {
			b.capKey, b.datacapRemain, err = b.dynamicDataCapCBFn(b.fwd, visaConfig.Cap, b.clientAgentIdent)
			if err != nil {
				return nil, fmt.Errorf("dynamic datacap callback failed: %w", err)
			}
		} else {
			b.capKey = fmt.Sprintf("%x", md5.Sum([]byte(fmt.Sprintf("%v_%v_%v_%v", b.fwd, b.clientAgentIdent, capID, capVal))))
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
		cons.DataCapAffinity = capAffinity.AsSlice()
	}

	visa := &vsio.Visa{
		IssuerId:      b.visaID,
		Configuration: b.netConfig,
		Expires:       vsio.VToTimestamp(b.expiration),
		Source:        b.sourceTether.AsSlice(),
		Dest:          b.destTether.AsSlice(),
		SourceContact: b.sourceContact.AsSlice(),
		DestContact:   b.destContact.AsSlice(),
		DockPep:       visaConfig.DockPEP,
		DockPepArgs:   visaConfig.DockPEPArgs,
		FwdPep:        visaConfig.FwdPEP, // TODO (probably needs args too)
		Cons:          cons,
		Sig:           nil, // TODO
	}

	switch b.sessionKeyEncoding {
	case SKEv1:
		if err := EncodeKeysFormat1(b.sessionKey, visa); err != nil {
			return nil, fmt.Errorf("encode keys failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown session key encoding: %v", b.sessionKeyEncoding)
	}

	return visa, nil
}

func (b *VisaBuilder) WithExpiration(t time.Time) *VisaBuilder {
	b.expiration = t
	return b
}

func (b *VisaBuilder) WithTrafficAndPolicy(pkt *snip.Traffic, pol []*polio.MatchedPolicy) *VisaBuilder {
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

// WithClientAgentIdent sets the client agent identifier. In a forward match, the client agent is the
// source agent, otherwise it is the destination agent.
//
// Required if a DataCap is used.
func (b *VisaBuilder) WithClientAgentIdent(ident string) *VisaBuilder {
	b.clientAgentIdent = ident
	return b
}

func (b *VisaBuilder) WithSessionKeyAndEncoding(key []byte, ske SessionKeyEncoding) *VisaBuilder {
	b.sessionKey = key
	b.sessionKeyEncoding = ske
	return b
}

func (b *VisaBuilder) WithIssuerID(id uint32) *VisaBuilder {
	b.visaID = id
	return b
}
