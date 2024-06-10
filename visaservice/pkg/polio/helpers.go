package polio

import (
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	fmt "fmt"
	"net"
	"strconv"
	"strings"
	"time"

	snip "zpr.org/vs/pkg/ip"
)

// GetAuthEndpoint returns and "endponint" for this service.
func (svc *Service) GetAuthEndpoint() *snip.Endpoint {
	if _, p, err := net.SplitHostPort(svc.Addr); err == nil {
		if pn, err := strconv.Atoi(p); err == nil {
			return snip.NewEndpoint(AuthProtocol, uint16(pn))
		}
	}
	return nil
}

// GetMaxVisaLifetime get the visa lifetime setting from the policy, or return zero.
func (p *Policy) GetMaxVisaLifetime() time.Duration {
	for _, setting := range p.GetConfig() {
		if CFKey(setting.GetKey()) == CKMaxVisaLifetimeSeconds {
			if v := setting.GetU64V(); v > 0 {
				return time.Duration(v) * time.Second
			}
		}
	}
	return 0
}

// Given a condition from THIS policy `p`, return the condition in human readable form.
func (p *Policy) StringifyCondition(c *Condition) string {
	if len(c.AttrExprs) == 0 {
		return "[]"
	}
	var attrCount = 0
	var sb strings.Builder

	for _, exp := range c.AttrExprs {
		var kstr, valstr string
		if k, ok := lookup(p.AttrKeyIndex, int(exp.Key)); ok {
			kstr = k
		} else {
			kstr = fmt.Sprintf("<INVALID_%d>", exp.Key)
		}

		if v, ok := lookup(p.AttrValIndex, int(exp.Val)); ok {
			valstr = v
		} else {
			valstr = fmt.Sprintf("<INVALID_%d>", exp.Val)
		}
		if attrCount > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(fmt.Sprintf("[%v, %v, %v]", kstr, exp.Op.String(), valstr))
		attrCount++
	}

	return sb.String()
}

func (p *Policy) ExtractDefaultINTAuthority() string {
	var externs []string
	for _, svc := range p.GetServices() {
		if svc.GetType() == SvcT_SVCT_AUTH {
			externs = append(externs, svc.GetPrefix())
		}
	}

	var defaultInternalAuthority string
	for _, cert := range p.GetCertificates() {
		certPfx := cert.GetName()

		// Bit of a hack, but if this is not an extern prefix, it is an intern prefix.
		isExtern := false
		for i := range externs {
			if externs[i] == certPfx {
				isExtern = true
				break
			}
		}
		if !isExtern {
			if defaultInternalAuthority == "" {
				defaultInternalAuthority = certPfx
			} else {
				// Too many candidates.
				defaultInternalAuthority = ""
				break
			}
		}
	}
	return defaultInternalAuthority
}

// AuthServiceForPrefix return the auth service with the given prefix or nil.
func (p *Policy) AuthServiceForPrefix(pfx string) *Service {
	for _, s := range p.GetServices() {
		if s.GetType() == SvcT_SVCT_AUTH && s.GetPrefix() == pfx {
			return s
		}
	}
	return nil
}

func (p *Policy) ListCertificateIDs() []uint32 {
	var ids []uint32
	for _, c := range p.GetCertificates() {
		ids = append(ids, c.GetID())
	}
	return ids
}

func (p *Policy) GetCertificate(authID uint32) (*x509.Certificate, string, error) {
	for _, c := range p.GetCertificates() {
		if c.GetID() == authID {
			data, err := x509.ParseCertificate(c.GetAsn1Data())
			if err != nil {
				return nil, "", err
			}
			return data, c.GetName(), nil
		}
	}
	return nil, "", errors.New("certificate not found")
}

func (p *Policy) ServiceByName(name string) *Service {
	for _, s := range p.Services {
		if s.GetName() == name {
			return s
		}
	}
	return nil
}

// Hash creates a sha512 hash of this constraint.
func (c *Constraint) Hash() []byte {
	var scratch [8]byte
	hasher := sha512.New()
	switch cons := c.Carg.(type) {
	case *Constraint_Bw:
		hasher.Write([]byte("BW"))
		binary.BigEndian.PutUint64(scratch[0:], cons.Bw.BitsPerSec)
		hasher.Write(scratch[0:])
	case *Constraint_Cap:
		hasher.Write([]byte("CAP"))
		binary.BigEndian.PutUint64(scratch[0:], cons.Cap.CapBytes)
		hasher.Write(scratch[0:])
		binary.BigEndian.PutUint64(scratch[0:], cons.Cap.PeriodSeconds)
		hasher.Write(scratch[0:])
	case *Constraint_Dur:
		hasher.Write([]byte("DUR"))
		binary.BigEndian.PutUint64(scratch[0:], cons.Dur.Seconds)
		hasher.Write(scratch[0:])
	default:
		panic("constraint type handler missing")
	}
	if c.Group != "" {
		hasher.Write([]byte(c.Group))
	}
	return hasher.Sum(nil)
}

// HashHex returns hex encoded sha512 hash of this constraint.
func (c *Constraint) HashHex() string {
	return hex.EncodeToString(c.Hash())
}

func lookup(inlist []string, index int) (string, bool) {
	if index < 0 || index >= len(inlist) {
		return "", false
	}
	return inlist[index], true
}

// Return TRUE if the protocol/port is included the a scope attached to this CPolicy.
// For ICMP the port is a code value.
func (cp *CPolicy) HasScope(protocol, port int) bool {
	p32 := uint32(port)

	for _, scope := range cp.Scope {
		if scope.Protocol == uint32(protocol) {
			switch parg := scope.Protarg.(type) {
			case *Scope_Icmp:
				for _, icmpCode := range parg.Icmp.Codes {
					if icmpCode == p32 {
						return true
					}
				}

			case *Scope_Pspec:
				for _, spec := range parg.Pspec.Spec {
					switch specArg := spec.Parg.(type) {
					case *PortSpec_Port:
						if specArg.Port == p32 {
							return true
						}
					case *PortSpec_Pr:
						if p32 >= specArg.Pr.Low && p32 <= specArg.Pr.High {
							return true
						}
					}
				}
			}
		}
	}
	return false
}

// Helper to visualize the Scope value.
func (s *Scope) Stringify() string {
	var sb strings.Builder

	switch s.Protocol {
	case snip.ProtocolTCP.Num():
		sb.WriteString("TCP/")
	case snip.ProtocolUDP.Num():
		sb.WriteString("UDP/")
	case snip.ProtocolICMP6.Num():
		sb.WriteString("ICMP6/")
	default:
		sb.WriteString(fmt.Sprintf("?%d?/", s.Protocol))
	}

	switch parg := s.Protarg.(type) {
	case *Scope_Icmp:
		sb.WriteString(fmt.Sprintf("type %d, codes: %#v", parg.Icmp.Type, parg.Icmp.Codes))

	case *Scope_Pspec:
		for _, spec := range parg.Pspec.Spec {
			switch specArg := spec.Parg.(type) {
			case *PortSpec_Port:
				sb.WriteString(fmt.Sprintf("%d", specArg.Port))
			case *PortSpec_Pr:
				sb.WriteString(fmt.Sprintf("%d - %d", specArg.Pr.Low, specArg.Pr.High))
			}
		}
	}

	return sb.String()
}
