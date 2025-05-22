package policy

import (
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	fmt "fmt"
	"strings"
	"time"

	"zpr.org/vsx/polio"
)

// GetMaxVisaLifetime get the visa lifetime setting from the policy, or return zero.
func GetMaxVisaLifetime(p *polio.Policy) time.Duration {
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
func StringifyCondition(p *polio.Policy, c *polio.Condition) string {
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

func ExtractDefaultINTAuthority(p *polio.Policy) string {
	var externs []string
	for _, svc := range p.GetServices() {
		if svc.GetType() == polio.SvcT_SVCT_AUTH {
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
func AuthServiceForPrefix(p *polio.Policy, pfx string) *polio.Service {
	for _, s := range p.GetServices() {
		if s.GetType() == polio.SvcT_SVCT_AUTH && s.GetPrefix() == pfx {
			return s
		}
	}
	return nil
}

func ListCertificateIDs(p *polio.Policy) []uint32 {
	var ids []uint32
	for _, c := range p.GetCertificates() {
		ids = append(ids, c.GetID())
	}
	return ids
}

func GetCertificate(p *polio.Policy, authID uint32) (*x509.Certificate, string, error) {
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

func ServiceByName(p *polio.Policy, name string) *polio.Service {
	for _, s := range p.Services {
		if s.GetName() == name {
			return s
		}
	}
	return nil
}

// Hash creates a sha512 hash of this constraint.
func Hash(c *polio.Constraint) []byte {
	var scratch [8]byte
	hasher := sha512.New()
	switch cons := c.Carg.(type) {
	case *polio.Constraint_Bw:
		hasher.Write([]byte("BW"))
		binary.BigEndian.PutUint64(scratch[0:], cons.Bw.BitsPerSec)
		hasher.Write(scratch[0:])
	case *polio.Constraint_Cap:
		hasher.Write([]byte("CAP"))
		binary.BigEndian.PutUint64(scratch[0:], cons.Cap.CapBytes)
		hasher.Write(scratch[0:])
		binary.BigEndian.PutUint64(scratch[0:], cons.Cap.PeriodSeconds)
		hasher.Write(scratch[0:])
	case *polio.Constraint_Dur:
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
func HashHex(c *polio.Constraint) string {
	return hex.EncodeToString(Hash(c))
}

func lookup(inlist []string, index int) (string, bool) {
	if index < 0 || index >= len(inlist) {
		return "", false
	}
	return inlist[index], true
}

// Return TRUE if the protocol/port is included the a scope attached to this CPolicy.
// For ICMP the port is a code value.
func HasScope(cp *polio.CPolicy, protocol, port int) bool {
	p32 := uint32(port)

	for _, scope := range cp.Scope {
		if scope.Protocol == uint32(protocol) {
			switch parg := scope.Protarg.(type) {
			case *polio.Scope_Icmp:
				for _, icmpCode := range parg.Icmp.Codes {
					if icmpCode == p32 {
						return true
					}
				}

			case *polio.Scope_Pspec:
				for _, spec := range parg.Pspec.Spec {
					switch specArg := spec.Parg.(type) {
					case *polio.PortSpec_Port:
						if specArg.Port == p32 {
							return true
						}
					case *polio.PortSpec_Pr:
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
