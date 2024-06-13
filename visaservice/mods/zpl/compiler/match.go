package compiler

import (
	"fmt"
	"sort"
	"strings"

	"golang.org/x/exp/slices"

	"zpr.org/vsx/polio"
	"zpr.org/vsx/zpl/defs"
	"zpr.org/vsx/zpl/doc"
)

func (c *Compilation) genMatchRules(d *doc.Doc) error {
	if err := c.processPolicies(d); err != nil {
		return err
	}
	return nil
}

// assertScopesDistinct makes sure that scopes in `news` are distinct from any scopes in `exist`.
func assertScopesDistinct(news, exist []*doc.Scoping) error {
	for _, nscope := range news {
		if nscope.ICMP == nil && nscope.TCP.Value() == nil && nscope.UDP.Value() == nil {
			continue
		}
		for _, xscope := range exist {
			if xscope.TCP.Value() != nil && portsOverlap(xscope.TCP, nscope.TCP) {
				return doc.ZplScalarErrorf(nscope.TCP, "service on same host with overlapping scope: %v", nscope.String())
			}
			if xscope.UDP.Value() != nil && portsOverlap(xscope.UDP, nscope.UDP) {
				return doc.ZplScalarErrorf(nscope.UDP, "service on same host with overlapping scope: %v", nscope.String())
			}
			if xscope.ICMP != nil && nscope.ICMP != nil && portsOverlap(xscope.ICMP.TypeCodes, nscope.ICMP.TypeCodes) {
				return doc.ZplScalarErrorf(nscope.ICMP.TypeCodes, "service on same host with overlapping scope: %v", nscope.String())
			}
		}
	}
	return nil
}

func portsOverlap(a, b doc.ZplString) bool {
	aports, _ := explodePorts(a.String())
	bports, _ := explodePorts(b.String())
	for _, portNum := range bports {
		for _, apn := range aports {
			if portNum == apn {
				return true
			}
		}
	}
	return false
}

func getAllScopes(comp *doc.Component, svcIndx map[string]*doc.Scoping) []*doc.Scoping {
	var scopes []*doc.Scoping
	for _, sname := range comp.Services {
		if sco, ok := svcIndx[sname]; ok {
			scopes = append(scopes, sco)
		}
	}
	return scopes
}

// getSubScipes given a list of "subset" services in `subset`, ensure that each of
// the services is present in `superset`, and if so, look the services up in the
// index and then return the scopings.
func getSubScopes(subset, superset []string, svcIndx map[string]*doc.Scoping) ([]*doc.Scoping, error) {
	var scopes []*doc.Scoping
	for _, subs := range subset {
		allow := false
		for _, super := range superset {
			if subs == super {
				allow = true
				break
			}
		}
		if !allow {
			return nil, fmt.Errorf("service %v not allowed by parent", subs)
		}
		if scoping, ok := svcIndx[subs]; !ok {
			return nil, fmt.Errorf("unknown service: %v", subs)
		} else {
			scopes = append(scopes, scoping)
		}
	}
	return scopes, nil
}

// keyFromComponentAddresses create a string key value from the address or address_set
// present on the passed component. If no address is set, returns empty string.
func keyFromComponentAddresses(c *doc.Component) string {
	if !c.Address.Empty() {
		return c.Address.AsString()
	}
	if len(c.AddressSet) > 0 {
		var addrs []string
		for _, a := range c.AddressSet {
			addrs = append(addrs, a.AsString())
		}
		slices.Sort(addrs)
		return strings.Join(addrs, "_")
	}
	return ""
}

func (c *Compilation) processPolicies(d *doc.Doc) error {
	pcount := 0

	var pending []*SysPath
	var nxt *SysPath
	for _, roots := range d.Communications.Systems {
		pending = append(pending, &SysPath{roots, fmt.Sprintf("/%v", roots.GetID())})
	}

	// Keep track of providers so we can check for scope overlap.
	providerIdx := make(map[string][]*doc.Scoping)

	for len(pending) > 0 {
		nxt, pending = pending[0], pending[1:]
		for _, child := range nxt.sys.Systems {
			pending = append(pending, &SysPath{child, fmt.Sprintf("%v/%v", nxt.path, child.GetID())})
		}
		for _, comp := range nxt.sys.Components {
			sID := fmt.Sprintf("%v/%v", nxt.path, comp.GetProvides())
			compScopes := getAllScopes(comp, d.Services) // use service names to get the scopes
			pscount := 0
			if ckey := keyFromComponentAddresses(comp); ckey != "" {
				if scopes, ok := providerIdx[ckey]; ok {
					if err := assertScopesDistinct(compScopes, scopes); err != nil {
						return err
					}
					providerIdx[ckey] = append(scopes, compScopes...)
				} else {
					providerIdx[ckey] = compScopes
				}
			}
			// Used to be that a policy could override scope. Now all policies
			// on a component have the same scope.

			// By default a policy inherits all scopes of its parent component.
			// But, if a policy has a services attribute, then it just gets the
			// subset scopes from that.

			parentScope, err := docScopeToPolicyScope(compScopes)
			if err != nil {
				return err
			}
			for _, pp := range comp.Policies {
				pscope := parentScope // the default
				if len(pp.Services) > 0 {
					pscopes, err := getSubScopes(pp.Services, comp.Services, d.Services)
					if err != nil {
						return err
					}
					pscope, err = docScopeToPolicyScope(pscopes) // or use this
					if err != nil {
						return err
					}
				}
				cp := &polio.CPolicy{
					ServiceId: sID,
					Id:        pp.GetID(),
					Scope:     pscope,
				}
				if cond, err := c.conditionsFor(pp); err != nil {
					return err
				} else {
					cp.Conditions = cond
				}
				if cons, err := c.constraintsFor(pp); err != nil {
					return err
				} else {
					cp.Constraints = cons
				}
				c.policy.Policies = append(c.policy.Policies, cp)
				pcount++
				pscount++
			}
			c.infof("%v (%d policies)", sID, pscount)
		}
	}
	// Order communications policies by (service ID, policy ID)
	sort.Slice(c.policy.Policies, func(i, j int) bool {
		diff := strings.Compare(c.policy.Policies[i].GetServiceId(), c.policy.Policies[j].GetServiceId())
		if diff == 0 {
			diff = strings.Compare(c.policy.Policies[i].GetId(), c.policy.Policies[j].GetId())
		}
		return diff < 0
	})
	c.infof("added %d communications policies", pcount)
	return nil
}

// docScopeToPolicyScope convert a doc scoping struct to a policy protocol buf
// scope struct.
func docScopeToPolicyScope(ds []*doc.Scoping) ([]*polio.Scope, error) {
	var scopes []*polio.Scope
	for _, s := range ds {
		if s.ICMP != nil {
			specs, err := portTypeToPortSpec(s.ICMP.TypeCodes.String())
			if err != nil {
				return nil, doc.ZplScalarErrorf(s.ICMP.TypeCodes, "%w", err)
			}
			typecodes := specsToTypecodes(specs)
			var itype polio.ICMPT
			switch s.ICMP.Type.String() {
			case doc.ICMPReqRep:
				itype = polio.ICMPT_ICMPT_REQREP
				// In this case we expect a pair of typecodes.
				if len(typecodes) != 2 {
					return nil, doc.ZplScalarErrorf(s.ICMP.TypeCodes, "icmp req-rep type requires a pair of ports")
				}
			case doc.ICMPOnce:
				// Allows any number of typecodes.
				itype = polio.ICMPT_ICMPT_ONCE
			default:
				return nil, doc.ZplScalarErrorf(s.ICMP.Type, "illegal ICMP type: %v", s.ICMP.Type)
			}
			scope := &polio.Scope{
				Protocol: uint32(defs.ProtocolICMP6),
				Protarg: &polio.Scope_Icmp{
					Icmp: &polio.ICMP{
						Type:  itype,
						Codes: typecodes,
					},
				},
			}
			scopes = append(scopes, scope)
		}
		if s.TCP.Value() != nil {
			specs, err := portTypeToPortSpec(s.TCP.String())
			if err != nil {
				return nil, doc.ZplScalarErrorf(s.TCP, "%w", err)
			}
			scope := &polio.Scope{
				Protocol: uint32(defs.ProtocolTCP),
				Protarg: &polio.Scope_Pspec{
					Pspec: &polio.PortSpecList{
						Spec: specs,
					},
				},
			}
			scopes = append(scopes, scope)
		}
		if s.UDP.Value() != nil {
			specs, err := portTypeToPortSpec(s.UDP.String())
			if err != nil {
				return nil, doc.ZplScalarErrorf(s.UDP, "%w", err)
			}
			scope := &polio.Scope{
				Protocol: uint32(defs.ProtocolUDP),
				Protarg: &polio.Scope_Pspec{
					Pspec: &polio.PortSpecList{
						Spec: specs,
					},
				},
			}
			scopes = append(scopes, scope)
		}
	}
	return scopes, nil
}

func (c *Compilation) conditionsFor(pp *doc.Policy) ([]*polio.Condition, error) {
	var conds []*polio.Condition
	for _, cond := range pp.Conditions {
		pc := &polio.Condition{}
		pc.Id = cond.GetID()
		for _, attrExpr := range cond.AttrExprs {
			attrKey := attrExpr.Key.String()
			attrOp := attrExpr.Op.String()
			attrVal := attrExpr.Value.String()
			pattr := &polio.AttrExpr{}
			if kidx, ok := c.lookupAttrKey(attrKey); !ok {
				pattr.Key = c.insertAttrKey(attrKey)
			} else {
				pattr.Key = kidx
			}
			if opCode, err := attrOpCode(attrOp); err != nil {
				return nil, doc.ZplScalarErrorf(attrExpr.Op, "%w", err)
			} else {
				pattr.Op = opCode
			}
			if vidx, ok := c.lookupAttrValue(attrVal); !ok {
				pattr.Val = c.insertAttrValue(attrVal)
			} else {
				pattr.Val = vidx
			}
			pc.AttrExprs = append(pc.AttrExprs, pattr)
		}
		conds = append(conds, pc)
	}
	return conds, nil
}

func (c *Compilation) constraintsFor(pp *doc.Policy) ([]*polio.Constraint, error) {
	if pp.Constraints == nil {
		return nil, nil
	}
	var cons []*polio.Constraint
	if pp.Constraints.Bandwidth.Value() != nil {
		bwval, gtag, err := c.splitGroup(pp.Constraints.Bandwidth.String())
		if err != nil {
			return nil, doc.ZplScalarErrorf(pp.Constraints.Bandwidth, "constraint.bandwidth parse error: %w", err)
		}
		if gtag != "" {
			return nil, doc.ZplScalarErrorf(pp.Constraints.Bandwidth, "constraint.bandwidth does not support grouping (%v)", gtag)
		}
		floatBitsPerSec, err := doc.ParseBandwidthType(bwval)
		if err != nil {
			return nil, doc.ZplScalarErrorf(pp.Constraints.Bandwidth, "constraint.bandwidth parse error: %w", err)
		}
		intBitsPerSec, err := uint64FromFloat64(floatBitsPerSec)
		if err != nil {
			return nil, doc.ZplScalarErrorf(pp.Constraints.Bandwidth, "constraint.bandwidth value error: %w", err)
		}
		cons = append(cons, &polio.Constraint{
			Carg: &polio.Constraint_Bw{
				Bw: &polio.BWConstraint{
					BitsPerSec: intBitsPerSec,
				},
			},
		})
	}
	if pp.Constraints.Duration.Value() != nil {
		dval, gtag, err := c.splitGroup(pp.Constraints.Duration.String())
		if err != nil {
			return nil, doc.ZplScalarErrorf(pp.Constraints.Duration, "constraint.duration parse error: %w", err)
		}
		if gtag != "" {
			return nil, doc.ZplScalarErrorf(pp.Constraints.Duration, "constraint.duration does not support grouping (%v)", gtag)
		}
		floatSec, err := doc.ParseDurationType(dval)
		if err != nil {
			return nil, doc.ZplScalarErrorf(pp.Constraints.Duration, "constraint.duration parse error: %w", err)
		}
		intSec, err := uint64FromFloat64(floatSec)
		if err != nil {
			return nil, doc.ZplScalarErrorf(pp.Constraints.Duration, "constraint.duration value error: %w", err)
		}
		cons = append(cons, &polio.Constraint{
			Carg: &polio.Constraint_Dur{
				Dur: &polio.DurConstraint{
					Seconds: intSec,
				},
			},
		})
	}
	if pp.Constraints.AgentLimit.Value() != nil {
		lval, gtag, err := c.splitGroup(pp.Constraints.AgentLimit.String())
		if err != nil {
			return nil, doc.ZplScalarErrorf(pp.Constraints.AgentLimit, "constraint.agent_limit parse error: %w", err)
		}
		floatBits, floatSec, err := doc.ParseCapacityType(lval)
		if err != nil {
			return nil, doc.ZplScalarErrorf(pp.Constraints.AgentLimit, "constraint.agent_limit parse error: %w", err)
		}
		intBits, err := uint64FromFloat64(floatBits)
		if err != nil {
			return nil, doc.ZplScalarErrorf(pp.Constraints.AgentLimit, "constraint.agent_limit bit count value error: %w", err)
		}
		intSec, err := uint64FromFloat64(floatSec)
		if err != nil {
			return nil, doc.ZplScalarErrorf(pp.Constraints.AgentLimit, "constraint.agent_limit period value error: %w", err)
		}
		cons = append(cons, &polio.Constraint{
			Carg: &polio.Constraint_Cap{
				Cap: &polio.DataCapConstraint{
					CapBytes:      intBits / 8,
					PeriodSeconds: intSec,
				},
			},
			Group: gtag,
		})
	}
	return cons, nil
}

func uint64FromFloat64(f float64) (uint64, error) {
	if f < 0 || f > float64(^uint64(0)) {
		return 0, fmt.Errorf("cannot represent as an unsigned 64-bit integer: %v\n", f)
	} else {
		return uint64(f), nil
	}
}

// splitGroup extracts the group-tag from the constraint string. Also checks that the group tag (if present)
// has not been previously applied to some other constraint.
func (c *Compilation) splitGroup(consval string) (stripped string, group string, err error) {
	stripped = consval // assume no group
	i := strings.IndexRune(consval, '@')
	if i < 0 {
		return
	}
	if i == 0 {
		err = fmt.Errorf("group tag without a preceeding value")
		return
	}
	if len(consval) <= i+1 {
		err = fmt.Errorf("empty tag value")
		return
	}
	group = strings.TrimSpace(consval[i+1:])
	if len(group) == 0 {
		err = fmt.Errorf("empty tag value")
		return
	}
	if strings.IndexRune(group, ' ') > 0 {
		err = fmt.Errorf("tag must not contain spaces: '%v'", group)
	}
	stripped = strings.TrimSpace(consval[0:i])
	// Assert: a tag can only be applied to one constraint value.
	if existing, ok := c.groups[group]; ok {
		if existing != stripped {
			err = fmt.Errorf("tag %v previousl applied to '%v' cannot be re-applied to '%v'", group, existing, stripped)
			return
		}
	} else {
		c.groups[group] = stripped
	}
	return
}

func portTypeToPortSpec(pt string) ([]*polio.PortSpec, error) {
	var specs []*polio.PortSpec
	for _, ps := range strings.Split(pt, ",") {
		if strings.Index(ps, "-") > 0 {
			abs := strings.Split(ps, "-")
			if len(abs) != 2 {
				return nil, fmt.Errorf("expected port range 'N-M' not: '%v'", ps)
			}
			low, err := portFromString(abs[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port range: '%v': %v", ps, err)
			}
			high, err := portFromString(abs[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port range: '%v': %v", ps, err)
			}
			if low >= high {
				return nil, fmt.Errorf("invalid port range: '%v': %v", ps, err)
			}
			pr := &polio.PortRange{
				Low:  uint32(low),
				High: uint32(high),
			}
			specs = append(specs, &polio.PortSpec{
				Parg: &polio.PortSpec_Pr{pr},
			})
		} else {
			p, err := portFromString(ps)
			if err != nil {
				return nil, err
			}
			specs = append(specs, &polio.PortSpec{
				Parg: &polio.PortSpec_Port{uint32(p)},
			})
		}
	}
	return specs, nil
}

// specsToTypecodes expands the PortSpecs into a list of port numbers.
// No checks for duplicates.
func specsToTypecodes(specs []*polio.PortSpec) []uint32 {
	var tcodes []uint32
	for _, spec := range specs {
		switch s := spec.Parg.(type) {
		case *polio.PortSpec_Port:
			tcodes = append(tcodes, s.Port)
		case *polio.PortSpec_Pr:
			for pn := s.Pr.Low; pn <= s.Pr.High; pn++ {
				tcodes = append(tcodes, pn)
			}
		}
	}
	return tcodes
}
