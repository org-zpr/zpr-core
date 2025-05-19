package compiler

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/exp/slices"

	"zpr.org/vsx/polio"
	"zpr.org/vsx/zpl/defs"
	"zpr.org/vsx/zpl/doc"
)

func (c *Compilation) genConnectRules(d *doc.Doc) error {
	sets, err := c.getConnectAttrExprSets(d)
	if err != nil {
		return err
	}
	if err := c.checkAttrExprPrefixes(d, sets); err != nil {
		return err
	}
	keytable, valtable := c.createAttrLookups(sets)
	var connects []*polio.Connect
	for _, set := range sets {
		var encodedAttrExprs []*polio.AttrExpr
		for _, ex := range set.AttrExprs {
			okey := ex.Key.String()
			if okey == defs.KAttrRole {
				continue // Do not use this synthetic attribute in a connect rule. (too hacky?)
			}
			oop := ex.Op.String()
			oval := ex.Value.String()
			if opCode, err := attrOpCode(oop); err != nil {
				return err
			} else {
				encodedAttrExprs = append(encodedAttrExprs, &polio.AttrExpr{
					Key: uint32(keytable[okey]),
					Op:  opCode,
					Val: uint32(valtable[oval]),
				})
			}
		}
		if len(encodedAttrExprs) == 0 {
			continue
		}
		connect := &polio.Connect{
			AttrExprs: encodedAttrExprs,
		}
		proc, err := c.newConnectProc(set)
		if err != nil {
			return err
		}
		if idx, found := c.findProc(proc); found {
			connect.Proc = idx
		} else {
			connect.Proc = addProc(proc, c.policy)
		}
		connects = append(connects, connect)
		c.debugf("(%d) can connect:", len(connects))
		for _, ex := range set.AttrExprs {
			c.debugf("    %v", ex.String())
		}
	}

	if !c.hasPMCTLAccess(sets) {
		// Who knows, maybe they just want to run a single policy at startup...
		c.warn("no policy allows access for PMCTL")
	}

	keyset := func() []string {
		ks := make([]string, len(keytable))
		for k, i := range keytable {
			ks[i] = k
		}
		return ks
	}()

	valset := func() []string {
		vs := make([]string, len(valtable))
		for v, i := range valtable {
			vs[i] = v
		}
		return vs
	}()

	c.policy.AttrKeyIndex = keyset
	c.policy.AttrValIndex = valset
	c.policy.Connects = connects
	c.infof("added %d connect rules, %d procs", len(connects), len(c.policy.Procs))

	// Reuse the attr-sets during communication policy:
	c.attrExprSets = sets
	return nil
}

// Returns the integer code corresponding to an attribute expression operator string.
func attrOpCode(op string) (polio.AttrOpT, error) {
	switch op {
	case doc.AttrExprOpEq:
		return polio.AttrOpT_EQ, nil
	case doc.AttrExprOpNe:
		return polio.AttrOpT_NE, nil
	case doc.AttrExprOpHas:
		return polio.AttrOpT_HAS, nil
	case doc.AttrExprOpExcludes:
		return polio.AttrOpT_EXCLUDES, nil
	default:
		return polio.AttrOpT_UNUSED, fmt.Errorf("unrecognized attribute expression operator: %q", op)
	}
}

func (c *Compilation) hasPMCTLAccess(sets []*AttrExprSet) bool {
	pmctlEP := fmt.Sprintf("TCP/%d", c.pmctlPort)
	for _, set := range sets {
		for _, p := range set.Provides {
			for _, ep := range p.Endpoints {
				if ep == pmctlEP {
					return true
				}
			}
		}
	}
	return false
}

func (c *Compilation) newConnectProc(as *AttrExprSet) (*polio.Proc, error) {

	var cline []*polio.Instruction

	for _, p := range as.Provides {
		var st polio.SvcT
		switch p.Type {
		case PSvcTAuth:
			st = polio.SvcT_SVCT_AUTH
		case PSvcTDecorator:
			st = polio.SvcT_SVCT_DECORATOR
		default:
			st = polio.SvcT_SVCT_DEF // maybe use node here instead of a flag?
		}

		// Ideally, we would add a proc to say ASSERT_ADDR(x) on the provider.

		eps := strings.Join(p.Endpoints, ",")
		cline = append(cline, registerService(p.Path, st, eps)) // register a service "path"

		if p.ServiceID == defs.VisaServiceName {
			cline = append(cline, setFlag(polio.FlagT_F_VISASERVICE))
		}
	}

	// Node needs a CIDR
	if as.Node {
		var np *PSvc
		for _, ps := range as.Provides {
			if ps.Type == PSvcTNode {
				np = ps
				break
			}
		}
		if np == nil {
			panic("node is set on AttrExprSet but no Node PSvc found")
		}
		cline = append(cline, setFlag(polio.FlagT_F_NODE))
		if as.VSDock {
			cline = append(cline, setFlag(polio.FlagT_F_VS_DOCK))
		}

		if netw := c.NextCIDR(); netw == nil {
			return nil, fmt.Errorf("no more CIDR space left for node")
		} else {
			cline = append(cline, setCIDR(netw.String()))
		}
	}

	return &polio.Proc{
		Proc: cline,
	}, nil
}

// getConnectAttrExprSets returns (sorted) list of attribute expression sets.
func (c *Compilation) getConnectAttrExprSets(d *doc.Doc) ([]*AttrExprSet, error) {
	var syslist []*doc.System
	for _, docsys := range d.Communications.Systems {
		syslist = append(syslist, docsys)
	}
	sets, err := c.getAttrExprSets(syslist)
	if err != nil {
		return nil, err
	}
	// At this point `sets` has all providers and regular policy conditions in it.

	providers := make(map[string]*AttrExprSet) // set hash -> set

	for _, set := range sets {
		set.GenerateID()
		if set.Provider {
			if ep, exist := providers[set.Hash]; exist {
				// Here is another AttrExprSet that matches an existing provider.
				if set.Node != ep.Node {
					// They both must be nodes or not.
					return nil, fmt.Errorf("duplicate provider attributes for node and non-node: A=%v | B=%v", set.Provides[0], ep.Provides[0])
				}
				ep.Provides = append(ep.Provides, set.Provides...)
			} else {
				providers[set.Hash] = set
			}
		}
	}

	c.warnIfAddrClaimRequired(sets)

	uniqueSets := make(map[string]*AttrExprSet)
	for _, set := range sets {
		if set.Provider {
			continue
		}
		// It's possible that a provider attribute set is also used as a policy condition. We only need to keep
		// the provider entry.
		if _, match := providers[set.Hash]; match {
			continue
		}
		uniqueSets[set.ID] = set
	}

	var results []*AttrExprSet
	for _, set := range providers {
		results = append(results, set)
	}
	for _, set := range uniqueSets {
		results = append(results, set)
	}

	// Canonical sorting:
	sort.Slice(results, func(i, j int) bool {
		cmp := strings.Compare(results[i].ID, results[j].ID)
		if cmp == 0 {
			cmp = strings.Compare(results[i].Hash, results[j].Hash)
		}
		return cmp < 0
	})

	return results, nil
}

// warnIfAddrClaimRequired checks if the only difference between attribute expressions
// is zpr.addr, that is a going to lead to confusion since zpr.addr is not a required
// attribute to cause a match. Test for that condition here and issue warning.
func (c *Compilation) warnIfAddrClaimRequired(sets []*AttrExprSet) {
	var pchecked []string
	for _, setA := range sets {
		if !setA.Provider {
			continue
		}
		for _, setB := range sets {
			if setB.Hash == setA.Hash {
				continue
			}
			if !setB.Provider {
				continue
			}
			if len(setA.AttrExprs) != len(setB.AttrExprs) {
				continue
			}
			pairing := []string{setA.GetProvides(), setB.GetProvides()}
			if slices.Index(pchecked, strings.Join(pairing, ",")) >= 0 {
				continue
			}

			addrMisMatch := false
			matched := 0
			for _, aExp := range setA.AttrExprs {
				for _, bExp := range setB.AttrExprs {
					// See if aExp is in setB
					if aExp.Equal(bExp) {
						// yes
						matched++
					}
					if aExp.Key.Value() == defs.KAttrEPID && bExp.Key.Value() == defs.KAttrEPID {
						// Found address key.
						addrMisMatch = aExp.Value.Value() != bExp.Value.Value()
					}
				}
			}
			if matched == (len(setA.AttrExprs)-1) && addrMisMatch {
				c.warnf("claim \"%v\" is required for actors to differentiate between %v and %v",
					defs.KAttrEPID, setA.GetProvides(), setB.GetProvides())
			}
			pchecked = append(pchecked, strings.Join(pairing, ","), fmt.Sprintf("%v,%v", pairing[1], pairing[0]))
		}
	}
}

// getAttrExprSets runs through the Systems and returns the "AttrExprSets" -- which is a summary of the attribute expressions
// used for each service and for each policy condition. This data is used to create a list of who can
// connect to the ZPR.  Clearly, to connect you must have potential of matching one of the attribute expression sets.
//
// This also checks that single-tenant rules are followed.
func (c *Compilation) getAttrExprSets(syslist []*doc.System) ([]*AttrExprSet, error) {
	var sets []*AttrExprSet
	var pending []*SysPath
	var nxt *SysPath

	singleTenantAddrs := make(map[string]string)
	addrsInUse := make(map[string][]string)

	decoratorSvcCount := 0
	defaultSvcCount := 0

	for _, sys := range syslist {
		pending = append(pending, &SysPath{sys, fmt.Sprintf("/%v", sys.GetID())})
	}

	for len(pending) > 0 {
		nxt, pending = pending[0], pending[1:]
		for chID, child := range nxt.sys.Systems {
			pending = append(pending, &SysPath{child, fmt.Sprintf("%v/%v", nxt.path, chID)})
		}

		for _, comp := range nxt.sys.Components {
			isVsDockingNode := false
			isVsAdapter := false
			sID := fmt.Sprintf("%v/%v", nxt.path, comp.GetProvides())
			var stype PSvcT
			if comp.Auth.String() != "" {
				stype = PSvcTAuth
			} else if comp.Decorator.AsBool() {
				stype = PSvcTDecorator
			} else {
				stype = PSvcTDef
			}
			if _, isNode := c.parsed.Zpr.Nodes[comp.GetProvides()]; isNode {
				stype = PSvcTNode
				if comp.GetProvides() == c.visaserviceDockingNode {
					isVsDockingNode = true
				}
			} else {
				isVsAdapter = comp.GetProvides() == defs.VisaServiceName
			}
			compSets, err := c.getAttrExprSetForComponent(sID, comp, stype, isVsDockingNode, isVsAdapter)
			if err != nil {
				return nil, err
			}

			switch stype {
			case PSvcTDef:
				// TODO: Should the visa service be a special type?
				if !strings.HasSuffix(sID, defs.VisaServiceName) {
					defaultSvcCount++
				}
			case PSvcTDecorator:
				decoratorSvcCount++
			}

			if !comp.Address.Empty() {
				if holder, inuse := singleTenantAddrs[comp.Address.AsString()]; inuse {
					return nil, fmt.Errorf("component %v using single-tenant address reserved by %v", comp.GetProvides(), holder)
				}

				// Even if not using a single-tenant address, a single-tenant component may
				// try to use it later, so we need to track that.
				if !comp.SingleTenant.AsBool() {
					addrsInUse[comp.Address.AsString()] = append(addrsInUse[comp.Address.AsString()], comp.GetProvides())
				}
			} else if len(comp.AddressSet) > 0 {
				// Has an address set. Preprocessor ensures that this type of component cannot
				// also be single-tenant.  So we just track these as in-use addresses.
				for _, a := range comp.AddressSet {
					if holder, inuse := singleTenantAddrs[a.AsString()]; inuse {
						return nil, fmt.Errorf("component %v using single-tenant address reserved by %v", comp.GetProvides(), holder)
					}
					addrsInUse[a.AsString()] = append(addrsInUse[a.AsString()], comp.GetProvides())
				}
			}

			if comp.SingleTenant.AsBool() {
				// Single-Tenant components must have unique addreses explicitly assigned.
				if comp.Address.Empty() {
					return nil, fmt.Errorf("single-tenant component %v requires an address", comp.GetProvides())
				}
				if users := addrsInUse[comp.Address.AsString()]; len(users) > 0 {
					return nil, fmt.Errorf("address for single-tenant component %v re-used by %v", comp.GetProvides(),
						strings.Join(users, ", "))
				}
				singleTenantAddrs[comp.Address.AsString()] = comp.GetProvides()
			}

			sets = append(sets, compSets...)
		}
	}

	if defaultSvcCount == 0 && decoratorSvcCount > 0 {
		return nil, fmt.Errorf("invalid policy: only decorator type services")
	}

	return sets, nil
}

// getAttrExprSetForComponent return the attribute expressions used in the
// provider and condition blocks.
func (c *Compilation) getAttrExprSetForComponent(sID string, comp *doc.Component, stype PSvcT, isVSDockingNode, isVSAdapter bool) ([]*AttrExprSet, error) {
	var sets []*AttrExprSet
	pname := comp.GetProvides()
	if pname == "" {
		return nil, doc.ZplScalarErrorf(comp.ZplRef, "unable to determine provides name for service '%v'", sID)
	}
	eps, err := c.getServiceEndpoints(comp)
	if err != nil {
		return nil, doc.ZplScalarErrorf(comp.ZplRef, "scope parsing failed for service %v: %w", sID, err)
	}
	pset := &AttrExprSet{
		Provider: true,
		Provides: []*PSvc{
			&PSvc{
				Path:      sID,
				ServiceID: comp.GetProvides(),
				Type:      stype,
				Endpoints: eps,
			},
		},
		Node: stype == PSvcTNode,
	}
	pset.VSDock = pset.Node && isVSDockingNode
	pset.VSInst = (!pset.Node) && isVSAdapter

	// If the server has an explicit address we will set that as the zpr.addr attribute.
	// Note that the preprocessor has already done the reverse (setting the address from zpr.addr).
	var svcEPID netip.Addr
	epidSet := false
	if !comp.Address.Empty() {
		svcaddr, err := c.resolve(comp.Address.String())
		if err != nil {
			return nil, doc.ZplScalarErrorf(comp.Address, "service error on %v: %w", comp.GetID(), err)
		}
		svcEPID, err = netip.ParseAddr(svcaddr)
		if err != nil {
			return nil, doc.ZplScalarErrorf(comp.Address, "failed to convert service address to ZPRID: %v: %v", sID, err)
		}
	}
	for _, attrExpr := range comp.Provider {
		if attrExpr.Key.AsString() == defs.KAttrEPID {
			epidSet = true // EPID is set already
			if attrExpr.Op.String() == doc.AttrExprOpEq {
				// Preprocessor should catch this.
				if ipa, err := netip.ParseAddr(attrExpr.Value.String()); err != nil {
					return nil, doc.ZplScalarErrorf(attrExpr.Value, "service %v with invalid zpr.addr: %v (%v)", sID, attrExpr.Value, err)
				} else {
					// Warn if the zpr.addr is different from the svcEPID.
					if !(svcEPID == ipa) {
						c.warnf("service %s zpr.addr (%v) differs from service address (%v)", sID, ipa, svcEPID)
					}
				}
			}
		}
		pset.AttrExprs = append(pset.AttrExprs, attrExpr)
	}
	if !epidSet {
		if !(svcEPID == netip.Addr{}) {
			key, _ := doc.NewZplString(defs.KAttrEPID)
			op, _ := doc.NewZplString(doc.AttrExprOpEq)
			val, _ := doc.NewZplString(svcEPID.String())
			pset.AttrExprs = append(pset.AttrExprs, &doc.AttrExpr{nil, key, op, val})
		} else if len(comp.AddressSet) > 0 {
			// We do not have a single address, use the HAS operator to allow one of the set of addresses.

			var resolved []string
			for _, a := range comp.AddressSet {
				if addr, err := c.resolve(a.String()); err != nil {
					return nil, doc.ZplScalarErrorf(a, "service error on %v: %w", comp.GetID(), err)
				} else {
					resolved = append(resolved, addr)
				}
			}
			pset.AttrExprs = append(pset.AttrExprs, &doc.AttrExpr{
				ZplRef: nil,
				Key:    doc.MustNewZplString(defs.KAttrEPID),
				Op:     doc.MustNewZplString(doc.AttrExprOpHas),
				Value:  doc.MustNewZplString(strings.Join(resolved, ",")),
			})
		}
	}
	// Before appending, ensure that the provides array is in an order.
	sort.Slice(pset.Provides, func(i, j int) bool {
		return strings.Compare(pset.Provides[i].Path, pset.Provides[j].Path) < 0
	})

	sets = append(sets, pset)

	for _, pol := range comp.Policies {
		for _, cond := range pol.Conditions {
			as := &AttrExprSet{}
			for _, attrExpr := range cond.AttrExprs {
				if attrExpr.Key.String() == defs.KAttrConnectVia && attrExpr.Op.String() == doc.AttrExprOpEq {
					addr, err := c.resolve(attrExpr.Value.String())
					if err != nil {
						return nil, err
					}
					addrz, _ := doc.NewZplString(addr)
					as.AttrExprs = append(as.AttrExprs, &doc.AttrExpr{attrExpr.ZplRef, attrExpr.Key, attrExpr.Op, addrz})
				} else {
					as.AttrExprs = append(as.AttrExprs, attrExpr)
				}
			}
			sets = append(sets, as)
		}
	}

	return sets, nil
}

// getServiceEndpints examines all scope within the component and comes up with an endpoint list.
//
// TODO: I don't see why the connect policy needs to know what the endpoints are.
//
//	So hopefully this can go away.
//	Endpoints are only used in visa policy to match traffic.
func (c *Compilation) getServiceEndpoints(comp *doc.Component) ([]string, error) {

	xscopes := make(map[uint8][]uint16) // protocol -> port numbers

	for _, sname := range comp.Services {
		if ds, ok := c.parsed.Services[sname]; !ok {
			return nil, fmt.Errorf("unknown service '%v' found in component '%v'", sname, comp.ID.String())
		} else if err := explodeScope([]*doc.Scoping{ds}, xscopes); err != nil {
			return nil, err
		}
	}

	endpoints := make(map[string]bool)
	for prot, portlist := range xscopes {
		for _, pnum := range portlist {
			eps := fmt.Sprintf("%v/%d", protocolNumberToName(prot), pnum)
			if _, match := endpoints[eps]; !match {
				endpoints[eps] = true
			}
		}
	}

	var eplist []string
	for k := range endpoints {
		eplist = append(eplist, k)
	}
	return eplist, nil
}

// TODO: What about addresses? Don't we need to assign address ??  Service connect with an address (EPID)
//
//	so that can be used as part of connect policy.
func explodeScope(s []*doc.Scoping, ploded map[uint8][]uint16) error {
	var err error
	for _, scope := range s {
		var proto uint8
		var ports []uint16
		if scope.TCP.Value() != nil {
			proto = defs.ProtocolTCP
			ports, err = explodePorts(scope.TCP.String(), doc.RangeTcpUdp)
			if err != nil {
				return doc.ZplScalarErrorf(scope.TCP, "%w", err)
			}
		}
		if scope.UDP.Value() != nil {
			proto = defs.ProtocolUDP
			ports, err = explodePorts(scope.UDP.String(), doc.RangeTcpUdp)
			if err != nil {
				return doc.ZplScalarErrorf(scope.UDP, "%w", err)
			}
		}
		if scope.ICMP != nil {
			proto = defs.ProtocolICMP6
			ports, err = explodePorts(scope.ICMP.TypeCodes.String(), doc.RangeICMP) // Not sure about this
		}

		if proto > 0 {
			if ent, exist := ploded[proto]; exist {
				for _, p := range ports {
					present := false
					for _, xp := range ent {
						if p == xp {
							present = true
							break
						}
					}
					if !present {
						ploded[proto] = append(ploded[proto], p)
					}
				}
			} else {
				ploded[proto] = ports
			}
		}
	}

	return nil
}

// explodePorts given a ports string, returns the list of (unique) ports described.
func explodePorts(portstr string, pr doc.PortRange) ([]uint16, error) {
	uniqports := make(map[uint16]bool)
	for _, ps := range strings.Split(portstr, ",") {
		if strings.Index(ps, "-") > 0 {
			abs := strings.Split(ps, "-")
			if len(abs) != 2 {
				return nil, fmt.Errorf("expected port range 'N-M' not: '%v'", ps)
			}
			low, err := portFromString(abs[0], pr)
			if err != nil {
				return nil, fmt.Errorf("invalid port range: '%v': %v", ps, err)
			}
			high, err := portFromString(abs[1], pr)
			if err != nil {
				return nil, fmt.Errorf("invalid port range: '%v': %v", ps, err)
			}
			if low >= high {
				return nil, fmt.Errorf("invalid port range: '%v': %v", ps, err)
			}
			for i := low; i <= high; i++ {
				uniqports[i] = true
			}
		} else {
			p, err := portFromString(ps, pr)
			if err != nil {
				return nil, err
			}
			uniqports[p] = true
		}
	}
	var ports []uint16
	for p := range uniqports {
		ports = append(ports, p)
	}
	return ports, nil
}

func portFromString(s string, pr doc.PortRange) (uint16, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid port-spec value '%v': %v", s, err)
	}
	if p <= pr.Min || p > pr.Max {
		return 0, fmt.Errorf("invalid port-spec value: '%v': %v", p, err)
	}
	return uint16(p), nil
}

func protocolNumberToName(p uint8) string {
	switch p {
	case defs.ProtocolICMP6:
		return "ICMP6"
	case defs.ProtocolTCP:
		return "TCP"
	case defs.ProtocolUDP:
		return "UDP"
	default:
		return fmt.Sprintf("%d", uint8(p))
	}
}
