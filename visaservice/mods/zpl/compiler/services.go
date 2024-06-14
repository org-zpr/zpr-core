package compiler

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"zpr.org/vsx/polio"
	"zpr.org/vsx/zpl/doc"
)

// setServices puts all the AUTH services into policy.  AUTH services are defined
// in a datasources ZPL section.  These are installed as components by the
// preprocessor.
//
// The actual datasource blocks are either in ZPR section or have been lifted
// out of systems areas and put in the Communications.NestedDatasources section.
func (c *Compilation) setServices(d *doc.Doc) error {
	var pending []*doc.System
	var cur *doc.System
	for _, docsys := range d.Communications.Systems {
		pending = append(pending, docsys)
	}
	for len(pending) > 0 {
		cur, pending = pending[0], pending[1:]
		if cur.Systems != nil {
			for _, docsys := range cur.Systems {
				pending = append(pending, docsys)
			}
		}
		for _, comp := range cur.Components {
			if pfx := comp.Auth.String(); pfx != "" { // preprocessor sets the Auth attribute to the prefix.
				ds, found := d.Zpr.Datasources[pfx]
				if !found {
					ds, found = d.Communications.NestedDatasources[pfx]
				}
				if !found {
					return doc.ZplScalarErrorf(comp.ZplRef, "(%v) datasource definition missing", comp.GetID())
				}
				// Only TCP to a single port is supported
				var svcPort int
				// Compiler will already have copied the services down from the endpoint.
				// The FIRST service is auth service.
				if svc, ok := d.Services[comp.Services[0]]; !ok {
					return doc.ZplScalarErrorf(ds.Endpoint.ZplRef, "(%v) unknown service for datasource %v", comp.GetID(), comp.Services[0])
				} else if svc.TCP.String() == "" {
					return doc.ZplScalarErrorf(ds.Endpoint.ZplRef, "(%v) auth endpoint protocol must be TCP", comp.GetID())
				} else if pn, err := strconv.Atoi(svc.TCP.String()); err != nil {
					return doc.ZplScalarErrorf(ds.Endpoint.ZplRef, "(%v) auth port error: %w", comp.GetID(), err)
				} else {
					svcPort = pn // preprocessor has checked port val.
				}
				if comp.Address.Value() == nil {
					return doc.ZplScalarErrorf(ds.Endpoint.ZplRef, "(%v) auth services requires an address", comp.GetID())
				}
				if ds.Endpoint.TlsDomain.String() == "" {
					return doc.ZplScalarErrorf(ds.Endpoint.TlsDomain, "(%v) auth service requires a domain", comp.GetID())
				}
				addr, err := c.resolve(comp.Address.String())
				if err != nil {
					return doc.ZplScalarErrorf(comp.Address, "(%v) failed to resolve auth service address: %v", comp.GetID(), err)
				}
				svcPathName := comp.GetProvides()
				for _, as := range c.attrExprSets {
					if as.Provider {
						for _, asp := range as.Provides {
							if asp.Type == PSvcTAuth && asp.ServiceID == comp.GetProvides() {
								svcPathName = asp.Path
							}
						}
					}
				}
				vApiVer, qApiVer, err := parseDSApiSpec(ds.Api.String())
				if err != nil {
					return doc.ZplScalarErrorf(ds.Api, "(%v) auth service with invalid API spec", comp.GetID())
				}
				ps := &polio.Service{
					Type:               polio.SvcT_SVCT_AUTH,
					Name:               svcPathName, // This must match the name in the registration proc
					Prefix:             pfx,
					Domain:             ds.Endpoint.TlsDomain.String(),
					QueryApiVersion:    int32(vApiVer),
					ValidateApiVersion: int32(qApiVer),
					Addr:               fmt.Sprintf("[%v]:%d", addr, svcPort), // Note assumption that addr is IPv6 address
				}
				c.policy.Services = append(c.policy.Services, ps)
			}
		}
	}
	// Sort auth services by their path names (/system_id/system_id/.../service_id)
	if c.policy.Services != nil {
		sort.Slice(c.policy.Services, func(i, j int) bool {
			return strings.Compare(c.policy.Services[i].Name, c.policy.Services[j].Name) < 0
		})
	}
	return nil
}

func scopeIncludesScope(superset, subset []*doc.Scoping) bool {

	superPS := scopeExplode(superset)

	// Each member of subset must be in superset.
	for _, subPS := range scopeExplode(subset) {
		matched := false
		for _, sup := range superPS {
			if subPS == sup {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// portTypeExplode returns list of port strings for the form "PROTOCOL/PORT".
// In the case of ICMP it is "ICMP/<TYPE_CODE>".
func scopeExplode(a []*doc.Scoping) []string {
	var pslist []string
	for _, scope := range a {
		if scope.ICMP != nil {
			for _, pn := range portTypeExplode(scope.ICMP.TypeCodes.String()) {
				pslist = append(pslist, fmt.Sprintf("ICMP/%d", pn))
			}
		}
		if scope.TCP.Value() != nil {
			for _, pn := range portTypeExplode(scope.TCP.String()) {
				pslist = append(pslist, fmt.Sprintf("TCP/%d", pn))
			}
		}
		if scope.UDP.Value() != nil {
			for _, pn := range portTypeExplode(scope.UDP.String()) {
				pslist = append(pslist, fmt.Sprintf("UDP/%d", pn))
			}
		}
	}
	return pslist
}

func portTypeExplode(pts string) []int {
	var plist []int
	for _, pt := range strings.Split(pts, ",") {
		ptr := strings.Split(pt, "-")
		if len(ptr) > 1 {
			var low, high int
			if n, err := strconv.Atoi(ptr[0]); err == nil {
				continue
			} else {
				low = n
			}
			if n, err := strconv.Atoi(ptr[1]); err == nil {
				continue
			} else {
				high = n
			}
			for i := low; i <= high; i++ {
				plist = append(plist, i)
			}
		} else {
			n, err := strconv.Atoi(ptr[0])
			if err != nil {
				continue
			}
			plist = append(plist, n)
		}
	}
	return plist
}

func parseDSApiSpec(apispec string) (validateApiVer int, queryApiVer int, err error) {
	if pperr := doc.AssertValidDSAPISpec(apispec); err != nil {
		err = pperr
		return
	}
	for _, spec := range strings.Split(apispec, ";") {
		namver := strings.Split(spec, "/")
		ver, _ := strconv.Atoi(strings.TrimSpace(namver[1]))
		switch strings.TrimSpace(namver[0]) {
		case "validation":
			validateApiVer = ver
		case "query":
			queryApiVer = ver
		}
	}
	return
}
