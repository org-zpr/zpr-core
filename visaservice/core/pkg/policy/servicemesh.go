package policy

import (
	fmt "fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	snip "zpr.org/vs/pkg/ip"

	"zpr.org/vsx/polio"
)

const (
	KAttrZPRAddr = "zpr.addr" // well known attribute used in policy to set an address
)

// ServiceMesh is a struct to expose the overall service offering of a policy.
// The `Includes` function is designed to help compare two offerings and check
// if all the services in one policy are also offered by another. Written to
// help with configuration change detection.
type ServiceMesh struct {
	services   map[string][]*ServiceRec // key is PROTOCOL:PORT
	sortedKeys []string
}

type ServiceRec struct {
	address     string
	name        string
	port        int
	protocol    string // string form of snet.ip.Protocol
	stype       polio.SvcT
	constraints []string // sorted list of constraint hashes
}

// New empty service mesh.
func NewServiceMesh() *ServiceMesh {
	mesh := new(ServiceMesh)
	mesh.services = make(map[string][]*ServiceRec)
	return mesh
}

// Parse the policy for all its services.
func NewServiceMeshFromPolicy(policy *polio.Policy) *ServiceMesh {
	mesh := NewServiceMesh()

	// services in use by port
	for _, authsvc := range policy.GetServices() {
		for _, uri := range []string{authsvc.QueryUri, authsvc.ValidateUri} {
			if uri == "" {
				continue
			}
			svcUrl, err := url.Parse(uri)
			if err != nil {
				panic(fmt.Sprintf("*ERR* invalid URI found in auth service %v: '%v'\n", authsvc.Name, uri))
			}
			// Host is left over from prototype. Policy compiler sets host to "::1"
			portn, err := strconv.Atoi(svcUrl.Port())
			if err != nil {
				panic(fmt.Sprintf("*ERR* invalid port on auth service in policy: %v", svcUrl))
			}
			skey := fmt.Sprintf("TCP:%d", portn)
			mesh.services[skey] = append(mesh.services[skey], &ServiceRec{
				address:  svcUrl.Hostname(),
				name:     authsvc.Name,
				port:     portn,
				protocol: svcUrl.Scheme,
				stype:    authsvc.Type, // polio.SvcT_SVCT_AUTH,
			})
		}
	}

	// non auth services are "registered" through a procedure.
	var keyIdxZPRAddr uint32
	hasEpidKey := false

	for idx, key := range policy.GetAttrKeyIndex() {
		if key == KAttrZPRAddr {
			keyIdxZPRAddr = uint32(idx)
			hasEpidKey = true
			break
		}
	}

	for _, cpos := range policy.GetConnects() {
		if cpos.Proc == NoProc {
			continue
		}
		// See if an address is specified as an attribute.
		svcAddr := "address dynamic"
		if hasEpidKey {
			for _, exp := range cpos.AttrExprs {
				if exp.Key == keyIdxZPRAddr {
					switch exp.Op {
					case polio.AttrOpT_EQ, polio.AttrOpT_HAS:
						svcAddr = policy.AttrValIndex[exp.Val]
					}
					break
				}
			}
		}
		// cheek the procedure for a register op
		proc := policy.Procs[cpos.Proc]
		for _, ins := range proc.Proc {
			if ins.Opcode == polio.OpCodeT_OP_Register {
				sname := ins.Args[0].GetStrval()
				for _, epstr := range strings.Split(ins.Args[2].GetStrval(), ",") {
					if ep, err := snip.ParseEndpoint(epstr); err == nil {
						skey := fmt.Sprintf("%v:%v", ep.Protocol, ep.Port)
						mesh.services[skey] = append(mesh.services[skey], &ServiceRec{
							address:  svcAddr,
							name:     sname,
							port:     int(ep.Port),
							protocol: ep.Protocol.String(),
							stype:    ins.Args[1].GetSvcval(),
						})
					} else {
						panic(fmt.Sprintf("*ERR* invalid endpoint in proc %d: '%v'\n", cpos.Proc, epstr))
					}
				}
			}
		}
	}

	// Get constraints from the communication policies.
	for _, cpol := range policy.GetPolicies() {
		if len(cpol.Constraints) > 0 {
			var candidateServices []*ServiceRec

			// Find the service(s) in our mesh
			// A policy on a component may apply to multiple scopes (multiple services) -- unless
			// the policy specifies the service subset it belongs to.
			for _, srecs := range mesh.services {
				for _, srec := range srecs {
					if srec.name == cpol.ServiceId { // There are many policies for each service ID
						prot, err := snip.ProtocolFromString(srec.protocol)
						if err != nil {
							panic(fmt.Sprintf("servicemesh unable to parse protocol %v: %v", srec.protocol, err))
						}
						if HasScope(cpol, int(prot.Num()), srec.port) {
							candidateServices = append(candidateServices, srec)
						}
					}
				}
			}
			if len(candidateServices) == 0 {
				// service not found
				continue
			}
			for _, rec := range candidateServices {
				var hashes []string
				for _, cons := range cpol.Constraints {
					if cons != nil {
						hashes = append(hashes, HashHex(cons))
					}
				}
				if len(hashes) > 0 {
					hashes = append(hashes, rec.constraints...) // from other possible matches?
					sort.Slice(hashes, func(i, j int) bool {
						return strings.Compare(hashes[i], hashes[j]) < 0
					})
					rec.constraints = hashes // now sorted
				}
			}
		}
	}
	mesh.sortedKeys = sortKeys(mesh.services)
	return mesh
}

// AddService is intended for testing.
func (mesh *ServiceMesh) AddService(proto snip.Protocol, port uint16, address string, name string, svctype polio.SvcT) {
	svc := &ServiceRec{
		address:  address,
		name:     name,
		port:     int(port),
		protocol: proto.String(),
		stype:    svctype,
	}
	skey := fmt.Sprintf("%v:%d", proto, port)
	mesh.services[skey] = append(mesh.services[skey], svc)
	mesh.sortedKeys = sortKeys(mesh.services)
}

// AddServiceWithConstraints is intended for testing.
// Constraints must be sorted.
func (mesh *ServiceMesh) AddServiceWithConstraints(proto snip.Protocol, port uint16, address string, name string, svctype polio.SvcT, constraints []string) {
	if len(constraints) == 0 {
		constraints = nil
	}
	svc := &ServiceRec{
		address:     address,
		name:        name,
		port:        int(port),
		protocol:    proto.String(),
		stype:       svctype,
		constraints: constraints,
	}

	skey := fmt.Sprintf("%v:%d", proto, port)
	mesh.services[skey] = append(mesh.services[skey], svc)
	mesh.sortedKeys = sortKeys(mesh.services)
}

// Returns true if the protocol/port is offered by one or more services in this mesh.
func (mesh *ServiceMesh) Allows(protocol snip.Protocol, port uint16) bool {
	skey := fmt.Sprintf("%v:%d", protocol, port)
	_, ok := mesh.services[skey]
	return ok
}

// Returns true if this mesh shows that the given host provides a service of given protocol and port.
// Ignores any differences in constraints.
// TODO: Do we care about service name or type?
func (mesh *ServiceMesh) Provides(host string, protocol snip.Protocol, port uint16) bool {
	skey := fmt.Sprintf("%v:%d", protocol, port)
	for _, rec := range mesh.services[skey] {
		if rec.address == host {
			return true
		}
	}
	return false
}

// Just like `Provides` but this one also checks that the constraints are the same.
func (mesh *ServiceMesh) providesWithConstraints(host string, protocol snip.Protocol, port uint16, constraints []string) bool {
	skey := fmt.Sprintf("%v:%d", protocol, port)
	for _, rec := range mesh.services[skey] {
		if rec.address == host {
			if len(rec.constraints) != len(constraints) {
				continue
			}
			for i, conhash := range rec.constraints {
				if conhash != constraints[i] {
					continue
				}
			}
			return true
		}
	}
	return false
}

// Does this mesh include the other mesh?
func (mesh *ServiceMesh) Includes(other *ServiceMesh) bool {
	// Every service in other must be in self.
	for skey := range other.services {
		if _, ok := mesh.services[skey]; !ok {
			return false
		}
	}

	// And if a host offers a service in other, it must be offered by same host in self.
	for _, recs := range other.services {
		for _, rec := range recs {
			proto, err := snip.ProtocolFromString(rec.protocol)
			if err != nil {
				panic(err)
			}
			if !mesh.providesWithConstraints(rec.address, proto, uint16(rec.port), rec.constraints) {
				return false
			}
		}
	}
	return true
}

// Sorts the service key (which is PROTOCOL:PORT string) first by protocol (alphabetic) and
// then by port (numeric).
func sortKeys(services map[string][]*ServiceRec) []string {
	var keys []string
	for skey := range services {
		keys = append(keys, skey)
	}

	sort.Slice(keys, func(i, j int) bool {

		// First compare by protocol name
		ibits := strings.Split(keys[i], ":")
		jbits := strings.Split(keys[j], ":")
		if ibits[0] < jbits[0] {
			return true
		} else if ibits[0] > jbits[0] {
			return false
		}

		// same protocol, so compare ports numerically
		return services[keys[i]][0].port < services[keys[j]][0].port
	})

	return keys
}

// Write mesh to stdout.
func (mesh *ServiceMesh) Dump() {
	for _, skey := range mesh.sortedKeys {
		fmt.Printf("[%v]\n", skey)
		for _, rec := range mesh.services[skey] {
			plural := "s"
			if len(rec.constraints) == 1 {
				plural = ""
			}
			fmt.Printf("            %-39v  (%v) %d constraint%s\n", rec.address, rec.name, len(rec.constraints), plural)
		}
	}

}
