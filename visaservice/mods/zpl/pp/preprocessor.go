package pp

import (
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/exp/slices"

	"zpr.org/vsx/polio"
	"zpr.org/vsx/zpl/defs"
	"zpr.org/vsx/zpl/doc"
	"zpr.org/vsx/zpl/fs"
	yt "zpr.org/vsx/zpl/pp/yamltree"
)

type ErrMode int

const (
	ErrModeSilent ErrMode = iota
	ErrModeFussy
	ErrModeError
)

type PreprocessOpts struct {
	Quiet                  bool // limit reporting to stderr
	Silent                 bool // inhibit reporting to stderr
	Werror                 bool
	DynamicAsserts         bool   // if true, evaluate assertions that require access to external data sources
	AbideAsserts           bool   // if true, warn about any failing assertions but otherwise ignore them
	TraceAsserts           string // if != "", path expression of assertions or of their "assert" or "desc" children to trace evaluation of
	DSDs                   []*DSDesc
	PMCTLPort              uint16
	VisaServiceAddress     string
	VisaSupportServicePort uint16
	VisaServicePort        uint16
}

// PPState holds extra state during a parse.
type PPState struct {
	fussy              ErrMode
	doc                *doc.Doc // The doc so far
	visaServiceAddress string
}

const (
	VisaServiceServiceName  = "zpr_vsvc"     // reserved name for the visa service protocol
	AdminServiceServiceName = "zpr_adminsvc" // reserved name for the admin service protocol
	VisaSupportServiceName  = "zpr_vsup"
)

// Internal datasources can only use this API spec until we fix the binary format to keep track of this.
const InternalDSValidAPI = "validation/1"

type DSChecking int // Datasource checking for atttibute tuples

const (
	DSCheckOff DSChecking = iota
	DSCheckOn
)

// The "zpr" datasource is always allowed.
var DSAlwaysAllow = []string{"zpr"}

type allowBlock struct {
	dsList  []string // allowed datasource names
	svcList []string // allowed service names
}

type applyBlock struct {
	conditions []*doc.Condition // conditions from apply block (combined with any parent apply conditions)
}

var (
	// VisaServicePolicy is added to the visa-service provider.
	VisaServicePolicy = &doc.Policy{
		Desc:     doc.MustNewZplString("(BUILTIN) nodes access to visaservice"),
		ID:       doc.MustNewZplString("zpr.visaservice.policy"),
		Services: []string{VisaServiceServiceName},
		Conditions: []*doc.Condition{
			{
				Desc: doc.MustNewZplString("(BUILTIN) node access to visa service"),
				AttrExprs: []*doc.AttrExpr{
					{
						Key:   doc.MustNewZplString(defs.KAttrRole),
						Op:    doc.MustNewZplString("eq"),
						Value: doc.MustNewZplString("node"),
					},
				},
			},
		},
	}
)

// VisaServiceService is the reserved ZPR service for the visa-service.
func newVisaService(visaServicePort uint16) *doc.Scoping {
	return &doc.Scoping{
		TCP: doc.MustNewZplString(fmt.Sprintf("%d", visaServicePort)),
	}
}

// AdminServiceService is the reserved ZPR service for the admin-service.
func newAdminService(adminServicePort uint16) *doc.Scoping {
	return &doc.Scoping{
		TCP: doc.MustNewZplString(fmt.Sprintf("%d", adminServicePort)),
	}
}

// VisaSupportService is the reserved ZPR service for the visa-support-service (runs on node to which visa-service connects).
func newVisaSupportService(visaSupportServicePort uint16) *doc.Scoping {
	return &doc.Scoping{
		TCP: doc.MustNewZplString(fmt.Sprintf("%d", visaSupportServicePort)),
	}
}

// newAdminServicePolicy generates access policy for `target` with the condition that accessor
// must match the given `adminAttrs`.
func newAdminServicePolicy(adminAttrs []*doc.AttrExpr, target string) *doc.Policy {
	p := &doc.Policy{
		Desc:     doc.MustNewZplString(fmt.Sprintf("(BUILTIN) admin access to pmctl on %s", target)),
		ID:       doc.MustNewZplString("zpr.adminservice.policy"),
		Services: []string{AdminServiceServiceName},
	}
	p.Conditions = []*doc.Condition{
		{
			Desc:      doc.MustNewZplString("(BUILTIN) must be admin"),
			AttrExprs: adminAttrs,
		},
	}
	return p
}

// Create visa-support service access policy using the attribute passed (which
// should come from the provider info in the policy).
func newVisaSupportServicePolicy(vsProviderAttrs []*doc.AttrExpr) *doc.Policy {
	p := &doc.Policy{
		Desc:     doc.MustNewZplString("(BUILTIN) vs access to vs support on node"),
		ID:       doc.MustNewZplString("zpr.visa_service_support.policy"),
		Services: []string{VisaSupportServiceName},
	}
	p.Conditions = []*doc.Condition{
		{
			Desc:      doc.MustNewZplString("(BUILTIN) must be visa service"),
			AttrExprs: vsProviderAttrs,
		},
	}
	return p
}

// newDatasourcePolicy genereates a parameterized "hard-coded" policy that will
// allow visa service to access a datasource.
func newDatasourcePolicy(prefix string, authServiceName string, vsProviderAttrs []*doc.AttrExpr) *doc.Policy {
	return &doc.Policy{
		Desc:     doc.MustNewZplString(fmt.Sprintf("(BUILTIN) policy allow visa service access to data source %v", prefix)),
		ID:       doc.MustNewZplString("zpr.authservice.policy"),
		Services: []string{authServiceName},
		Conditions: []*doc.Condition{
			{
				Desc:      doc.MustNewZplString(fmt.Sprintf("(BUILTIN) actor with visa service attrs can access data source %v", prefix)),
				AttrExprs: vsProviderAttrs,
			},
		},
	}

}

// Preprocess reads a ZPL (YAML) file, resolves all references to imports and
// defines, applies scoped defaults, and parses the result into a Doc structure.
// It also evaluates all static assertions. On success it returns the output
// Doc and the roots of YAML node trees for the original and preprocessed forms
// of the policy, with the preprocessed form having defines, defaults, and
// assertions removed. It returns a non-nil error value on parsing errors or
// assertion failures.
func Preprocess(fsrootpath string, fst fs.FileStore, opts *PreprocessOpts) (*doc.Doc, yt.Node, yt.Node, error) {
	// Some parts of codebase assume these are set.
	if opts.PMCTLPort == 0 {
		opts.PMCTLPort = defs.DefaultPMCTLPort
	}
	if opts.VisaServiceAddress == "" {
		opts.VisaServiceAddress = defs.DefaultVisaServiceAddress
	}
	if opts.VisaSupportServicePort == 0 {
		opts.VisaSupportServicePort = defs.DefaultVisaSupportServicePort
	}
	if opts.VisaServicePort == 0 {
		opts.VisaServicePort = defs.DefaultVisaServicePort
	}

	// Load the main policy file as a YAML node tree.
	root, err := LoadYamlTree(fsrootpath, fst)
	if err != nil {
		return nil, nil, nil, err
	}

	origRoot := root

	// Check the ZPL format before trying to parse the YAML as ZPL.
	err = validateZplFormat(root)
	if err != nil {
		return nil, nil, nil, err
	}

	// Recursively replace import directives by their argument files' contents.
	root, err = ProcessImports(root, fst)
	if err != nil {
		return nil, nil, nil, err
	}

	// Recursively replace defined symbol references by their definitions.
	root, err = ProcessDefines(root)
	if err != nil {
		return nil, nil, nil, err
	}

	// Recursively insert defaulted values in system configurations.
	root, err = ProcessDefaults(root)
	if err != nil {
		return nil, nil, nil, err
	}

	// Check any compile-time assertions against the (possibly modified) YAML.
	// TODO Need to pass in data source proxy map.
	dsProxies, err := createDSProxies(opts.DSDs)
	if err != nil {
		return nil, nil, nil, err
	}

	// Assertion processing removes the assertion blocks from the tree.
	// Also it runs before processing, so any side effects there cannot be tested.
	root, err = ProcessAssertions(root, dsProxies, os.Stderr, opts)
	if err != nil {
		return nil, nil, nil, err
	}

	prepRoot := root // now with assertions stripped out
	parsedDoc, err := parseZpl(prepRoot, opts)
	if err != nil {
		return nil, nil, nil, err
	}

	return parsedDoc, origRoot, prepRoot, nil
}

// Verifies that the policy file YAML specifies the correct ZPL format. Returns
// a non-nil error if it does not.
func validateZplFormat(root yt.Node) error {
	if err := validateNodeKind(root, yt.MappingKind); err != nil {
		return err
	} else {
		rootPath := []yt.Node{root}
		if zfPath, exists := childPathMap(rootPath)["zpl_format"]; !exists {
			return yt.PathErrorf(rootPath, "ZPL format must be specified in ZPL source")
		} else if zf, err := doc.NewZplInteger(zfPath); err != nil {
			return yt.PathErrorf(rootPath, "invalid ZPL format: %w", err)
		} else if zf.Value().(int64) != int64(doc.ZPLFormat) {
			return yt.PathErrorf(rootPath, "invalid ZPL format: %v required, %v read", doc.ZPLFormat, zf.Value())
		}
		return nil
	}
}

// Parses a ZPL policy file. First argument must be the root of the YAML node
// tree for the policy after expansion of any includes, defines, and defaults.
func parseZpl(root yt.Node, opts *PreprocessOpts) (*doc.Doc, error) {
	if err := validateNodeKind(root, yt.MappingKind); err != nil {
		return nil, err
	}

	rootPath := []yt.Node{root}
	childMap := childPathMap(rootPath)

	pps := &PPState{
		doc:                &doc.Doc{ZplRef: newZplRef(rootPath), Main: &doc.Main{}},
		visaServiceAddress: opts.VisaServiceAddress,
	}
	if opts.Silent || opts.Quiet {
		pps.fussy = ErrModeSilent
	} else {
		pps.fussy = ErrModeFussy
	}
	if opts.Werror {
		pps.fussy = ErrModeError
	}

	var err error

	// Need services before most things.
	if svcsPath, exists := childMap["services"]; !exists {
		return nil, yt.PathErrorf(rootPath, `required "services" key missing`)
	} else if err = pps.parseServices(svcsPath); err != nil {
		return nil, err
	}

	// Add our built in services:
	pps.doc.Services[AdminServiceServiceName] = newAdminService(opts.PMCTLPort)
	pps.doc.Services[VisaServiceServiceName] = newVisaService(opts.VisaServicePort)
	pps.doc.Services[VisaSupportServiceName] = newVisaSupportService(opts.VisaSupportServicePort)

	// Need to parse network before communications.
	if networkPath, exists := childMap["zpr"]; !exists {
		return nil, yt.PathErrorf(rootPath, `required "zpr" key missing`)
	} else if err = pps.parseZPR(networkPath); err != nil {
		return nil, err
	}

	for key, childPath := range childPathMap(rootPath) {
		switch key {
		case "zpl_format":
			pps.doc.ZPLFormat, err = doc.NewZplInteger(childPath)
		case "main":
			err = pps.parseMain(childPath)
		case "communications":
			err = pps.parseCommunications(childPath)
		case "zpr", "services": // handled above
		default:
			if kerr := noteInvalidKey(childPath, pps.fussy); kerr != nil {
				return nil, kerr
			}
			err = nil
		}
		if err != nil {
			return nil, err
		}
	}

	if err := checkRequiredKeys(rootPath, "zpl_format", "zpr", "communications"); err != nil {
		return nil, err
	}

	return pps.doc, nil
}

// Parses "main" block. First arg is path from YAML root to to block.
func (pps *PPState) parseMain(mainPath []yt.Node) error {
	if err := validateLastNodeKind(mainPath, yt.MappingKind); err != nil {
		return err
	}

	main := doc.Main{ZplRef: newZplRef(mainPath)}

	for key, childPath := range childPathMap(mainPath) {
		var err error
		switch key {
		case "policy_version":
			if main.PolicyVersion, err = doc.NewZplUnsigned(childPath); err != nil {
				return yt.PathErrorf(childPath, "invalid policy version: %w", err)
			}
		case "policy_date":
			if main.PolicyDate, err = doc.NewZplString(childPath); err != nil {
				return yt.PathErrorf(childPath, "invalid policy date: %w", err)
			} else if parsedPolDate, err := time.Parse(time.RFC3339, main.PolicyDate.String()); err != nil {
				return doc.ZplScalarErrorf(main.PolicyDate, "not a valid RFC3339 date/time: %w", err)
			} else {
				main.PolicyDateUtc = parsedPolDate.UTC().Format(time.RFC3339)
			}
		case "name":
			if err := warnNotImpl("main.name", childPath, pps.fussy); err != nil {
				return err
			}
		default:
			if err := noteInvalidKey(childPath, pps.fussy); err != nil {
				return err
			}
		}
	}

	pps.doc.Main = &main
	return nil
}

// parseServices parse the "services" section into state doc.
func (pps *PPState) parseServices(svcsPath []yt.Node) error {
	if err := validateLastNodeKindForTag(svcsPath, yt.MappingKind, "services"); err != nil {
		return err
	}
	svcMap := make(map[string]*doc.Scoping)
	for key, childPath := range childPathMap(svcsPath) {
		// Each key is a service name.
		// Each value is a Scoping.
		if _, dupe := svcMap[key]; dupe {
			return yt.PathErrorf(childPath, "duplicate service name: %v", key)
		}
		if strings.HasPrefix(key, "zpr") {
			return yt.PathErrorf(childPath, "service names cannot use reserved 'zpr' prefix: %v", key)
		}
		if scope, err := parseScoping(childPath, pps.fussy); err != nil {
			return err
		} else {
			svcMap[key] = scope
		}
	}
	if len(svcMap) == 0 {
		return yt.PathErrorf(svcsPath, "you must define at least one service")
	}
	pps.doc.Services = svcMap
	return nil
}

// Parses "zpr" block directly into our state doc. First arg is path from YAML root to block.
// Was previously named "network".
func (pps *PPState) parseZPR(networkPath []yt.Node) error {
	if err := validateLastNodeKind(networkPath, yt.MappingKind); err != nil {
		return err
	}

	childMap := childPathMap(networkPath)
	zpr := doc.ZPR{ZplRef: newZplRef(networkPath)}
	pps.doc.Zpr = &zpr
	var err error

	// Need to parse (or set defaults for) globals first.
	if globalsPath, exists := childMap["globals"]; exists {
		if zpr.Globals, err = parseNetworkGlobals(globalsPath, pps.fussy); err != nil {
			return err
		}
	} else {
		zpr.Globals = &doc.NetGlobs{}
		zpr.Globals.MaxConnections, _ = doc.NewZplUnsigned(doc.DefaultMaxConnections)
		zpr.Globals.MaxConnectionsPerDock, _ = doc.NewZplUnsigned(doc.DefaultMaxConnectionsPerDock)
		zpr.Globals.MaxConnectionsPerActor, _ = doc.NewZplUnsigned(doc.DefaultMaxConnectionsPerActor)
	}

	// We need the datasource list before we can parse nodes.
	if childPath, ok := childMap["datasources"]; ok {
		if err = pps.parseNetworkDatasources(childPath); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("missing required 'zpr.datasources' section")
	}

	// Then we need nodes
	if childPath, ok := childMap["nodes"]; ok {
		if err = pps.parseZPRNodes(childPath); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("missing required 'zpr.nodes' section")
	}

	for key, childPath := range childMap {
		var err error
		switch key {
		case "globals", "nodes", "datasources":

		case "topology":
			zpr.Topology, err = parseNetworkTopology(childPath, pps.doc.Zpr.Nodes, zpr.Globals, pps.fussy)
		case "visaservice":
			zpr.Visaservice, err = parseNetworkVisaservice(childPath, pps.doc.Zpr.Nodes, pps.fussy)
		case "adminservice":
			if err := warnNotImpl("zpr.adminservice", childPath, pps.fussy); err != nil {
				return err
			}
		default:
			if kerr := noteInvalidKey(childPath, pps.fussy); kerr != nil {
				return kerr
			}
			err = nil
		}
		if err != nil {
			return err
		}
	}
	if err := checkRequiredKeys(networkPath, "nodes", "visaservice", "datasources"); err != nil {
		return err
	}

	// All nodes allow admin PMCTL requests and visa-service-support connects from visa service.
	for _, vsnode := range zpr.Nodes {
		if err := pps.addUniqueService(vsnode, AdminServiceServiceName); err != nil {
			return err
		}
		vsnode.Policies = append(vsnode.Policies, newAdminServicePolicy(pps.doc.Zpr.Visaservice.Attrs, "node"))

		// Take the attributes specified in the policy
		// And add on that the adapter must also have the visa service address
		var attrs []*doc.AttrExpr
		attrs = append(attrs, zpr.Visaservice.Provider...)
		attrs = append(attrs, &doc.AttrExpr{
			Key:   doc.MustNewZplString(defs.KAttrEPID),
			Op:    doc.MustNewZplString("eq"),
			Value: doc.MustNewZplString(pps.visaServiceAddress),
		})
		if err := pps.addUniqueService(vsnode, VisaSupportServiceName); err != nil {
			return err
		}
		vsnode.Policies = append(vsnode.Policies, newVisaSupportServicePolicy(attrs))
	}

	// If topology is unspecified, set up a default topology with zero bridges and
	// one LAN.
	if zpr.Topology == nil {
		zpr.Topology = &doc.Topology{}
	}
	if zpr.Topology.LANs == nil {
		zpr.Topology.LANs = make(map[string]*doc.LANDesc)
	}
	if len(zpr.Topology.LANs) < 1 {
		defLAN := &doc.LANDesc{}
		for nodeID, nComp := range zpr.Nodes {
			if len(nComp.Interfaces) > 1 {
				return fmt.Errorf("unable to populate default LAN, node %v has multiple interfaces", nodeID)
			}
			defLAN.Nodes = append(defLAN.Nodes, doc.MustNewZplString(nodeID))
		}
		zpr.Topology.LANs["lan0"] = defLAN
	}

	return nil
}

// addUniqueService adds the service by name `svcName` to the services list on
// component `c` only if it is not already in there (even if by a different name).
func (pps *PPState) addUniqueService(c *doc.Component, svcName string) error {
	sdef, ok := pps.doc.Services[svcName]
	if !ok {
		return fmt.Errorf("service not found: %v", svcName)
	}
	for _, csname := range c.Services {
		csdef, ok := pps.doc.Services[csname]
		if !ok {
			continue // will be caught later
		}
		if scopesEquivalent([]*doc.Scoping{sdef}, []*doc.Scoping{csdef}) {
			return fmt.Errorf("duplicate service on component %v: %v == %v", c.ID.String(), svcName, csname)
		}
	}
	c.Services = append(c.Services, svcName)
	return nil
}

// parseZPRNodes parse the zpr.nodes section directly into our state doc.
// A node is a Component with the addition of some extra properties.
// By default it will have no services and no policies.
func (pps *PPState) parseZPRNodes(nodesPath []yt.Node) error {
	// Warning: There are two kinds of node being referenced in this function!
	// In variable names, "node" refers to a ZPR node, whereas "Node" refers
	// to a YAML tree node.

	if err := validateLastNodeKind(nodesPath, yt.MappingKind); err != nil {
		return err
	}
	nodes := map[string]*doc.Component{} // node ID -> Component
	nodeKeys := map[string]string{}      // node Key -> node ID

	nodesMap := childPathMap(nodesPath)

	for nodeName, nodePath := range nodesMap {
		if err := validateLastNodeKind(nodePath, yt.MappingKind); err != nil {
			return err
		}
		allow := &allowBlock{
			dsList: []string{"zpr"},
		}
		for svcID := range pps.doc.Services {
			allow.svcList = append(allow.svcList, svcID)
		}
		for dsID := range pps.doc.Zpr.Datasources {
			allow.dsList = append(allow.dsList, dsID)
		}
		nodeC, err := parseComponent(nodePath, allow, &applyBlock{}, pps.fussy, []string{"provider"})
		if err != nil {
			return err
		}
		if nodeC.ID.String() != nodeName {
			return doc.ZplScalarErrorf(nodeC.ID, "node ID (%v) must match nodes mapping name (%v)", nodeC.ID.String(), nodeName)
		}
		if nodeC.Key.Empty() {
			return yt.PathErrorf(nodesPath, `required key "key" missing from node definition`)
		}
		if nID, dupeKey := nodeKeys[nodeC.Key.String()]; dupeKey {
			return doc.ZplScalarErrorf(nodeC.Key, "found duplicate node key value (same as node %v)", nID)
		}
		nodeKeys[nodeC.Key.String()] = nodeC.ID.String()

		nodeComponentMap := childPathMap(nodePath)
		// A node must have an interfaces propert.
		if ifPath, ok := nodeComponentMap["interfaces"]; !ok {
			return yt.PathErrorf(nodesPath, `required key "interfaces" missing from node definition`)
		} else {
			maxconn, err := pps.doc.Zpr.Globals.MaxConnectionsPerDock.AsUint64()
			if err != nil {
				maxconn = 0 // unlimited.
			}
			if ifaces, err := parseNodeInterfaces(ifPath, maxconn, pps.fussy); err != nil {
				return err
			} else {
				nodeC.Interfaces = ifaces
			}
		}
		if _, dupe := nodes[nodeName]; dupe {
			return yt.PathErrorf(nodesPath, "duplicate node id: %v", nodeName)
		}
		nodes[nodeName] = nodeC
	}

	if len(nodes) == 0 {
		return yt.PathErrorf(nodesPath, "no nodes defined")
	}

	pps.doc.Zpr.Nodes = nodes
	return nil
}

// parseNodeInterfaces parses the interfaces map from a zpr.nodes block.
func parseNodeInterfaces(ifacesPath []yt.Node, maxConnectionsPerDock uint64, fussy ErrMode) (map[string]*doc.Interface, error) {
	if err := validateLastNodeKind(ifacesPath, yt.MappingKind); err != nil {
		return nil, err
	}
	ifaces := make(map[string]*doc.Interface)
	for ifaceID, ifacePath := range childPathMap(ifacesPath) {
		if _, dupe := ifaces[ifaceID]; dupe {
			return nil, yt.PathErrorf(ifacePath, "duplice interface ID: %v", ifaceID)
		}
		// Each childPath is a mapping element of interface properties.
		if err := validateLastNodeKind(ifacePath, yt.MappingKind); err != nil {
			return nil, err
		}
		iface := &doc.Interface{
			ZplRef:         newZplRef(ifacePath),
			Dock:           doc.MustNewZplBoolean(true),
			MaxConnections: doc.MustNewZplUnsigned(maxConnectionsPerDock),
		}
		var err error
		for ifkey, childPath := range childPathMap(ifacePath) {
			switch ifkey {
			case "netaddr":
				if iface.Netaddr, err = doc.NewZplString(childPath); err != nil {
					return nil, err
				} else if err = doc.AssertValidNetAddr(iface.Netaddr.String()); err != nil {
					return nil, doc.ZplScalarErrorf(iface.Netaddr, "%w", err)
				}
			case "dock":
				if iface.Dock, err = doc.NewZplBoolean(childPath); err != nil {
					return nil, err
				}
				if !iface.Dock.AsBool() {
					if err := warnNotImpl("disabling docking on a node interface", childPath, fussy); err != nil {
						return nil, err
					}
				}

			case "max_connections":
				if iface.MaxConnections, err = doc.NewZplUnsigned(childPath); err != nil {
					return nil, err
				} else {
					maxc, err := iface.MaxConnections.AsUint64()
					if err != nil {
						return nil, doc.ZplScalarErrorf(iface.MaxConnections, "%w", err)
					}
					if maxc > maxConnectionsPerDock {
						return nil, doc.ZplScalarErrorf(iface.MaxConnections, "invalid connection limit for node interface %q: "+
							"value %v exceeds global per-dock maximum %v", ifkey, maxc, maxConnectionsPerDock)
					}
				}

			default:
				if err := noteInvalidKey(childPath, fussy); err != nil {
					return nil, err
				}
			}
		}
		ifaces[ifaceID] = iface

	}
	return ifaces, nil
}

// Parses network "globals" block. First arg is path from YAML root to block.
func parseNetworkGlobals(globalsPath []yt.Node, fussy ErrMode) (*doc.NetGlobs, error) {
	if err := validateLastNodeKind(globalsPath, yt.MappingKind); err != nil {
		return nil, err
	}

	globals := doc.NetGlobs{ZplRef: newZplRef(globalsPath)}

	for key, childPath := range childPathMap(globalsPath) {
		var err error
		switch key {
		case "max_connections":
			globals.MaxConnections, err = doc.NewZplUnsigned(childPath)
		case "max_connections_per_dock":
			globals.MaxConnectionsPerDock, err = doc.NewZplUnsigned(childPath)
		case "max_connections_per_actor":
			globals.MaxConnectionsPerActor, err = doc.NewZplUnsigned(childPath)
		case "max_heap_size", "tether_net", "zpr_net":
			if err := warnNotImpl(fmt.Sprintf("zpr.globals.%s", key), childPath, fussy); err != nil {
				return nil, err
			}
		default:
			if kerr := noteInvalidKey(childPath, fussy); kerr != nil {
				return nil, kerr
			}
			err = nil
		}
		if err != nil {
			return nil, err
		}
	}

	return &globals, nil
}

// TODO: Not hooked up
// Parses network "addresses" block. First arg is path from YAML root to block.
func parseNetworkAddresses(addrsPath []yt.Node, fussy ErrMode) (*doc.NetAddresses, error) {
	if err := validateLastNodeKind(addrsPath, yt.MappingKind); err != nil {
		return nil, err
	}

	addrs := doc.NetAddresses{ZplRef: newZplRef(addrsPath)}

	for key, childPath := range childPathMap(addrsPath) {
		var err error
		switch key {
		case "tether_net":
			if addrs.TetherNet, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			} else if err = doc.AssertValidIPv6CIDR(addrs.TetherNet.String()); err != nil {
				return nil, doc.ZplScalarErrorf(addrs.TetherNet, "%w", err)
			}
		case "zpr_net":
			if addrs.ZPRNet, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			} else if err = doc.AssertValidIPv6CIDR(addrs.ZPRNet.String()); err != nil {
				return nil, doc.ZplScalarErrorf(addrs.ZPRNet, "%w", err)
			}
		default:
			if err := noteInvalidKey(childPath, fussy); err != nil {
				return nil, err
			}
		}

		if addrs.TetherNet.Value() != nil && addrs.ZPRNet.Value() != nil {
			_, netNode, _ := net.ParseCIDR(addrs.TetherNet.String())
			zip, _, _ := net.ParseCIDR(addrs.ZPRNet.String())
			if netNode.Contains(zip) { // Not sure how great this test is...
				return nil, doc.ZplScalarErrorf(addrs.TetherNet, "tether_net must not overlap zpr_net")
			}
		}
	}

	return &addrs, nil
}

// parseNetworkDatasources parses zpr (was network) "datasources" block directly into our state doc.
// Sets `pps.doc.Zpr.Datasources`.
func (pps *PPState) parseNetworkDatasources(authsPath []yt.Node) error {
	dsnames := map[string]bool{
		"zpr": true, // "zpr" is reserved for internal use
	}
	dsblock, err := parseDatasourcesBlock(authsPath, pps.doc.Services, dsnames, false, nil, nil, pps.fussy)
	if err != nil {
		return err
	}
	pps.doc.Zpr.Datasources = dsblock
	return nil
}

// `existingDSNames` is a map of all the datasources identifiers already defined (must include 'zpr' too).
//
// `extOnly` is set true to only allow external datasource declarations.
//
// `allow`, `apply` These are used when parsing datasources within systems blocks.  Should be nil when
//
//	parsing the ZPR datasources.
func parseDatasourcesBlock(dsPath []yt.Node, allServices map[string]*doc.Scoping, existingDSNames map[string]bool,
	extOnly bool, allow *allowBlock, apply *applyBlock, fussy ErrMode) (map[string]*doc.Datasource, error) {
	if err := validateLastNodeKind(dsPath, yt.MappingKind); err != nil {
		return nil, err
	}
	// The mapping key is the datasource "prefix".
	sources := make(map[string]*doc.Datasource)
	for dsPrefix, dsNodePath := range childPathMap(dsPath) {
		// Use lowercase for prefixes.
		dsPrefix = strings.ToLower(dsPrefix)
		if _, exists := existingDSNames[dsPrefix]; exists {
			return nil, yt.PathErrorf(dsNodePath, "duplicate datasource prefix: %v", dsPrefix)
		}
		if _, found := sources[dsPrefix]; found {
			return nil, yt.PathErrorf(dsNodePath, "duplicate datasource prefix: %v", dsPrefix)
		}
		if err := validateLastNodeKind(dsNodePath, yt.MappingKind); err != nil {
			return nil, err
		}
		if err := checkRequiredKeys(dsNodePath, "api"); err != nil {
			return nil, err
		}
		ds := &doc.Datasource{ZplRef: newZplRef(dsNodePath)}
		hasAuthority, hasEndpoint := false, false
		var err error
		for key, childPath := range childPathMap(dsNodePath) {
			switch key {
			case "api":
				if apiSpec, err := doc.NewZplString(childPath); err != nil {
					return nil, err
				} else if err := doc.AssertValidDSAPISpec(apiSpec.String()); err != nil {
					return nil, yt.PathErrorf(childPath, "failed to parse API spec: %w", err)
				} else {
					ds.Api = apiSpec
				}
			case "authority":
				if extOnly {
					return nil, yt.PathErrorf(childPath, "internal datasource declaration not allowed here")
				}
				if hasEndpoint {
					return nil, yt.PathErrorf(childPath, "only one of endpoint or authority can be specified per datasource")
				}
				hasAuthority = true
				if ds.Authority, err = parseCertificate(childPath, fussy); err != nil {
					return nil, err
				}
			case "endpoint":
				if hasAuthority {
					return nil, yt.PathErrorf(childPath, "only one of endpoint or authority can be specified per datasource")
				}
				hasEndpoint = true
				if ds.Endpoint, err = parseDSEndpointGeneral(childPath, allServices, allow, apply, fussy); err != nil {
					return nil, err
				}
			case "config":
				if ds.Config, err = parseStringConfigMap(childPath, fussy); err != nil {
					return nil, err
				}
			default:
				if err := noteInvalidKey(childPath, fussy); err != nil {
					return nil, err
				}
			}
		}
		// Ok finished parsing this mapping, did we get enough?
		if !(hasEndpoint || hasAuthority) {
			if extOnly {
				return nil, yt.PathErrorf(dsNodePath, "missing endpoint attribute for %v", dsPrefix)
			} else {
				return nil, yt.PathErrorf(dsNodePath, "missing endpoint or authority attribute for %v", dsPrefix)
			}
		}
		// TODO: Current bug in policy binary format - we loose the api info about internal datasources.
		//       Therefore we only allow "validation/1".
		if hasAuthority && ds.Api.AsString() != InternalDSValidAPI {
			return nil, yt.PathErrorf(dsNodePath, "internal type datasources can only use api version %v", InternalDSValidAPI)
		}
		sources[dsPrefix] = ds
	}
	return sources, nil
}

// parseStringConfigMap just parse a mapping of string->string into a vanilla map.
func parseStringConfigMap(mapPath []yt.Node, _ ErrMode) (map[string]string, error) {
	if err := validateLastNodeKind(mapPath, yt.MappingKind); err != nil {
		return nil, err
	}
	mm := make(map[string]string)
	for key, childPath := range childPathMap(mapPath) {
		if _, found := mm[key]; found {
			return nil, yt.PathErrorf(childPath, "duplicate config key: %v", key)
		}
		if sv, err := doc.NewZplString(childPath); err != nil {
			return nil, err
		} else {
			mm[key] = sv.String()
		}
	}
	return mm, nil
}

// parseDSEndpointZPR parses a ZPR level Datasource Endpoint block.
//
// We assume this is from the ZPR datasources area, not a nested datasource.
//
// A nested datasource may be under an apply block restriction in which case
// we will need to check attributes.
//
// This ignores any apply block also.
func parseDSEndpointZPR(epPath []yt.Node, services map[string]*doc.Scoping, fussy ErrMode) (*doc.Endpoint, error) {
	return parseDSEndpointGeneral(epPath, services, nil, nil, fussy)
}

// parseDSEndpointGeneral parser for a datasource endpoint block that is general enough to use on both our ZPR level
// datasources and on scoped datasources (found within a systems block).
//
// `allow` should be nil if we are in ZPR context. Otherwise must include the list of
//
//	allowed datasources and services that can be referenced here.
//
// `apply` can be nil, is only used for parsing optional policies when not in ZPR context
//
//	(ie, when `allow`` is non-nil)
func parseDSEndpointGeneral(epPath []yt.Node, allServices map[string]*doc.Scoping, allow *allowBlock, apply *applyBlock, fussy ErrMode) (*doc.Endpoint, error) {
	if err := validateLastNodeKind(epPath, yt.MappingKind); err != nil {
		return nil, err
	}
	if err := checkRequiredKeys(epPath, "provider", "services", "tls_domain", "tls_cert"); err != nil {
		return nil, err
	}
	ep := &doc.Endpoint{ZplRef: newZplRef(epPath)}
	var err error

	// Before we can parse the policies, we need to see if there are services defined.
	cpMap := childPathMap(epPath)
	if childPath, ok := cpMap["services"]; ok {
		if svcnames, err := parseStringList(childPath, fussy); err != nil {
			return nil, err
		} else {
			for i, sname := range svcnames {
				if allow != nil {
					// If allow is passed, service name must be in there.
					if slices.Index(allow.svcList, sname) < 0 {
						return nil, doc.ZplScalarErrorf(ep.ZplRef, "datasource references undefined or blocked service: %v", sname)
					}
				}
				if sdef, ok := allServices[sname]; !ok {
					return nil, doc.ZplScalarErrorf(ep.ZplRef, "datasource references undefined service: %v", sname)
				} else if i == 0 && sdef.TCP.Empty() {
					return nil, doc.ZplScalarErrorf(ep.ZplRef, "first datasource service %v must specify a TCP port", sname)
				}
			}
			ep.Services = svcnames
		}
	}

	for key, childPath := range cpMap {
		switch key {
		case "provider":
			if allow == nil {
				if ep.Provider, err = parseAttrExprSequenceAnyDS(childPath, fussy); err != nil {
					return nil, err
				}
			} else {
				if ep.Provider, err = parseAttrExprSequence(childPath, allow.dsList, fussy); err != nil {
					return nil, err
				}
			}
			for _, attrExpr := range ep.Provider {
				key := attrExpr.Key.String()
				op := attrExpr.Op.String()
				if key == defs.KAttrAuthority && !(op == doc.AttrExprOpEq || op == doc.AttrExprOpHas) {
					return nil, doc.ZplScalarErrorf(attrExpr.ZplRef, "provider attribute expression with %q key requires %q or %q operator (found %q)",
						key, doc.AttrExprOpHas, doc.AttrExprOpEq, op)
				}
			}
		case "services":
			// Already done above.

		case "tls_domain":
			if ep.TlsDomain, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			}
		case "tls_cert":
			if ep.TlsCert, err = parseCertificate(childPath, fussy); err != nil {
				return nil, err
			}
		case "address": // optional
			if ep.Address, err = doc.NewIPv6Address(childPath); err != nil {
				return nil, err
			}
			if err = doc.AssertValidZPRAddress(ep.Address.String()); err != nil {
				return nil, doc.ZplScalarErrorf(ep.Address, "invalid service address: %w", err)
			}
		case "policies": // optional
			if err := validateLastNodeKind(childPath, yt.SequenceKind); err != nil {
				return nil, err
			}
			policiesWithServices := 0
			for _, polPath := range childPathSeq(childPath) {
				var pol *doc.Policy
				if allow == nil {
					pol, err = ParsePolicy(polPath, ep.Services, nil, DSCheckOff, nil, fussy) // ZPR context
				} else {
					pol, err = ParsePolicy(polPath, ep.Services, allow.dsList, DSCheckOn, apply, fussy)
				}
				if err != nil {
					return nil, err
				}
				if len(pol.Services) > 0 {
					policiesWithServices++
				}
				ep.Policies = append(ep.Policies, pol)
			}
			if policiesWithServices > 0 && (len(ep.Policies) != policiesWithServices) {
				return nil, yt.PathErrorf(childPath, "if any policy a component has a services block then all must have a services block")
			}
		default:
			if err := noteInvalidKey(childPath, fussy); err != nil {
				return nil, err
			}
		}
	}

	return ep, nil
}

func parseStringList(lPath []yt.Node, _ ErrMode) ([]string, error) {
	if err := validateLastNodeKind(lPath, yt.SequenceKind); err != nil {
		return nil, err
	}
	var slist []string
	for _, valp := range childPathSeq(lPath) {
		if sname, err := doc.NewZplString(valp); err != nil {
			return nil, err
		} else {
			slist = append(slist, sname.String())
		}
	}
	return slist, nil
}

func parseNetworkVisaservice(vsPath []yt.Node, nodes map[string]*doc.Component, fussy ErrMode) (*doc.Visaservice, error) {
	if err := validateLastNodeKind(vsPath, yt.MappingKind); err != nil {
		return nil, err
	}

	vservice := doc.Visaservice{ZplRef: newZplRef(vsPath)}

	for key, childPath := range childPathMap(vsPath) {
		var err error
		switch key {
		case "dock":
			if vservice.Dock, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			}
			if _, ok := nodes[vservice.Dock.String()]; !ok {
				return nil, doc.ZplScalarErrorf(vservice.Dock, "node ID is unknown")
			}
		case "provider":
			if vservice.Provider, err = parseAttrExprSequenceAnyDS(childPath, fussy); err != nil {
				return nil, err
			}
			if len(vservice.Provider) == 0 {
				return nil, yt.PathErrorf(childPath, "provider for visaservice must be nonempty")
			}
		case "admin_attrs":
			if vservice.Attrs, err = parseAttrExprSequenceAnyDS(childPath, fussy); err != nil {
				return nil, err
			}
			if len(vservice.Attrs) == 0 {
				return nil, yt.PathErrorf(childPath, "admin_attrs for visaservice must be nonempty")
			}
		default:
			if err := noteInvalidKey(childPath, fussy); err != nil {
				return nil, err
			}
		}
	}

	if err := checkRequiredKeys(vsPath, "admin_attrs", "provider"); err != nil {
		return nil, err
	}

	// dock is only required if there are multiple nodes
	if len(nodes) > 1 {
		if err := checkRequiredKeys(vsPath, "dock"); err != nil {
			return nil, err
		}
	} else if len(nodes) == 0 {
		return nil, yt.PathErrorf(vsPath, "unable to define visa service: no nodes to dock to")
	} else { // exactly 1 node
		for nodeID := range nodes {
			vservice.Dock = doc.MustNewZplString(nodeID)
		}
	}

	return &vservice, nil
}

// Parses network "topology" block. First arg is path from YAML root to block,
// second arg is parsed network globals.
func parseNetworkTopology(topoPath []yt.Node, nodes map[string]*doc.Component, globals *doc.NetGlobs, fussy ErrMode) (*doc.Topology, error) {
	topo := doc.Topology{ZplRef: newZplRef(topoPath)}
	if isLastNodeEmpty(topoPath) {
		// Empty topology
		return &topo, nil
	}
	if err := validateLastNodeKind(topoPath, yt.MappingKind); err != nil {
		return nil, err
	}
	for key, childPath := range childPathMap(topoPath) {
		var err error
		switch key {
		case "lans":
			if topo.LANs, err = parseNetworkTopologyLans(childPath, nodes, fussy); err != nil {
				return nil, err
			}
		case "bridges":
			if topo.Bridges, err = parseNetworkTopologyBridges(childPath, globals, nodes, fussy); err != nil {
				return nil, err
			}
		default:
			if err := noteInvalidKey(childPath, fussy); err != nil {
				return nil, err
			}
		}
	}

	// If no lans were defined, create a default lan0 with all nodes in it.
	if len(topo.LANs) == 0 {
		nodeNames := make([]doc.ZplString, 0, len(nodes))
		for nodeID := range nodes {
			nodeNames = append(nodeNames, doc.MustNewZplString(nodeID))
		}
		lanDesc := doc.LANDesc{ZplRef: newZplRef(topoPath), Nodes: nodeNames}
		topo.LANs = map[string]*doc.LANDesc{"lan0": &lanDesc}
	}
	return &topo, nil
}

func lookupNodeOrNodeInterface(nodenameIn string, nodes map[string]*doc.Component) (nodeName string, ifName string, err error) {
	if _, exist := nodes[nodenameIn]; exist {
		// Found the node
		nodeName = nodenameIn
		return
	}
	if bits := strings.Split(nodenameIn, "."); len(bits) <= 1 {
		err = fmt.Errorf("node name not found")
		return
	} else {
		nodeName = bits[0]
		ifName = strings.Join(bits[1:], ".")
		if nn, ok := nodes[nodeName]; ok {
			if _, ok := nn.Interfaces[ifName]; ok {
				return // All good
			} else {
				err = fmt.Errorf("node %v has no interface named %v", nodeName, ifName)
				return
			}
		}
		err = fmt.Errorf("node '%v' not found", nodeName)
		return
	}
}

// Parses topology "lans" block. First arg is path from YAML root to block,
// second arg is map of node names to parsed node descriptors.
func parseNetworkTopologyLans(lansPath []yt.Node, nodes map[string]*doc.Component, _ ErrMode) (map[string]*doc.LANDesc, error) {
	// See comment about "node" vs "Node" in parseNetworkTopologyNodes.
	if err := validateLastNodeKind(lansPath, yt.MappingKind); err != nil {
		return nil, err
	}

	lansMap := map[string]*doc.LANDesc{} // key = lan name

	for lanName, lanPath := range childPathMap(lansPath) {
		if err := validateLastNodeKind(lanPath, yt.SequenceKind); err != nil {
			return nil, err
		}
		nodeNames := []doc.ZplString{}
		for _, nodeNamePath := range childPathSeq(lanPath) {
			nodeName, err := doc.NewZplString(nodeNamePath)
			if err != nil {
				return nil, err
			}
			if _, _, err = lookupNodeOrNodeInterface(nodeName.String(), nodes); err != nil {
				return nil, doc.ZplScalarErrorf(nodeName,
					"undefined node declared for LAN %q: %q: %v", lanName, nodeName.String(), err)
			}
			nodeNames = append(nodeNames, nodeName)
		}

		lansMap[lanName] = &doc.LANDesc{ZplRef: newZplRef(lanPath), Nodes: nodeNames}

	}

	return lansMap, nil
}

// Parses topology "bridges" block. First arg is path from YAML root to block,
// second arg is parsed network globals, third arg is map of node names to
// parsed node descriptors.
func parseNetworkTopologyBridges(bridgesPath []yt.Node, globals *doc.NetGlobs, nodes map[string]*doc.Component, fussy ErrMode) ([]*doc.Bridge, error) {
	if err := validateLastNodeKind(bridgesPath, yt.SequenceKind); err != nil {
		return nil, err
	}

	bridges := []*doc.Bridge{}

	for _, bridgePath := range childPathSeq(bridgesPath) {
		if err := validateLastNodeKind(bridgePath, yt.MappingKind); err != nil {
			return nil, err
		}

		bridge := doc.Bridge{ZplRef: newZplRef(bridgePath)}

		for key, childPath := range childPathMap(bridgePath) {
			var err error
			switch key {
			case "nodes":
				if err = validateLastNodeKind(childPath, yt.SequenceKind); err != nil {
					return nil, err
				}

				bridge.Nodes = []doc.ZplString{}

				for _, nodeNamePath := range childPathSeq(childPath) {
					nodeName, err := doc.NewZplString(nodeNamePath)
					if err != nil {
						return nil, err
					}
					// In the node list, the name may be just a node id or it may have an interface name on it too.
					if _, _, err := lookupNodeOrNodeInterface(nodeName.String(), nodes); err != nil {
						return nil, doc.ZplScalarErrorf(nodeName, "undefined node declared for bridge: %q: %v", nodeName.String(), err)
					}
					bridge.Nodes = append(bridge.Nodes, nodeName)
				}
				if len(bridge.Nodes) != 2 {
					return nil, yt.PathErrorf(childPath, "exactly two nodes must defined for bridge (found %d)", len(bridge.Nodes))
				}

			case "cost":
				if bridge.Cost, err = doc.NewZplUnsigned(childPath); err != nil {
					return nil, err
				}

			default:
				if err := noteInvalidKey(childPath, fussy); err != nil {
					return nil, err
				}
			}
		}

		if err := checkRequiredKeys(bridgePath, "nodes"); err != nil {
			return nil, err
		}

		if bridge.Cost.Value() == nil {
			bridge.Cost, _ = doc.NewZplUnsigned(doc.DefaultBridgeCost)
		}

		if c := bridge.Cost.Value().(uint64); c <= 0 {
			return nil, doc.ZplScalarErrorf(bridge.Cost, "invalid bridge cost, must be > 0 : %d", c)
		}

		bridges = append(bridges, &bridge)
	}

	return bridges, nil
}

// Parses "communications" block directly into our state doc. First arg is path from YAML root to block.
func (pps *PPState) parseCommunications(commsPath []yt.Node) error {
	if err := validateLastNodeKind(commsPath, yt.MappingKind); err != nil {
		return err
	}

	comms := doc.Communications{ZplRef: newZplRef(commsPath)}
	childPaths := childPathMap(commsPath)
	var err error

	if hierPath, exists := childPaths["hierarchy"]; exists {
		if comms.Hierarchy, err = parseHierarchy(hierPath, pps.fussy); err != nil {
			return err
		}
	} else {
		comms.Hierarchy = []doc.ZplString{}
	}

	rootSystem := &doc.System{
		ID:         doc.MustNewZplString("zpr"),
		Desc:       doc.MustNewZplString("(BUILT IN) root ZPR system"),
		Components: make(map[string]*doc.Component),
	}

	if authServices, err := pps.createZPRAuthServices(); err != nil {
		return err
	} else {
		for k, v := range authServices {
			rootSystem.Components[k] = v
		}
	}

	if visaservice, err := pps.makeVisaService(pps.visaServiceAddress); err != nil {
		return err
	} else {
		rootSystem.Components[visaservice.ID.String()] = visaservice
	}

	// The nodes also get service definitions in the root of the hierarchy.
	// In this case we just refernce the components already defined in the
	// zpr.nodes section.
	for nodeID, nodeC := range pps.doc.Zpr.Nodes {
		rootSystem.Components[nodeID] = nodeC
	}

	// Setup an initial allow block to include all datasources and all services. As the
	// system parser runs these could be reduced.
	allow := &allowBlock{
		dsList: []string{"zpr"},
	}
	for svcID := range pps.doc.Services {
		allow.svcList = append(allow.svcList, svcID)
	}
	for dsID := range pps.doc.Zpr.Datasources {
		allow.dsList = append(allow.dsList, dsID)
	}

	// Pass this already parsed state into the systems parser.
	helper := &sysParseHelper{}
	helper.zprDSNames = append(helper.zprDSNames, allow.dsList...)
	helper.zprServices = pps.doc.Services

	// The systems may define new datasources, they get added here.
	nestedDatasources := make(map[string]*doc.Datasource)

	if rootSystem.Systems, err = parseSystems(commsPath, comms.Hierarchy, helper, allow, &applyBlock{}, nestedDatasources, pps.fussy); err != nil {
		return err
	}

	// convert nested to components and add to our rootSystem
	// TODO: Do we really need that?

	if compmap, err := extDatasourcesToComponents(nestedDatasources, pps.doc.Zpr.Visaservice); err != nil {
		return err
	} else {
		for compID, comp := range compmap {
			if _, dupe := rootSystem.Components[compID]; dupe {
				// Sanity check - this logic should already be enforced by the parseSystems function. So this just
				// catches a programming error.
				panic(fmt.Sprintf("duplicate datasource declaration: %v (prefix=%v)", compID, comp.Auth.AsString()))
			}
			rootSystem.Components[compID] = comp
		}
	}

	// Copy the nested datasources up
	comms.NestedDatasources = make(map[string]*doc.Datasource)
	for dsID, ds := range nestedDatasources {
		comms.NestedDatasources[dsID] = ds
	}

	comms.Systems = make(map[string]*doc.System)
	comms.Systems["root"] = rootSystem

	for key, childPath := range childPaths {
		switch {
		case key == "hierarchy":
		case key == "systems" || len(comms.Hierarchy) > 0 && key == comms.Hierarchy[0].String():
		default:
			if err := noteInvalidKey(childPath, pps.fussy); err != nil {
				return err
			}
		}
	}
	pps.doc.Communications = &comms
	return nil
}

// createZPRAuthServices creates external service definitions for all the
// "external" datasources defined in the zpr area.
// The 'Service.auth' attribute is set to the prefix.
//
// So this will work OK for the global ZPR data sources. But once we allow
// datasources to be set anywhere in the tree, not sure what we will do.
//
// The the Auth attribute references a prefix, we just need a way to lookup
// the prefix from some sort of scoping map (since we want to look up the
// tree for the prefix, and it may be explicitly denied via an allow statement).
func (pps *PPState) createZPRAuthServices() (map[string]*doc.Component, error) {
	external := make(map[string]*doc.Datasource)
	for pfx, ds := range pps.doc.Zpr.Datasources {
		if ds.Endpoint != nil {
			// Ensure that any service referenced here is defined. (TODO: is this redundant?)
			for _, sname := range ds.Endpoint.Services {
				if _, ok := pps.doc.Services[sname]; !ok {
					return nil, doc.ZplScalarErrorf(ds.ZplRef, "invalid service name: %v", sname)
				}
			}
			external[pfx] = ds
		}
	}
	return extDatasourcesToComponents(external, pps.doc.Zpr.Visaservice)
}

// Create the visa service component. The provider is taken from the network.visaservice
// block.  We are setting things up so that the correct adapter will be "providing" the
// visa service to the network.
func (pps *PPState) makeVisaService(visaServiceAddress string) (*doc.Component, error) {
	vs := pps.doc.Zpr.Visaservice
	svc := &doc.Component{
		ZplRef:   vs.ZplRef, // TODO: I can't remember what ZplRef is for...
		ID:       doc.MustNewZplString(polio.VisaServiceName),
		Desc:     doc.MustNewZplString("visa service"),
		Provider: vs.Provider,
		// Auth:
		Address:      doc.MustNewIPv6Address(visaServiceAddress),
		SingleTenant: doc.MustNewZplBoolean(true),
		Decorator:    doc.MustNewZplBoolean(false),
	}

	svc.Services = append(svc.Services, VisaServiceServiceName)
	svc.Policies = append(svc.Policies, VisaServicePolicy)

	svc.Services = append(svc.Services, AdminServiceServiceName)
	svc.Policies = append(svc.Policies, newAdminServicePolicy(vs.Attrs, "visaservice"))
	return svc, nil
}

// extDatasourcesToComponents convert a doc.Datasource into a doc.Component,
// allowing access by visa service.
//
// Note that the `Auth` property on the component is the "prefix".
func extDatasourcesToComponents(ds map[string]*doc.Datasource, vs *doc.Visaservice) (map[string]*doc.Component, error) {
	services := make(map[string]*doc.Component)
	for pfx, ds := range ds {
		if ds.Endpoint == nil {
			return nil, fmt.Errorf("passed a non-external datasource: %v", pfx)
		}

		svc := &doc.Component{
			ZplRef:       ds.ZplRef,
			ID:           doc.MustNewZplString(fmt.Sprintf("%v.%v", pfx, ds.Endpoint.TlsDomain.String())),
			Desc:         doc.MustNewZplString(fmt.Sprintf("external auth datasource %v", pfx)),
			Provider:     ds.Endpoint.Provider,
			Auth:         doc.MustNewZplString(pfx),
			Address:      ds.Endpoint.Address,
			SingleTenant: doc.MustNewZplBoolean(false),
			Decorator:    doc.MustNewZplBoolean(false),
		}
		svc.Services = append(svc.Services, ds.Endpoint.Services...)
		svc.Policies = append(svc.Policies, newDatasourcePolicy(pfx, ds.Endpoint.Services[0], vs.Provider))
		svc.Policies = append(svc.Policies, ds.Endpoint.Policies...)
		services[svc.ID.String()] = svc
	}
	return services, nil
}

// Parses "hierarchy" list. First arg is path from YAML root to block.
func parseHierarchy(hierPath []yt.Node, _ ErrMode) ([]doc.ZplString, error) {
	if err := validateLastNodeKind(hierPath, yt.SequenceKind); err != nil {
		return nil, err
	}

	hierNames := []doc.ZplString{}

	for _, namePath := range childPathSeq(hierPath) {
		if name, err := doc.NewZplString(namePath); err != nil {
			return nil, err
		} else if err := doc.AssertValidHierarchy(name.String()); err != nil {
			return nil, doc.ZplScalarErrorf(name, "%w", err)
		} else {
			hierNames = append(hierNames, name)
		}

	}

	return hierNames, nil
}

// sysParseHelper is some info from the parser that we need to parse the systems blocks.
// This is setup once and is then read-only.
type sysParseHelper struct {
	zprDSNames  []string                // the ZPR root datasource names (prefixes)
	zprServices map[string]*doc.Scoping // the full services list
}

// Parses a "systems" block if one exists at a given level of the system
// hierarchy. First arg is path from global YAML root to initial parent node
// ("communications" for the top level, an individual system block otherwise),
// second arg is sequence of hierarchy names from parent node downward, third
// arg is previously parsed network structure (examined for validation
// purposes). Returns a map of system IDs to System structs for all systems
// defined in the "systems" block. The map is empty if no "systems" block is
// found or if one is found but it is empty. This function assumes all
// system-level explicit defaults and service-level implicit defaults have
// already been analyzed and used to augment the YAML tree where applicable.
func parseSystems(parentPath []yt.Node, hierarchy []doc.ZplString, helper *sysParseHelper, parentAllow *allowBlock, parentApply *applyBlock, nestedDatasources map[string]*doc.Datasource, fussy ErrMode) (map[string]*doc.System, error) {
	var err error
	var hierarchyExists bool
	var hierarchyHead doc.ZplString
	var hierarchyTail []doc.ZplString
	if len(hierarchy) == 0 {
		hierarchyTail = []doc.ZplString{}
	} else {
		hierarchyExists = true
		hierarchyHead = hierarchy[0]
		hierarchyTail = hierarchy[1:]
	}

	// The "systems" block's key may be either "systems" or the next available
	// hierarchy name.
	var systemsPath []yt.Node
	for key, childPath := range childPathMap(parentPath) {
		if key == "systems" || hierarchyExists && key == hierarchyHead.String() {
			if systemsPath != nil {
				return nil, yt.PathErrorf(childPath, `both "systems" and hierarchy key %q defined`, hierarchy[0].String())
			} else {
				systemsPath = childPath
			}
		}
	}

	systemMap := make(map[string]*doc.System) // sys ID -> system

	if systemsPath != nil {
		if err := validateLastNodeKind(systemsPath, yt.MappingKind); err != nil {
			return nil, err
		}

		// The children of the "systems" block are the individual systems OR could be a special "allow" or
		// "apply" block.

		var childAllow *allowBlock
		var childApply *applyBlock

		children := childPathMap(systemsPath)

		if spath, ok := children["allow"]; ok {
			childAllow, err = parseAllow(spath, parentAllow, DSAlwaysAllow, fussy)
			if err != nil {
				return nil, err
			}
		} else {
			childAllow = parentAllow.Copy()
		}
		if spath, ok := children["apply"]; ok {
			// Note that the apply block uses the PARENT allow, not one defined at this level.
			childApply, err = parseApply(spath, parentApply, parentAllow, fussy)
			if err != nil {
				return nil, err
			}

		} else {
			childApply = parentApply.Copy()
		}

		for systemId, systemPath := range children {
			if doc.AssertValidID(systemId) != nil {
				return nil, yt.PathErrorf(systemPath, "not a valid system identifier: %q", systemId)
			}
			switch systemId {
			case "allow", "apply":
				// already done
			default:
				if system, err := parseSystem(systemPath, hierarchyTail, helper, childAllow, childApply, nestedDatasources, fussy); err != nil {
					return nil, err
				} else {
					if hierarchyExists {
						system.Hierarchy = hierarchyHead
					}
					systemMap[systemId] = system
				}
			}
		}
	}

	return systemMap, nil
}

// Parses a system block (i.e., a child of a "systems" block). First arg is path
// from global YAML root to system block. Second arg is hierarchy name list to
// use for any descendant systems. Remaining args are as for parseSystems.
// Caller is responsible for setting the Hierarchy field of the returned System
// struct.
func parseSystem(sysPath []yt.Node, hierarchy []doc.ZplString, helper *sysParseHelper, parentAllow *allowBlock, parentApply *applyBlock, nestedDatasources map[string]*doc.Datasource, fussy ErrMode) (*doc.System, error) {
	if err := validateLastNodeKind(sysPath, yt.MappingKind); err != nil {
		return nil, err
	}

	sys := doc.System{ZplRef: newZplRef(sysPath)}
	var err error

	sys.ID = newKeyZplString(sysPath)
	sys.Components = make(map[string]*doc.Component)
	nestedAllow := parentAllow.Copy() // start with the allow block passed in.
	nestedApply := parentApply.Copy()

	children := childPathMap(sysPath)

	// Pass 1 - Pick up allow and apply, as they may be immidiately applicable.
	for key, childPath := range children {
		switch key {
		case "allow":
			if nestedAllow, err = parseAllow(childPath, parentAllow, DSAlwaysAllow, fussy); err != nil {
				return nil, err
			}
		case "apply":
			if nestedApply, err = parseApply(childPath, parentApply, parentAllow, fussy); err != nil {
				return nil, err
			}
		}
	}

	// Pass 2 - datasources
	if dsChildPath, ok := children["datasources"]; ok {
		// A scoped datasource. Datasources here can only be referenced
		// within or below this system.

		existingDSNames := make(map[string]bool)
		for _, n := range helper.zprDSNames {
			existingDSNames[n] = true
		}
		for pfx := range nestedDatasources {
			existingDSNames[pfx] = true
		}

		if dsblock, err := parseDatasourcesBlock(dsChildPath, helper.zprServices, existingDSNames, true, nestedAllow, nestedApply, fussy); err != nil {
			return nil, err
		} else {
			for pfx, ds := range dsblock {
				nestedDatasources[pfx] = ds
				// New datasources must be added to the allow.
				nestedAllow.dsList = append(nestedAllow.dsList, pfx)
			}
		}
	}

	// Pass 3 - all the rest
	for key, childPath := range children {
		switch key {
		case "allow", "apply", "datasources":
			// handled above

		case "desc":
			if sys.Desc, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			}
		case "services":
			return nil, yt.PathErrorf(childPath, "'services' block has been renamed to 'components'")

		case "components":
			if isLastNodeEmpty(childPath) {
				// TODO: No components?
				continue
			}
			if err := validateLastNodeKind(childPath, yt.MappingKind); err != nil {
				return nil, err
			}

			componentChildren := childPathMap(childPath)
			compNestedAllow := nestedAllow
			compNestedApply := nestedApply
			for svcId, svcPath := range componentChildren {
				switch svcId {
				case "allow":
					if compNestedAllow, err = parseAllow(svcPath, nestedAllow, DSAlwaysAllow, fussy); err != nil {
						return nil, err
					}

				case "apply":
					if compNestedApply, err = parseApply(childPath, nestedApply, nestedAllow, fussy); err != nil {
						return nil, err
					}
				}
			}

			for svcId, svcPath := range componentChildren {
				// It is permitted to put an allow or apply right in the component map.
				if svcId == "allow" || svcId == "apply" {
					continue // handled above
				}

				if doc.AssertValidID(svcId) != nil {
					return nil, yt.PathErrorf(svcPath, "not a valid service identifier: %q", svcId)
				}
				if svc, err := parseComponent(svcPath, compNestedAllow, compNestedApply, fussy, []string{"desc", "provider"}); err != nil {
					return nil, err
				} else {
					// This duplicate check probably unnecessary since I believe the
					// YAML parser only returns one map element.
					if _, dupe := sys.Components[svcId]; dupe {
						return nil, yt.PathErrorf(svcPath, "duplicate component: %v", svcId)
					}
					sys.Components[svcId] = svc
				}
			}

		default:
			if !(key == "systems" || len(hierarchy) > 0 && key == hierarchy[0].String()) {
				if err := noteInvalidKey(childPath, fussy); err != nil {
					return nil, err
				}
			}
		}
	}

	if err = checkRequiredKeys(sysPath, "desc"); err != nil {
		return nil, err
	}

	// Now recurse parse my own self if there is a systems tag present.
	// Any datasources defined at this level or above should be passed down, but when we return
	// those datasources are not valid in sibling branches.
	if sys.Systems, err = parseSystems(sysPath, hierarchy, helper, nestedAllow, nestedApply, nestedDatasources, fussy); err != nil {
		return nil, err
	}

	return &sys, nil
}

// parseAllow parses an "allow" block. The passed `services` and `datasources` are the set of
// services and datasources which are currently allowed (at this parsing level).
func parseAllow(svcPath []yt.Node, parentAllow *allowBlock, alwaysAllowDS []string, fussy ErrMode) (*allowBlock, error) {
	if err := validateLastNodeKind(svcPath, yt.MappingKind); err != nil {
		return nil, err
	}
	var dsPresent, svcPresent bool
	ab := &allowBlock{}
	for key, childPath := range childPathMap(svcPath) {
		switch key {
		case "datasources":
			dsPresent = true
			if names, err := parseStringList(childPath, fussy); err != nil {
				return nil, err
			} else {
				for _, dsname := range names {
					if slices.Index(parentAllow.dsList, dsname) < 0 {
						return nil, yt.PathErrorf(childPath, "datasource not allowed here: %v", dsname)
					}
					ab.dsList = append(ab.dsList, dsname)
				}
			}
		case "services":
			svcPresent = true
			if names, err := parseStringList(childPath, fussy); err != nil {
				return nil, err
			} else {
				for _, sname := range names {
					if slices.Index(parentAllow.svcList, sname) < 0 {
						return nil, yt.PathErrorf(childPath, "service not allowed here: %v", sname)
					}
					// If the name exists in the list of allowed services (which may itself be clamped down), we add it
					// to the list of scoped services.
					ab.svcList = append(ab.svcList, sname)
				}
			}
		default:
			if err := noteInvalidKey(childPath, fussy); err != nil {
				return nil, err
			}
		}
	}

	// If user did not include the datasources or services blocks, then we "inherit" the list that was passed in.
	if !dsPresent {
		ab.dsList = append(ab.dsList, parentAllow.dsList...)
	}
	if !svcPresent {
		ab.svcList = append(ab.svcList, parentAllow.svcList...)
	}

	// Finally, if any datasources are always allowed, add them here.
	for _, a := range alwaysAllowDS {
		if slices.Index(ab.dsList, a) < 0 {
			ab.dsList = append(ab.dsList, a)
		}
	}

	return ab, nil
}

func parseApply(svcPath []yt.Node, parentApply *applyBlock, parentAllow *allowBlock, fussy ErrMode) (*applyBlock, error) {
	if err := validateLastNodeKind(svcPath, yt.MappingKind); err != nil {
		return nil, err
	}

	// Start witht he parent apply block
	ab := &applyBlock{}
	ab.conditions = append(ab.conditions, parentApply.conditions...)

	for key, childPath := range childPathMap(svcPath) {
		switch key {
		case "conditions":
			if conds, err := parseConditionSequence(childPath, parentAllow.dsList, DSCheckOn, fussy); err != nil {
				return nil, err
			} else {
				ab.conditions = append(ab.conditions, conds...)
			}
		default:
			if err := noteInvalidKey(childPath, fussy); err != nil {
				return nil, err
			}
		}
	}

	// Now do a quick sanity check (will not catch everything...)
	var allExprs []*doc.AttrExpr
	for _, c := range ab.conditions {
		allExprs = append(allExprs, c.AttrExprs...)
	}
	if conflict := checkAttributeExpressionsForConflicts(allExprs); conflict != "" {
		return nil, yt.PathErrorf(svcPath, "apply results in policy condition conflict on key: %v", conflict)
	}

	return ab, nil
}

// Parses a component (was called service) block. First arg is path from YAML
// root to block, second arg is parsed network structure.
// TODO: remove network arg
//
// `services` is the set of allowed services (possibly modified by an allow block).
func parseComponent(svcPath []yt.Node, allow *allowBlock, apply *applyBlock, fussy ErrMode, reqkeys []string) (*doc.Component, error) {
	if err := validateLastNodeKind(svcPath, yt.MappingKind); err != nil {
		return nil, err
	}

	childMap := childPathMap(svcPath)
	svc := doc.Component{
		ZplRef:       newZplRef(svcPath),
		ID:           newKeyZplString(svcPath),
		SingleTenant: doc.MustNewZplBoolean(false),
		Decorator:    doc.MustNewZplBoolean(false),
	}
	var err error

	// Before we can parse the polices, we need to parse the component services.
	if childPath, ok := childMap["services"]; ok {
		if names, err := parseStringList(childPath, fussy); err != nil {
			return nil, err
		} else {
			for _, sname := range names {
				if slices.Index(allow.svcList, sname) < 0 {
					return nil, doc.ZplScalarErrorf(svc.ZplRef, "component references undefined or disallowed service: %v", sname)
				}
			}
			svc.Services = names
		}
	}

	for key, childPath := range childMap {
		switch key {
		case "desc":
			if svc.Desc, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			}
		case "services":
			// parsed already above.
		case "key":
			if svc.Key, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			}
			if err := doc.AssertValidNoisePK(svc.Key.AsString()); err != nil {
				return nil, err
			}
		case "provider":
			if svc.Provider, err = parseAttrExprSequence(childPath, allow.dsList, fussy); err != nil {
				return nil, err
			}
			for _, attrExpr := range svc.Provider {
				key := attrExpr.Key.String()
				op := attrExpr.Op.String()
				if key == defs.KAttrAuthority && !(op == doc.AttrExprOpEq || op == doc.AttrExprOpHas) {
					return nil, doc.ZplScalarErrorf(attrExpr.ZplRef, "provider attribute expression with %q key requires %q or %q operator (found %q)",
						key, doc.AttrExprOpHas, doc.AttrExprOpEq, op)
				}
			}
		case "address":
			if len(svc.AddressSet) > 0 {
				return nil, yt.PathErrorf(childPath, "cannot use both address and address_set")
			}
			if svc.Address, err = doc.NewIPv6Address(childPath); err != nil {
				return nil, err
			}
			if err = doc.AssertValidZPRAddress(svc.Address.String()); err != nil {
				return nil, doc.ZplScalarErrorf(svc.Address, "invalid service address: %w", err)
			}
		case "address_set":
			if !svc.Address.Empty() {
				return nil, yt.PathErrorf(childPath, "cannot use both address and address_set")
			}
			if err = validateLastNodeKind(childPath, yt.SequenceKind); err != nil {
				return nil, err
			}
			for _, addrPath := range childPathSeq(childPath) {
				if addr, err := doc.NewIPv6Address(addrPath); err != nil {
					return nil, err
				} else if err = doc.AssertValidZPRAddress(addr.String()); err != nil {
					return nil, doc.ZplScalarErrorf(addr, "invalid service address: %w", err)
				} else {
					svc.AddressSet = append(svc.AddressSet, addr)
				}
			}
			if len(svc.AddressSet) < 1 {
				return nil, yt.PathErrorf(childPath, "cannot have empty address_set")
			}
			if len(svc.AddressSet) < 2 {
				return nil, yt.PathErrorf(childPath, "cannot have address_set with only one entry, use address instead")
			}
		case "address_pool":
			if err := warnNotImpl("component.address_pool", childPath, fussy); err != nil {
				return nil, err
			}
		case "single_tenant":
			// Means that the address must be unique to this component. Ideally this would be passed to
			// the embodiment through policy but for now we only enforce this at compile time. If
			// single_tenant is used, user MUST specify an address and not use it anywhere else.
			if svc.SingleTenant, err = doc.NewZplBoolean(childPath); err != nil {
				return nil, err
			}

		case "decorator":
			if svc.Decorator, err = doc.NewZplBoolean(childPath); err != nil {
				return nil, err
			}

		case "policies":
			if err := validateLastNodeKind(childPath, yt.SequenceKind); err != nil {
				return nil, err
			}
			policiesWithServices := 0
			for _, polPath := range childPathSeq(childPath) {
				if pol, err := ParsePolicy(polPath, svc.Services, allow.dsList, DSCheckOn, apply, fussy); err != nil {
					return nil, err
				} else {
					if len(pol.Services) > 0 {
						policiesWithServices++
					}
					svc.Policies = append(svc.Policies, pol)
				}
			}
			if policiesWithServices > 0 && (len(svc.Policies) != policiesWithServices) {
				return nil, yt.PathErrorf(childPath, "if any policy a component has a services block then all must have a services block")
			}

		default:
			if key != "interfaces" { // "interfaces" allowed on nodes
				if err := noteInvalidKey(childPath, fussy); err != nil {
					return nil, err
				}
			}
		}
	}

	// Prevent user from setting zpr.addr AND an address or address_set
	if len(svc.Provider) > 0 && (len(svc.AddressSet) > 0 || !svc.Address.Empty()) {
		for _, exp := range svc.Provider {
			if exp.Key.AsString() == defs.KAttrEPID {
				// Allow it only if the address is the same as address setting.
				if svc.Address.Empty() {
					return nil, yt.PathErrorf(svcPath, "cannot use %v and address_set on %v", defs.KAttrEPID, svc.ID.AsString())
				}
				expValue, err := doc.NewIPv6Address(exp.Value.String())
				if err != nil {
					return nil, yt.PathErrorf(svcPath, "provider value %v must be an address %v", defs.KAttrEPID, svc.ID.AsString())
				}
				if expValue.String() != svc.Address.AsString() {
					return nil, yt.PathErrorf(svcPath, "provider %v must match address for %v", defs.KAttrEPID, svc.ID.AsString())
				}
			}
		}
	}

	// Single-tenant is not allowed with address_set
	if svc.SingleTenant.AsBool() && len(svc.AddressSet) > 0 {
		return nil, yt.PathErrorf(svcPath, "single-tenant cannot be used with address_set: %v", svc.ID.AsString())
	}

	// If user has set zpr.addr and not address, set address from the attribute.
	if len(svc.Provider) > 0 && svc.Address.Empty() {
		for _, exp := range svc.Provider {
			if exp.Key.AsString() == defs.KAttrEPID {
				svc.Address, err = doc.NewZplString(exp.Value.String())
				if err != nil {
					return nil, doc.ZplScalarErrorf(exp.Value, "invalid service address value for %v", svc.ID.AsString())
				}
			}
		}
	}

	if len(svc.Policies) == 0 && len(apply.conditions) > 0 {
		// No policues declared in the yaml, but there is an active apply block,
		// so use that to construct a policy with the apply conditions.
		svc.Policies = append(svc.Policies, newPolicyFromApply(svcPath, apply))
	}

	if err = checkRequiredKeys(svcPath, reqkeys...); err != nil {
		return nil, err
	}

	// This used to check scopes, but now not relevant
	//var loadedPolicies []*doc.Policy
	//for _, lp := range svc.Policies {
	//	if dupe, idx := policyExists(lp, loadedPolicies); dupe {
	//		return nil, fmt.Errorf("duplicate policy: '%v' is equivalent to '%v'", loadedPolicies[idx].Desc, lp.Desc)
	//	}
	//	loadedPolicies = append(loadedPolicies, lp)
	//}

	return &svc, nil
}

// Parses a sequence of attribute expressions. First arg is path from YAML root
// to sequence. This ensures that all expressions use only allowed datasources.
func parseAttrExprSequence(seqPath []yt.Node, allowedDatasources []string, fussy ErrMode) ([]*doc.AttrExpr, error) {
	return parseAttrExprSequenceOptCheck(seqPath, allowedDatasources, DSCheckOn, fussy)
}

func parseAttrExprSequenceAnyDS(seqPath []yt.Node, fussy ErrMode) ([]*doc.AttrExpr, error) {
	return parseAttrExprSequenceOptCheck(seqPath, nil, DSCheckOff, fussy)
}

// Parses a sequence of attribute expressions. First arg is path from YAML root
// to sequence. If `checkDSEnable` is set true then this ensures that all expressions
// use only allowed datasources from the `allowedDatasoruces` list.
func parseAttrExprSequenceOptCheck(seqPath []yt.Node, allowedDatasources []string, checkDS DSChecking, _ ErrMode) ([]*doc.AttrExpr, error) {
	if err := validateLastNodeKind(seqPath, yt.SequenceKind); err != nil {
		return nil, err
	}

	attrExprs := []*doc.AttrExpr{}

	for _, childPath := range childPathSeq(seqPath) {
		if attrExpr, err := parseAttrExpr(childPath); err != nil {
			return nil, err
		} else {
			attrExprs = append(attrExprs, attrExpr)
		}
	}

	if badKey := checkAttributeExpressionsForConflicts(attrExprs); badKey != "" {
		return nil, yt.PathErrorf(seqPath, "attribute expression list contains conflicting or redundant expressions for key %q", badKey)
	}

	if checkDS == DSCheckOn {
		for _, ae := range attrExprs {
			key := ae.Key.AsString()
			bits := strings.Split(key, ".")
			if len(bits) < 2 {
				return nil, yt.PathErrorf(seqPath, "attribute key lacks data source: %v", key)
			}
			if slices.Index(allowedDatasources, bits[0]) < 0 {
				return nil, yt.PathErrorf(seqPath, "datasource not in scope: %v", key)
			}
			// Special case: zpr.authority references a datasource.
			if key == defs.KAttrAuthority {
				switch ae.Op.AsString() {
				case doc.AttrExprOpEq:
					// Checking authority EQ, then the datasource must be allowed
					if slices.Index(allowedDatasources, ae.Value.String()) < 0 {
						return nil, yt.PathErrorf(seqPath, "datasource '%v' not in scope: %v", ae.Value.String(), key)
					}
				case doc.AttrExprOpHas:
					// In a has, then all the sources must be allowed:
					for _, dsname := range strings.Split(ae.Value.String(), ",") {
						if slices.Index(allowedDatasources, strings.TrimSpace(dsname)) < 0 {
							return nil, yt.PathErrorf(seqPath, "datasource '%v' not in scope: %v", dsname, key)
						}
					}
				}
			}
		}
	}

	return attrExprs, nil
}

// Parses a single attribute expression. Arg is path from YAML root.
func parseAttrExpr(exprPath []yt.Node) (*doc.AttrExpr, error) {
	if err := validateLastNodeKind(exprPath, yt.SequenceKind); err != nil {
		return nil, err
	}

	zplRef := newZplRef(exprPath)
	fieldNodes := lastNode(exprPath).Value().([]yt.Node)

	// TODO For the time being allow the older two-element form of attribute
	// expressions (with "eq" assumed for the operator), but print a warning.
	if len(fieldNodes) == 2 {
		keyPath := yt.AppendToPathCopy(exprPath, fieldNodes[0])
		valPath := yt.AppendToPathCopy(exprPath, fieldNodes[1])

		if key, err := doc.NewZplString(keyPath); err != nil {
			return nil, yt.PathErrorf(keyPath, "invalid attribute expression key: %w", err)
		} else if val, err := doc.NewZplString(valPath); err != nil {
			return nil, yt.PathErrorf(valPath, "invalid attribute expression value: %w", err)
		} else {
			op, _ := doc.NewZplString(doc.AttrExprOpEq)
			fmt.Fprintf(os.Stderr, "warning: two-element attribute expressions are deprecated %s\n",
				yt.PathErrorf(exprPath, "interpreting [%v, %v] as [%v, %v, %v]", key, val, key, op, val).Error())
			attrExpr := doc.AttrExpr{zplRef, key, op, val}
			if err = doc.AssertValidAttrExpr(&attrExpr); err != nil {
				return nil, yt.PathErrorf(exprPath, "invalid attribute expression: %w", err)
			}
			return &attrExpr, nil
		}
	}

	if len(fieldNodes) != 3 {
		return nil, yt.PathErrorf(exprPath, "an attribute expression must have 3 elements (key, operator, value)")
	}
	keyPath := yt.AppendToPathCopy(exprPath, fieldNodes[0])
	opPath := yt.AppendToPathCopy(exprPath, fieldNodes[1])
	valPath := yt.AppendToPathCopy(exprPath, fieldNodes[2])

	if key, err := doc.NewZplString(keyPath); err != nil {
		return nil, yt.PathErrorf(keyPath, "invalid attribute expression key: %w", err)
	} else if op, err := doc.NewZplString(opPath); err != nil {
		return nil, yt.PathErrorf(opPath, "invalid attribute expression operator: %w", err)
	} else if val, err := doc.NewZplScalar(valPath); err != nil {
		return nil, yt.PathErrorf(valPath, "invalid attribute expression value: %w", err)
	} else {
		attrExpr := doc.AttrExpr{zplRef, key, op, val}
		if err = doc.AssertValidAttrExpr(&attrExpr); err != nil {
			return nil, yt.PathErrorf(exprPath, "invalid attribute expression: %w", err)
		}
		return &attrExpr, nil
	}
}

func newPolicyFromApply(compPath []yt.Node, apply *applyBlock) *doc.Policy {
	pol := doc.Policy{ZplRef: newZplRef(compPath)}
	pol.Desc = doc.MustNewZplString(fmt.Sprintf("policy generated by apply for %v", pol.ZplRef.String()))
	pol.Conditions = append(pol.Conditions, apply.conditions...)
	return &pol
}

// Parses a connection policy block. First arg is path from YAML root to block.
// If the apply block is non-nil, the conditions in there are added into the policy.
func ParsePolicy(polPath []yt.Node, allowedServices, allowedDatasources []string, checkDS DSChecking, apply *applyBlock, fussy ErrMode) (*doc.Policy, error) {
	if err := validateLastNodeKind(polPath, yt.MappingKind); err != nil {
		return nil, err
	}

	pol := doc.Policy{ZplRef: newZplRef(polPath)}

	for key, childPath := range childPathMap(polPath) {
		var err error
		switch key {
		case "desc":
			if pol.Desc, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			}
		case "id":
			if pol.ID, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			} else if err = doc.AssertValidID(pol.ID.String()); err != nil {
				return nil, doc.ZplScalarErrorf(pol.ID, "invalid policy ID: %w", err)
			} else if strings.HasPrefix(pol.ID.String(), "zpr.") {
				return nil, doc.ZplScalarErrorf(pol.ID, "policy ID cannot use reserved 'zpr.' prefix")
			}
		case "conditions":
			if pol.Conditions, err = parseConditionSequence(childPath, allowedDatasources, checkDS, fussy); err != nil {
				return nil, err
			}
			// Check for attribute expression consistency across all conditions
			allExprs := []*doc.AttrExpr{}
			for _, c := range pol.Conditions {
				for _, e := range c.AttrExprs {
					allExprs = append(allExprs, e)
				}
			}
			if badKey := checkAttributeExpressionsForConflicts(allExprs); badKey != "" {
				return nil, yt.PathErrorf(childPath, "conditions contain conflicting or redundant attribute expressions for key %q", badKey)
			}
		case "constraints":
			if pol.Constraints, err = parseConstraints(childPath, fussy); err != nil {
				return nil, err
			}
		case "services":
			// Optional, and allows a policy to restrict to a subset of component services.
			// Expects a list of service names.
			svcNames, err := parseStringList(childPath, fussy)
			if err != nil {
				return nil, err
			}
			if len(svcNames) == 0 {
				return nil, yt.PathErrorf(childPath, `"services" must not be empty, but can be omitted`)
			}
			// Now ensure that svcNames are all included in parent service list.
			for _, sn := range svcNames {
				matched := false
				for _, allowed := range allowedServices {
					if allowed == sn {
						matched = true
						break
					}
				}
				if !matched {
					return nil, yt.PathErrorf(childPath, `service "%v" is not allowed by parent`, sn)
				}
			}
			pol.Services = svcNames

		default:
			if err := noteInvalidKey(polPath, fussy); err != nil {
				return nil, err
			}
		}
	}

	// It is possible that the apply block is the only place conditions are introduced.
	if apply != nil {
		pol.Conditions = append(pol.Conditions, apply.conditions...)

		// Check for attribute expression consistency across all conditions
		allExprs := []*doc.AttrExpr{}
		for _, c := range pol.Conditions {
			allExprs = append(allExprs, c.AttrExprs...)
		}
		if badKey := checkAttributeExpressionsForConflicts(allExprs); badKey != "" {
			return nil, yt.PathErrorf(polPath, "conditions contain conflicting or redundant attribute expressions for key %q", badKey)
		}
	}

	if err := checkRequiredKeys(polPath, "desc"); err != nil {
		return nil, err
	}

	if len(pol.Conditions) == 0 {
		return nil, yt.PathErrorf(polPath, "policy with empty conditions")
	}

	return &pol, nil
}

// Parses a "scope" sequence. First arg is path from YAML root to sequence.
func parseScopeSequence(seqPath []yt.Node, fussy ErrMode) ([]*doc.Scoping, error) {
	if err := validateLastNodeKind(seqPath, yt.SequenceKind); err != nil {
		return nil, err
	}
	scopes := []*doc.Scoping{}
	for _, scopePath := range childPathSeq(seqPath) {
		if scopeEl, err := parseScoping(scopePath, fussy); err != nil {
			return nil, err
		} else {
			scopes = append(scopes, scopeEl)
		}
	}
	return scopes, nil
}

func parseScoping(scopePath []yt.Node, fussy ErrMode) (*doc.Scoping, error) {
	if err := validateLastNodeKind(scopePath, yt.MappingKind); err != nil {
		return nil, err
	}

	scoping := doc.Scoping{ZplRef: newZplRef(scopePath)}

	for key, childPath := range childPathMap(scopePath) {
		var err error
		switch key {
		case "desc":
			// ignore, for human use only
		case "tcp":
			if scoping.TCP, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			} else if err = doc.AssertValidTcpUdpPortType(scoping.TCP.String()); err != nil {
				return nil, doc.ZplScalarErrorf(scoping.TCP, "invalid TCP port specification: %w", err)
			}
		case "udp":
			if scoping.UDP, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			} else if err = doc.AssertValidTcpUdpPortType(scoping.UDP.String()); err != nil {
				return nil, doc.ZplScalarErrorf(scoping.UDP, "invalid UDP port specification: %w", err)
			}
		case "icmp":
			if err = validateLastNodeKind(childPath, yt.MappingKind); err != nil {
				return nil, err
			}
			scoping.ICMP = &doc.ScopeICMP{ZplRef: newZplRef(childPath)}
			for icmpKey, icmpValPath := range childPathMap(childPath) {
				switch icmpKey {
				case "type":
					if scoping.ICMP.Type, err = doc.NewZplString(icmpValPath); err != nil {
						return nil, err
					} else {
						switch scoping.ICMP.Type.String() {
						case doc.ICMPOnce, doc.ICMPReqRep:
						default:
							return nil, doc.ZplScalarErrorf(scoping.ICMP.Type, "invalid ICMP type: %w", err)
						}
					}
				case "type_codes":
					if scoping.ICMP.TypeCodes, err = doc.NewZplString(icmpValPath); err != nil {
						return nil, err
					} else if err := doc.AssertValidIcmpType(scoping.ICMP.TypeCodes.String()); err != nil {
						return nil, doc.ZplScalarErrorf(scoping.ICMP.TypeCodes, "invalid ICMP type codes: %w", err)
					}
				default:
					if err := noteInvalidKey(icmpValPath, fussy); err != nil {
						return nil, err
					}
				}
			}
			if err = checkRequiredKeys(childPath, "type", "type_codes"); err != nil {
				return nil, err
			}
		default:
			if err := noteInvalidKey(childPath, fussy); err != nil {
				return nil, err
			}
		}
	}
	return &scoping, nil
}

// Parses a "conditions" sequence. First arg is path from YAML root to sequence.
func parseConditionSequence(seqPath []yt.Node, allowedDS []string, checkDS DSChecking, fussy ErrMode) ([]*doc.Condition, error) {
	if err := validateLastNodeKind(seqPath, yt.SequenceKind); err != nil {
		return nil, err
	}

	conds := []*doc.Condition{}

	for _, condPath := range childPathSeq(seqPath) {
		if err := validateLastNodeKind(condPath, yt.MappingKind); err != nil {
			return nil, err
		}

		cond := doc.Condition{ZplRef: newZplRef(condPath)}

		for key, childPath := range childPathMap(condPath) {
			var err error
			switch key {
			case "desc":
				if cond.Desc, err = doc.NewZplString(childPath); err != nil {
					return nil, err
				}
			case "id":
				if cond.ID, err = doc.NewZplString(childPath); err != nil {
					return nil, err
				} else if err = doc.AssertValidID(cond.ID.String()); err != nil {
					return nil, doc.ZplScalarErrorf(cond.ID, "invalid condition ID: %w", err)
				}
			case "attrs":
				if cond.AttrExprs, err = parseAttrExprSequenceOptCheck(childPath, allowedDS, checkDS, fussy); err != nil {
					return nil, err
				}
			default:
				if err := noteInvalidKey(childPath, fussy); err != nil {
					return nil, err
				}
			}
		}

		if err := checkRequiredKeys(condPath, "attrs"); err != nil {
			return nil, err
		}

		conds = append(conds, &cond)
	}

	return conds, nil
}

// Parses a "constraints" block. First arg is path from YAML root to block.
func parseConstraints(consPath []yt.Node, fussy ErrMode) (*doc.Constraint, error) {
	if err := validateLastNodeKind(consPath, yt.MappingKind); err != nil {
		return nil, err
	}

	cons := doc.Constraint{ZplRef: newZplRef(consPath)}

	for key, childPath := range childPathMap(consPath) {
		var err error
		switch key {
		case "bandwidth":
			if cons.Bandwidth, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			} else if _, err = doc.ParseBandwidthType(cons.Bandwidth.String()); err != nil {
				return nil, doc.ZplScalarErrorf(cons.Bandwidth, "invalid bandwidth constraint: %w", err)
			}
		case "duration":
			if cons.Duration, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			} else if _, err = doc.ParseDurationType(cons.Duration.String()); err != nil {
				return nil, doc.ZplScalarErrorf(cons.Duration, "invalid duration constraint: %w", err)
			}
		case "actor_limit":
			if cons.ActorLimit, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			} else if _, _, err = doc.ParseCapacityType(cons.ActorLimit.String()); err != nil {
				return nil, doc.ZplScalarErrorf(cons.ActorLimit, "invalid actor limit constraint: %w", err)
			}
		default:
			if err := noteInvalidKey(childPath, fussy); err != nil {
				return nil, err
			}
		}
	}

	return &cons, nil
}

// Parses a "certificate" block. First arg is path from YAML root to block.
func parseCertificate(certPath []yt.Node, fussy ErrMode) (*doc.Certificate, error) {
	if err := validateLastNodeKind(certPath, yt.MappingKind); err != nil {
		return nil, err
	}

	cert := doc.Certificate{ZplRef: newZplRef(certPath)}

	for key, childPath := range childPathMap(certPath) {
		var err error
		switch key {
		case "encoding":
			if cert.Encoding, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			} else if strings.ToLower(cert.Encoding.String()) != "pem" {
				return nil, doc.ZplScalarErrorf(cert.Encoding, "unsupported certificate encoding: %q", cert.Encoding.String())
			}
		case "cert_data":
			if cert.CertData, err = doc.NewZplString(childPath); err != nil {
				return nil, err
			} else if blk, _ := pem.Decode([]byte(linePadRe.ReplaceAllString(cert.CertData.String(), ""))); blk == nil {
				return nil, doc.ZplScalarErrorf(cert.CertData, "pem decode of certificate failed")
			}
		default:
			if err := noteInvalidKey(childPath, fussy); err != nil {
				return nil, err
			}
		}
	}

	if err := checkRequiredKeys(certPath, "encoding", "cert_data"); err != nil {
		return nil, err
	}

	return &cert, nil
}

var (
	linePadRe = regexp.MustCompile(`(?m)(^\s+|\s+$)`) // space at starts and ends of lines
)

// Returns paths to a mapping node's children indexed by their mapping keys.
// Assumes the final node of the argument path is a mapping node (panics if
// not) and returns a map of its children's keys to paths to the corresponding
// children.
func childPathMap(parentPath []yt.Node) map[string][]yt.Node {
	if err := validateLastNodeKind(parentPath, yt.MappingKind); err != nil {
		panic(err.Error())
	} else {
		nodeMap := lastNode(parentPath).Value().(map[string]yt.Node)
		pathMap := make(map[string][]yt.Node, len(nodeMap))
		for key, child := range nodeMap {
			pathMap[key] = yt.AppendToPathCopy(parentPath, child)
		}
		return pathMap
	}
}

// Returns paths to a sequence node's children in their original order.
// Assumes the final node of the argument path is a sequewnce node (panics
// if not) and returns a slice containing paths to all its children.
func childPathSeq(parentPath []yt.Node) [][]yt.Node {
	if err := validateLastNodeKind(parentPath, yt.SequenceKind); err != nil {
		panic(err.Error())
	} else {
		nodeSeq := lastNode(parentPath).Value().([]yt.Node)
		pathSeq := make([][]yt.Node, len(nodeSeq))
		for i, child := range nodeSeq {
			pathSeq[i] = yt.AppendToPathCopy(parentPath, child)
		}
		return pathSeq
	}
}

// Prints one-line warning to stderr saying the specified child node is mapped
// under an invalid key in its parent if the second argument is true. Panics
// if the argument path is too short or if its final node is not the child of
// a mapping.
func noteInvalidKey(childPath []yt.Node, fussy ErrMode) error {
	var msg string
	if fussy > ErrModeSilent {
		key, err := tryLastNodeKey(childPath)
		if err == nil {
			msg = fmt.Sprintf("warning: ignoring invalid mapping key %q %s\n", key, yt.PathErrorf(childPath, "").Error())
		} else {
			msg = fmt.Sprintf("warning: ignoring invalid mapping key ?UNK? %s\n", yt.PathErrorf(childPath, "").Error())
		}
		fmt.Fprint(os.Stderr, msg)
	}
	if fussy >= ErrModeError {
		return yt.PathErrorf(childPath, msg)
	}
	return nil
}

func warnNotImpl(propName string, childPath []yt.Node, fussy ErrMode) error {
	msg := fmt.Sprintf("warning: '%s' is not yet implemented %s\n", propName, yt.PathErrorf(childPath, "").Error())
	if fussy > ErrModeSilent {
		fmt.Fprint(os.Stderr, msg)
	}
	if fussy >= ErrModeError {
		return yt.PathErrorf(childPath, msg)
	}
	return nil
}

// Returns a non-nil error if a mapping node is missing any required keys.
// First arg should be path from global document root to target mapping node.
// Remaining args are required keys.
func checkRequiredKeys(pathToParent []yt.Node, requiredKeys ...string) error {
	if err := validateLastNodeKind(pathToParent, yt.MappingKind); err != nil {
		return err
	}
	childMap := childPathMap(pathToParent)
	for _, key := range requiredKeys {
		if _, exists := childMap[key]; !exists {
			return yt.PathErrorf(pathToParent, "required key %q missing", key)
		}
	}
	return nil
}

// policyExists check if `p` is in set `set`, if so, return TRUE and the index of `p` in `set`.
func policyExists(p *doc.Policy, set []*doc.Policy) (bool, int) {
	for i, sp := range set {
		if policiesEquivalent(p, sp) {
			return true, i
		}
	}
	return false, -1
}

func policiesEquivalent(a, b *doc.Policy) bool {
	// I don't check constraints since user is probably confused if they are adding different
	// constraints to the same scope+condition.
	panic("not implemented")

	//
	// return scopesEquivalent(a.Scope, b.Scope) && conditionsEquivalent(a.Conditions, b.Conditions)
}

// scopeEquivalent does a cursory check to see if the scopes "look the same". Will not detect
// overlap, for example.
func scopesEquivalent(a, b []*doc.Scoping) bool {
	for _, aa := range a {
		astr := aa.String()
		matched := false
		for _, bb := range b {
			if astr == bb.String() {
				matched = true
				break
			}
		}
		if !matched {
			return false // element of a not in b
		}
	}
	// All a is in b
	return len(a) == len(b)
}

// conditionsEquivalent checks the attributes for equality.
func conditionsEquivalent(a, b []*doc.Condition) bool {
	var aattrs, battrs []*doc.AttrExpr
	for _, ca := range a {
		aattrs = append(aattrs, ca.AttrExprs...)
	}
	for _, cb := range b {
		battrs = append(battrs, cb.AttrExprs...)
	}
	for _, aa := range aattrs {
		astr := aa.String()
		matched := false
		for _, bb := range battrs {
			if astr == bb.String() {
				matched = true
				break
			}
		}
		if !matched {
			return false // element of a not in b
		}
	}
	// All a is in b
	return len(aattrs) == len(battrs)
}

// Checks a set of attribute expressions for conflicts or redundancies. Returns
// an empty string if there are none. Otherwise returns a the first key found to
// be used inconsistently.
func checkAttributeExpressionsForConflicts(attrExprs []*doc.AttrExpr) string {
	eqSet := make(map[string]bool)              // key -> true for eq/ne attr exprs
	inclSet := make(map[string]map[string]bool) // key -> val -> true for includes attr exprs
	exclSet := make(map[string]map[string]bool) // key -> val -> true for excludes attr exprs
	for _, attrExpr := range attrExprs {
		key, op, val := attrExpr.Key.String(), attrExpr.Op.String(), attrExpr.Value.String()
		switch op {
		case doc.AttrExprOpEq, doc.AttrExprOpNe:
			if _, exists := eqSet[key]; exists {
				return key // equals multiple values
			}
			eqSet[key] = true
		case doc.AttrExprOpHas:
			inclValSet, found := inclSet[key]
			if found {
				if _, found := inclValSet[val]; found {
					return key // includes a value more than once
				}
			} else {
				inclSet[key] = make(map[string]bool)
			}
			inclSet[key][val] = true
			exclValSet, found := exclSet[key]
			if found {
				if _, found := exclValSet[val]; found {
					return key // includes and excludes a value
				}
			}
		case doc.AttrExprOpExcludes:
			exclValSet, found := exclSet[key]
			if found {
				if _, found := exclValSet[val]; found {
					return key // excludes a value more than once
				}
			} else {
				exclSet[key] = make(map[string]bool)
			}
			exclSet[key][val] = true
			inclValSet, found := inclSet[key]
			if found {
				if _, found := inclValSet[val]; found {
					return key // excludes and includes a value
				}
			}
		}
	}
	return ""
}

// Returns a ZplString value associated with the key under which a YAML node is
// mapped. Normally a ZplString value is associated with a scalar YAML node and
// carries information about the location of the node's definition in the YAML
// source. Mapping keys aren't scalar nodes, but it is still useful to associate
// them with locations in the source, even if only approximately. This function
// returns a ZplString value associated with an imaginary scalar node whose
// value is the key under which the final node of the argument path is mapped
// and whose location is the same as the final node's location. It panics if
// if the second-to-last node of the argument path is not a mapping node, if
// the last node is not its child, or if the path is otherwise malformed.
func newKeyZplString(path []yt.Node) doc.ZplString {
	if len(path) < 2 {
		panic(yt.PathErrorf(path, "path too short to create key node"))
	}
	root := path[0]
	node := path[len(path)-1]
	pred := path[len(path)-2]
	key := lastNodeKey(path)
	if pathExpr, err := yt.PathExpression(path); err != nil {
		panic(err)
	} else if err := validateNodeKind(pred, yt.MappingKind); err != nil {
		panic(err)
	} else if keyNode, err := yt.ReplaceNodeValue(node, key); err != nil {
		panic(err)
	} else if newRoot, err := yt.ReplaceNode(root, node, keyNode, nil); err != nil {
		panic(err)
	} else if zs, err := doc.NewZplString(yt.MatchingPaths(newRoot, yt.NewPathPatternOk(pathExpr))[0]); err != nil {
		panic(err)
	} else {
		return zs
	}
}

// Returns a ZplScalar value associated with the same location in the ZPL source
// as the node at the end of the specified path. Although ZplScalar values are
// normally associated only with scalar nodes, this function works as well for
// mapping or sequence nodes. The Value method returns nil for the returned
// ZplScalar; only the location information as returned by Path and Sources is
// intended to be useful, e.g., for producing meaningful error values with
// ZplScalarErrorf. (The returned ZplScalar is created from an imaginary scalar
// node whose location is the same as the argument path's final node.) This
// function panics if the argument path is malformed.
func newZplRef(path []yt.Node) doc.ZplScalar {
	if len(path) == 0 {
		panic(yt.PathErrorf(path, "cannot create ref node for empty path"))
	}
	root := path[0]
	node := path[len(path)-1]
	if pathExpr, err := yt.PathExpression(path); err != nil {
		panic(err)
	} else if refNode, err := yt.ReplaceNodeValue(node, nil); err != nil {
		panic(err)
	} else if newRoot, err := yt.ReplaceNode(root, node, refNode, nil); err != nil {
		panic(err)
	} else if zs, err := doc.NewZplString(yt.MatchingPaths(newRoot, yt.NewPathPatternOk(pathExpr))[0]); err != nil {
		panic(err)
	} else {
		return zs
	}
}

// Copy create a fresh allowBlock that holds a copy of the data in `b`
func (b *allowBlock) Copy() *allowBlock {
	cpy := &allowBlock{}
	cpy.dsList = append(cpy.dsList, b.dsList...)
	cpy.svcList = append(cpy.svcList, b.svcList...)
	return cpy
}

// Copy create a fresh applyBlock that holds a copy of the data in `b`
func (b *applyBlock) Copy() *applyBlock {
	cpy := &applyBlock{}
	cpy.conditions = append(cpy.conditions, b.conditions...)
	return cpy
}
