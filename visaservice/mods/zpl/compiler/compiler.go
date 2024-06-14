package compiler

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/user"
	"sort"
	"strings"
	"time"

	"zpr.org/vsx/polio"
	"zpr.org/vsx/zpl/defs"
	"zpr.org/vsx/zpl/doc"
	"zpr.org/vsx/zpl/fs"
	"zpr.org/vsx/zpl/pp"
)

const (
	MaxVisaLifetime = 12 * time.Hour // TODO: Should come from the ZPL

	DefaultBootstrapVisaLifetime = 48 * time.Hour

	// CredIDNodeNetworkOffset is the byte number index into the IPv6 surenet
	// address that is used (incremented) for node-unique networks.
	CredIDNodeNetworkOffset = 7

	// Number of leading 1s in the network mask for the node-unique network CIDR.
	CredIDNodeMaskSize = (CredIDNodeNetworkOffset + 1) * 8
)

type CompileOpts struct {
	Quiet                  bool
	Silent                 bool
	Werror                 bool
	Verbose                bool
	Revision               string // Revision is not optional
	DynamicAsserts         bool
	AbideAsserts           bool
	TraceAsserts           string
	DSDs                   []*pp.DSDesc // passed to pp
	SkipBootstrapVisas     bool         // If TRUE does not generate bootstap visas
	PMCTLPort              uint16
	VisaServiceAddress     string
	VisaSupportServicePort uint16
	VisaServicePort        uint16
	TetherBaseAddress      string
	CredIDBaseAddress      string
}

type AuthProv struct {
	Provides string
	External bool
}

// At the end of compilation the compiler emits descriptors for the needed bootstrap
// visas.  See zplc command line tool for how to turn these into visas.
type BootstrapVisaDescriptor struct {
	SourceTether netip.Addr
	SourceAddr   netip.Addr
	SourcePort   uint16
	DestTether   netip.Addr
	DestAddr     netip.Addr
	DestPort     uint16
	Protocol     uint8
	Forward      bool
	Duration     time.Duration
}

// Compile is an older function that does not support creation of or returning the bootstrap visas.
func Compile(main string, store fs.FileStore, opts *CompileOpts) (*polio.Policy, error) {
	opts.SkipBootstrapVisas = true
	p, _, e := compileWithOpts(main, store, opts)
	return p, e
}

func CompileAndGenerateVisas(main string, store fs.FileStore, opts *CompileOpts) (*polio.Policy, []*BootstrapVisaDescriptor, error) {
	opts.SkipBootstrapVisas = false
	return compileWithOpts(main, store, opts)
}

func compileWithOpts(main string, store fs.FileStore, opts *CompileOpts) (*polio.Policy, []*BootstrapVisaDescriptor, error) {
	// Previous a lof of constants were plucked directly from the snet/cfg module.
	// So old code assumes they are set.
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
	if opts.TetherBaseAddress == "" {
		opts.TetherBaseAddress = defs.DefaultTetherBaseAddress
	}
	if opts.CredIDBaseAddress == "" {
		opts.CredIDBaseAddress = defs.DefaultCredIDBaseAddress
	}
	popts := &pp.PreprocessOpts{
		Quiet:          opts.Quiet,
		Silent:         opts.Silent,
		Werror:         opts.Werror,
		DynamicAsserts: opts.DynamicAsserts,
		AbideAsserts:   opts.AbideAsserts,
		TraceAsserts:   opts.TraceAsserts,
		DSDs:           opts.DSDs,
	}
	pdoc, _, _, err := pp.Preprocess(main, store, popts)
	if err != nil {
		return nil, nil, err
	}
	comp := NewCompilation(pdoc, opts)
	if err := comp.setDateAndVersion(opts, pdoc.Main); err != nil {
		return nil, nil, err
	}
	if err := comp.setMetadata(pdoc.Main); err != nil {
		return nil, nil, err
	}
	if err := comp.loadZPRNetwork(pdoc.Zpr); err != nil {
		return nil, nil, err
	}
	if err := comp.genConnectRules(pdoc); err != nil {
		return nil, nil, err
	}
	if err := comp.genMatchRules(pdoc); err != nil {
		return nil, nil, err
	}
	if err := comp.SetLinks(pdoc); err != nil {
		return nil, nil, err
	}
	if err := comp.setCerts(pdoc); err != nil {
		return nil, nil, err
	}
	if err := comp.setServices(pdoc); err != nil {
		return nil, nil, err
	}
	// TODO: Settings
	{
		comp.policy.Config = append(comp.policy.Config, polio.NewMaxVisaLifetime(MaxVisaLifetime))
	}
	if opts.Werror && comp.warnings > 0 {
		return nil, nil, fmt.Errorf("compilation aborted due to too many warnings (try without -Werror)")
	}

	var bootstrapVisas []*BootstrapVisaDescriptor
	if !opts.SkipBootstrapVisas {
		dockingNodeID := pdoc.Zpr.Visaservice.Dock.String()
		dockingNode, found := pdoc.Zpr.Nodes[dockingNodeID]
		if !found {
			return nil, nil, fmt.Errorf("docking node %v not found", dockingNodeID)
		}

		vsaddr, _ := netip.ParseAddr(opts.VisaServiceAddress)
		nodeaddr, _ := netip.ParseAddr(dockingNode.Address.String())
		bootstrapVisaLifetime := DefaultBootstrapVisaLifetime // TODO: lifetime could be overridden on command line

		visa := &BootstrapVisaDescriptor{
			SourceTether: vsaddr,
			SourceAddr:   vsaddr,
			SourcePort:   0,
			DestTether:   nodeaddr,
			DestAddr:     nodeaddr,
			DestPort:     opts.VisaSupportServicePort,
			Protocol:     defs.ProtocolTCP,
			Forward:      true,
			Duration:     bootstrapVisaLifetime,
		}
		bootstrapVisas = append(bootstrapVisas, visa)

		visa = &BootstrapVisaDescriptor{
			SourceTether: nodeaddr,
			SourceAddr:   nodeaddr,
			SourcePort:   0,
			DestTether:   vsaddr,
			DestAddr:     vsaddr,
			DestPort:     opts.VisaServicePort,
			Protocol:     defs.ProtocolTCP,
			Forward:      true,
			Duration:     bootstrapVisaLifetime,
		}
		bootstrapVisas = append(bootstrapVisas, visa)
	}

	return comp.policy, bootstrapVisas, nil
}

func (c *Compilation) lookupAttrKey(k string) (uint32, bool) {
	for i, xv := range c.policy.AttrKeyIndex {
		if xv == k {
			return uint32(i), true
		}
	}
	return 0, false
}

func (c *Compilation) lookupAttrValue(v string) (uint32, bool) {
	for i, xv := range c.policy.AttrValIndex {
		if xv == v {
			return uint32(i), true
		}
	}
	return 0, false
}

func (c *Compilation) insertAttrKey(k string) uint32 {
	c.policy.AttrKeyIndex = append(c.policy.AttrKeyIndex, k)
	return uint32(len(c.policy.AttrKeyIndex) - 1)
}

func (c *Compilation) insertAttrValue(v string) uint32 {
	c.policy.AttrValIndex = append(c.policy.AttrValIndex, v)
	return uint32(len(c.policy.AttrValIndex) - 1)
}

// setDateAndVersion updates policy version, revision and date in the doc. Also sets
// the date and version in the binary format.
func (c *Compilation) setDateAndVersion(opts *CompileOpts, main *doc.Main) error {
	if main.PolicyDate.Value() == nil {
		main.SetDate(time.Now().UTC())
	}
	defaultPolicyVersion := uint64(time.Now().Unix())

	if main.PolicyVersion.Value() == nil {
		c.policy.PolicyVersion = defaultPolicyVersion
	} else {
		mainPolicyVersion := main.PolicyVersion.Value().(uint64)
		if mainPolicyVersion == 0 {
			main.PolicyVersion, _ = doc.NewZplUnsigned(defaultPolicyVersion)
		}
		c.policy.PolicyVersion = main.PolicyVersion.Value().(uint64)
	}

	// Expect revision to be provided (not an option)
	if opts.Revision == "" {
		return fmt.Errorf("a revision must be provided")
	}
	c.policy.PolicyRevision = opts.Revision

	// TODO Above we set the policy date if the ZPL didn't specify one, but
	// here we just set it unconditionally. Which do we want to do?
	main.SetDate(time.Now().UTC())
	c.policy.PolicyDate = main.PolicyDate.String()

	return nil
}

// setMetadata sets the metadata string in the binary format.
func (c *Compilation) setMetadata(m *doc.Main) error {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "<unk_host>"
	}
	var username string
	usr, err := user.Current()
	if err != nil {
		username = "<unk_user>"
	}
	username = usr.Username
	c.policy.PolicyMetadata = fmt.Sprintf("compiled %v on %v by %v", time.Now().UTC().Format(time.RFC3339), hostname, username)
	return nil
}

func (c *Compilation) loadZPRNetwork(n *doc.ZPR) error {
	// TODO: At some point we should allow this to be set in policy
	nodenet := fmt.Sprintf("%v/32", c.tetherBaseAddress)
	_, nn, err := net.ParseCIDR(nodenet)
	if err != nil {
		return fmt.Errorf("invalid tether_net: %v", err)
	}
	c.nodeNet = nn

	// TODO: At some point we should allow this to be set in policy
	zprnet := fmt.Sprintf("%v/32", c.credIDBaseAddress)
	_, zn, err := net.ParseCIDR(zprnet)
	if err != nil {
		return fmt.Errorf("invalid zpr_net: %v", err)
	}
	c.zprNet = zn
	if n.Visaservice == nil {
		return fmt.Errorf("network.visaservice must be specified")
	}
	c.visaserviceDockingNode = n.Visaservice.Dock.String()
	if c.visaserviceDockingNode == "" {
		return fmt.Errorf("visaservice dock property must be set")
	}
	return nil
}

// resolve resolves a domain name
func (c *Compilation) resolve(host string) (string, error) {
	entry, found := c.hostTable[host]
	if !found {
		entry = &doc.Host{
			Address: host,
		}
		c.hostTable[host] = entry
	}
	if entry.IP() == nil || entry.IP().IsUnspecified() {
		if ipt := net.ParseIP(entry.Address); ipt != nil {
			// If already an IP, great.
			entry.SetAddrIP(ipt)
		} else {
			fmt.Fprintf(os.Stderr, "resolving: %v\n", entry.Address)
			addrs, err := net.LookupHost(entry.Address)
			if err != nil {
				return "", fmt.Errorf("DNS lookup failed for '%v': %v", entry.Address, err)
			}
			if len(addrs) > 1 {
				c.warnf("multiple address for %v", entry.Address)
				for i, a := range addrs {
					fmt.Fprintf(os.Stderr, "   %v", a)
					if i == 0 {
						fmt.Fprintf(os.Stderr, " (DEFAULT)\n")
					} else {
						fmt.Fprintln(os.Stderr)
					}
				}
			}
			c.infof("resolved: %v -> %v", entry.Address, addrs[0])
			entry.SetAddrName(entry.Address)
			entry.SetAddrIP(net.ParseIP(addrs[0]))
		}
	}
	return entry.IP().String(), nil
}

// checkAttrExprPrefixes checks that all attribute expressions have a prefix that is actually provided by an auth service.
// Also updates the `authProviders` map in the compilation.
func (c *Compilation) checkAttrExprPrefixes(d *doc.Doc, sets []*AttrExprSet) error {
	pfxm := make(map[string]*AuthProv)
	pfxkeym := make(map[string]doc.ZplScalar)

	for pfx, ds := range d.Zpr.Datasources {
		if ds.Authority != nil { // is-an internal data source
			pf := strings.ToLower(pfx)
			if _, exist := pfxm[pf]; exist {
				return doc.ZplScalarErrorf(doc.MustNewZplString(pfx), "duplicate internal auth prefix: %q", pf)
			}
			pfxm[pf] = &AuthProv{
				Provides: pf, // TODO: What is "Provides" ?
				External: false,
			}
		}
	}

	for _, set := range sets {
		for _, ex := range set.AttrExprs {
			parts := strings.Split(ex.Key.String(), ".")
			if len(parts) < 2 {
				return doc.ZplScalarErrorf(ex.Key, "attribute without a prefix: %q", ex.Key.String())
			}
			pfx := strings.ToLower(parts[0])
			if pfx == "zpr" {
				// While we are here, ensure only known zpr attributes are used.
				attr := strings.ToLower(parts[1])
				switch attr {
				case "addr", "authority", "connect_via", "role", "visa_service_adapter": // ok!
				default:
					return doc.ZplScalarErrorf(ex.Key, "unknown zpr attribute: %q", attr)
				}
				continue
			}
			if _, exist := pfxm[pfx]; !exist {
				pfxm[pfx] = &AuthProv{} // empty
				pfxkeym[pfx] = ex.Key
			}
		}
	}

	// Now we know all the prefixes, find all the relevant authorities.
	// Every prefix must match to a service with an AUTH block that defines the prefix.
	var pending []*doc.System
	for _, docsys := range d.Communications.Systems {
		pending = append(pending, docsys)
	}
	var sys *doc.System

	for len(pending) > 0 {
		sys, pending = pending[0], pending[1:]
		if len(sys.Systems) > 0 {
			for _, docsys := range sys.Systems {
				pending = append(pending, docsys)
			}
		}
		// Preoprocessor copies the zpr datasources down into the communications hierarchy.
		for _, svc := range sys.Components {
			if apfx := svc.Auth.String(); apfx != "" {
				if handler, exist := pfxm[apfx]; exist && handler.Provides != "" {
					if handler.Provides != svc.GetProvides() {
						return doc.ZplScalarErrorf(svc.Auth,
							"auth prefix '%v' offered by multiple services: found '%v' and '%v'",
							apfx, handler.Provides, svc.GetProvides())
					}
				} else {
					pfxm[apfx] = &AuthProv{
						Provides: svc.GetProvides(),
						External: true,
					}
				}
			}
		}
	}

	for pfx, provider := range pfxm {
		if provider.Provides == "" {
			if key, ok := pfxkeym[pfx]; ok {
				return doc.ZplScalarErrorf(key, "prefix not provided by any auth service: %q", pfx)
			} else {
				return fmt.Errorf("prefix not provided by any auth service: %q", pfx)
			}
		}
	}

	// Save for later??
	c.authProviders = pfxm

	return nil
}

// createAttrLookups returns two tables: (keytable, valtable).
// The keytable is a list of every key value in use across all attribute expressions.
// The valtable is a list of every value in use across all attribute expressions.
//
// The integers mapped to the values are to be used in the binary policy in place of
// the actual strings (poor mans compression).
func (c *Compilation) createAttrLookups(sets []*AttrExprSet) (map[string]int, map[string]int) {
	keytable := make(map[string]int)
	valtable := make(map[string]int)

	for _, set := range sets {
		for _, ex := range set.AttrExprs {
			key := ex.Key.String()
			val := ex.Value.String()
			if _, exist := keytable[key]; !exist {
				keytable[key] = 0
			}
			if _, exist := valtable[val]; !exist {
				valtable[val] = 0
			}
		}
	}

	// Sort the keys and values then put the index number into the respective table.
	var keys, vals []string
	for k := range keytable {
		keys = append(keys, k)
	}
	for v := range valtable {
		vals = append(vals, v)
	}
	sort.Slice(keys, func(i, j int) bool {
		return strings.Compare(keys[i], keys[j]) < 0
	})
	sort.Slice(vals, func(i, j int) bool {
		return strings.Compare(vals[i], vals[j]) < 0
	})
	for i, k := range keys {
		keytable[k] = i
	}
	for i, v := range vals {
		valtable[v] = i
	}

	return keytable, valtable
}

// NextCIDR returns a CIDR for use by a node.
//
// TODO: Not sure why this is handing out the ZPR address space and not the Tether address space.
// TODO: How is tether address space communicated to nodes?
func (c *Compilation) NextCIDR() *net.IPNet {
	if c.nextCIDR == 255 {
		return nil
	}
	base := c.zprNet.IP.To16()
	base[CredIDNodeNetworkOffset] = c.nextCIDR
	c.nextCIDR++
	return &net.IPNet{
		IP:   base,
		Mask: net.CIDRMask(CredIDNodeMaskSize, 128),
	}
}

func (c *Compilation) findProc(p *polio.Proc) (uint32, bool) {
	for i, existing := range c.policy.GetProcs() {
		if equivalentProcs(p, existing) {
			return uint32(i), true
		}
	}
	return 0, false
}
