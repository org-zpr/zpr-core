package compiler

import (
	"fmt"
	"net"

	"zpr.org/vsx/polio"
	"zpr.org/vsx/zpl/doc"
)

type Compilation struct {
	ll                     LogLevel
	warnings               int
	policy                 *polio.Policy
	authProviders          map[string]*AuthProv // attr prefix -> AuthProc
	visaserviceDockingNode string               // name of visa service node (TODO: Support multiple)
	parsed                 *doc.Doc             // input parsed Doc
	zprNet                 *net.IPNet
	nodeNet                *net.IPNet
	hostTable              map[string]*doc.Host // for caching resolution
	nextCIDR               byte
	attrExprSets           []*AttrExprSet    // created during connect processing
	nodeKeys               []string          // sorted topology node keys
	lanKeys                []string          // sorted topology lan keys
	groups                 map[string]string // constraint groups in use. GroupName -> ConstraintValue
	keyFingerprints        map[string]string // fingerprint(HEX) -> key identifier or description
	pmctlPort              int
	tetherBaseAddress      string
	credIDBaseAddress      string
}

func NewCompilation(parsedDoc *doc.Doc, opts *CompileOpts) *Compilation {
	ll := LLQUIET
	if opts.Silent {
		ll = LLSILENT
	} else if opts.Verbose {
		ll = LLVERBOSE
	}

	return &Compilation{
		ll:     ll,
		parsed: parsedDoc,
		policy: &polio.Policy{
			SerialVersion: polio.SerialVersion,
		},
		nextCIDR:          1,
		groups:            make(map[string]string),
		hostTable:         make(map[string]*doc.Host),
		keyFingerprints:   make(map[string]string),
		pmctlPort:         int(opts.PMCTLPort),
		tetherBaseAddress: opts.TetherBaseAddress,
		credIDBaseAddress: opts.CredIDBaseAddress,
	}
}

// GetPolicy -- for unit tests only
func (c *Compilation) GetPolicy() *polio.Policy {
	return c.policy
}

// AddUniqueKeyFingerprint returns error if key already exists in cache.
// `k` is the hex encoded fingerprint.
func (c *Compilation) AddUniqueKeyFingerprint(k string, d string) error {
	if desc, found := c.keyFingerprints[k]; found {
		return fmt.Errorf("duplicate key fingerprint: %v", desc)
	}
	c.keyFingerprints[k] = d
	return nil
}
