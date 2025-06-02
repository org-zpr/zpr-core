// Package policy handles the node policy state and a "machine" for altering
// policy via gRPC.
package policy

import (
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"zpr.org/vs/pkg/logr"

	"zpr.org/vsx/polio"
)

const (
	// EmptyPolicyVersion is the version of the empty (deny-all) policy.
	EmptyPolicyVersion = ""
)

// Policy is a wrapper around a pol.Policy and, if applicable, its container.
// It also caches some values and attempts to return sane values if the
// actual policy is empty or nil.
//
// This has some helper functions on it to make working with policies easier
// for ZPRN. Possibly it would be better to just use the protobuf policy
// object and add helpers to that.
type Policy struct {
	cache struct {
		version         string
		versioni        uint64
		revision        string
		maxVisaLifetime time.Duration
		defaultIntAuth  string // possibly empty
		dsHash          []byte
		topoHash        []byte
		mesh            *ServiceMesh
	}
	container *polio.PolicyContainer // possibly nil
	bun       *polio.Policy          // possibly nil, usually extracted from container
}

func NewEmptyPolicy() *Policy {
	return &Policy{}
}

// Most code should call NewPolicyFromContainer
func NewPolicyFromPol(ppol *polio.Policy, log logr.Logger) *Policy {
	p := &Policy{
		bun: ppol,
	}
	p.cache.version = fmt.Sprintf("%v", ppol.GetPolicyVersion())
	p.cache.maxVisaLifetime = GetMaxVisaLifetime(ppol)
	if p.cache.maxVisaLifetime == 0 {
		log.Warn("[P] max visa lifetime is zero")
	}
	p.cache.defaultIntAuth = ExtractDefaultINTAuthority(ppol)
	p.createDatasourceHash()
	p.createTopologyHash()
	p.cache.mesh = NewServiceMeshFromPolicy(ppol)
	return p
}

// Container signature should already have been checked.
// Policy serial format should already have been checked.
func NewPolicyFromContainer(pc *ContainedPolicy, log logr.Logger) *Policy {
	p := NewPolicyFromPol(pc.Policy, log)
	p.container = pc.Container
	return p
}

// GetMaxVisaLifetime is the maximum visa lifetime as set in policy.
func (p *Policy) GetMaxVisaLifetime() time.Duration {
	return p.cache.maxVisaLifetime
}

// Version returns the current policy version as string
// TODO: We use VersionAndRevision in some places and Version in others. We should have one string "version" value for a policy.
func (p *Policy) Version() string {
	if p.bun == nil {
		return EmptyPolicyVersion
	}
	return p.cache.version
}

// VersionAndRevision returns canonical "<version>+<revision>" string.
// TODO: We use VersionAndRevision in some places and Version in others. We should have one string "version" value for a policy.
func (p *Policy) VersionAndRevision() string {
	if p.bun == nil {
		return EmptyPolicyVersion
	}
	return fmt.Sprintf("%s+%s", p.cache.version, p.bun.GetPolicyRevision())
}

// Version as integer.
func (p *Policy) VersionNumber() uint64 {
	if p.bun == nil {
		return 0
	}
	return p.bun.GetPolicyVersion()
}

func (p *Policy) GetSerialVersion() uint32 {
	return p.bun.GetSerialVersion()
}

func (p *Policy) Size() int {
	if p.bun == nil {
		return 0
	}
	if p.container != nil {
		return len(p.container.Policy)
	}
	return len(p.bun.GetPolicies()) + len(p.bun.GetConnects()) // guestimate
}

// Export the container that created this policy (possibly nil).
func (p *Policy) Export() *polio.PolicyContainer {
	return p.container
}

// ExportBundle returns the policy bundle extracted from the container that
// created this policy. Possibly nil.
func (p *Policy) ExportBundle() *polio.Policy {
	return p.bun
}

// IsEmpty is true if the policy is nil or there are no policy lines.
func (p *Policy) IsEmpty() bool {
	return p.Size() == 0
}

// ListLinks is readonly set of links in current policy.
// Implements topo.Manager.LinkSource.
// Deprecated: use ExportBundle().GetLinks()
func (p *Policy) ListLinks() []*polio.Link {
	if p.bun == nil {
		return nil
	}
	return p.bun.GetLinks()
}

// AuthServiceForPrefix return the (visa-service facing) auth service with the given prefix or nil.
func (p *Policy) AuthServiceForPrefix(pfx string) *polio.Service {
	if p.bun == nil {
		return nil
	}
	for _, s := range p.bun.GetServices() {
		if s.GetType() == polio.SvcT_SVCT_AUTH && s.GetPrefix() == pfx {
			return s
		}
	}
	return nil
}

// Returns the names of any actor authentication services in the policy.
// Note does not mean that the services are on the ZPRnet.
func (p *Policy) GetActorAuthenticationServiceNames() []string {
	if p.bun == nil {
		return nil
	}
	var authServices []string
	for _, s := range p.bun.GetServices() {
		if s.GetType() == polio.SvcT_SVCT_ACTOR_AUTH {
			authServices = append(authServices, s.GetName())
		}
	}
	return authServices
}

func (p *Policy) GetVisaServiceValidationServiceNames() []string {
	if p.bun == nil {
		return nil
	}
	var authServices []string
	for _, s := range p.bun.GetServices() {
		if s.GetType() == polio.SvcT_SVCT_AUTH {
			authServices = append(authServices, s.GetName())
		}
	}
	return authServices
}

// Lookup RSA public key for the given common name (CN).
// If found, and we can deserialize the key it is returned.
// If not found, or there is a problem deserializing the key, an error is returned.
func (p *Policy) GetPublicKeyForCN(cn string) (*rsa.PublicKey, error) {
	if p.bun == nil {
		return nil, errors.New("empty policy")
	}
	for _, k := range p.bun.Pubkeys {
		if k.Cn == cn {
			if pk, err := x509.ParsePKIXPublicKey(k.Keydata); err == nil {
				return pk.(*rsa.PublicKey), nil
			} else {
				return nil, fmt.Errorf("failed to parse public key: %w", err)
			}
		}
	}
	return nil, fmt.Errorf("no public key found for CN: %s", cn)
}

// GetDefaultINTAuthority returns the default "internal" authority prefix value. Internal is as
// opposed to an external validation service.
//
// Returns a prefix value or empty string if there are too many (so no default) or none.
func (p *Policy) GetDefaultINTAuthority() string {
	return p.cache.defaultIntAuth
}

// Get a hash value representing the datasource configuration of this policy.
func (p *Policy) GetDatasourceHash() []byte {
	return p.cache.dsHash
}

func (p *Policy) GetServiceMesh() *ServiceMesh {
	return p.cache.mesh
}

// Checks if policy `other` is "connect compatible" with `p`. Returns TRUE if the
// `other` policy permits all the connections that `p` does.  Returns FALSE when
// the `other` policy would prevent some actors that could have connected in `p` from
// connecting.
//
// This is not very sophisticated - the connection attributes must match exactly to
// count as compatible.
func (p *Policy) IsConnectCompatibleWith(other *Policy) bool {
	// Simple: every connect hash in `p` must also be in `other`.
	otherHashes := other.getConnectHashes()
	for _, hh := range p.getConnectHashes() {
		found := false
		for _, oh := range otherHashes {
			if hh == oh {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// GetConnectHashes returns a list of hashes (as hex strings), one for each attribute expression set that
// permits a connect to the network.  These are returned sorted.
func (p *Policy) getConnectHashes() []string {
	var hashes []string
	hasher := sha512.New()
	for _, connect := range p.bun.GetConnects() {
		var cexprs []string
		for _, expr := range connect.AttrExprs {
			key, op, val := p.bun.AttrKeyIndex[expr.Key], expr.Op, p.bun.AttrValIndex[expr.Val]
			cexprs = append(cexprs, fmt.Sprintf("%v-%v-%v", key, op.String(), val))
		}
		sort.Slice(cexprs, func(i, j int) bool {
			return strings.Compare(cexprs[i], cexprs[j]) < 1
		})
		for _, exp := range cexprs {
			hasher.Write([]byte(exp))
		}
		hashes = append(hashes, hex.EncodeToString(hasher.Sum(nil)))
		hasher.Reset()
	}

	sort.Slice(hashes, func(i, j int) bool {
		return strings.Compare(hashes[i], hashes[j]) < 0
	})

	return hashes
}

// Compute a hashcode value over the datasource configuration, store in our cache.
// TODO: Should we do this in the compiler?
func (p *Policy) createDatasourceHash() {

	prefixes := make(map[string][]byte) // auth prefix -> hash of entity
	hasher := sha512.New()

	// Get all the "external" services
	for _, s := range p.bun.Services {
		if s.Type != polio.SvcT_SVCT_AUTH {
			continue
		}
		hasher.Write([]byte(s.Name))
		hasher.Write([]byte(s.Prefix))
		hasher.Write([]byte(s.Domain))
		hasher.Write([]byte(s.QueryUri))
		hasher.Write([]byte(s.ValidateUri))
		prefixes[s.Prefix] = hasher.Sum(nil)

		hasher.Reset()
	}

	// Get all the "internal" services and mix in the certs to existing hashses.
	for _, c := range p.bun.Certificates {
		if curHash, ok := prefixes[c.Name]; ok {
			hasher.Write(curHash)
			hasher.Write(c.Asn1Data)
			prefixes[c.Name] = hasher.Sum(nil)
		} else {
			// is an internal cert
			hasher.Write([]byte(c.Name))
			hasher.Write(c.Asn1Data)
			prefixes[c.Name] = hasher.Sum(nil)
		}
		hasher.Reset()
	}

	var sorted []string
	for pfx := range prefixes {
		sorted = append(sorted, pfx)
	}
	sort.Slice(sorted, func(i, k int) bool {
		return sorted[i] < sorted[k]
	})
	for _, pfx := range sorted {
		hasher.Write(prefixes[pfx])
	}
	p.cache.dsHash = hasher.Sum(nil)
}

// GetTopologyHash returns a hash representing the node topology. Policies with the same topology will
// return the same hash value here.
func (p *Policy) GetTopologyHash() []byte {
	return p.cache.topoHash
}

func (p *Policy) createTopologyHash() {
	var connections []string

	for _, link := range p.bun.Links {
		na := net.IP(link.SourceId).String()
		for _, termAddr := range link.Terms {
			nb := net.IP(termAddr.Key).String()
			if strings.Compare(na, nb) > 0 {
				connections = append(connections, fmt.Sprintf("%v %v %d %d", na, nb, termAddr.Port, termAddr.Cost))
			} else {
				connections = append(connections, fmt.Sprintf("%v %v %d %d", nb, na, termAddr.Port, termAddr.Cost))
			}
		}
	}
	sort.Slice(connections, func(i, j int) bool {
		return strings.Compare(connections[i], connections[j]) < 0
	})

	// Now that `connections` is a sorted list of node connections, use that to create a hash.
	hasher := sha512.New()
	for _, connection := range connections {
		hasher.Write([]byte(connection))
	}
	p.cache.topoHash = hasher.Sum(nil)
}

// BEGIN CertificateDB interface

func (p *Policy) ListCertificateIDs() []uint32 {
	if p.bun == nil {
		return nil
	}
	return ListCertificateIDs(p.bun)
}

// GetCertificate returns certificate asn1 data and its name, given its certificate ID.
func (p *Policy) GetCertificate(authID uint32) (*x509.Certificate, string, error) {
	if p.bun == nil {
		return nil, "", errors.New("empty policy")
	}
	return GetCertificate(p.bun, authID)
}

func (p *Policy) ServiceByName(name string) *polio.Service {
	if p.bun == nil {
		return nil
	}
	return ServiceByName(p.bun, name)
}

// END CertificateDB interface
