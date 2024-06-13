package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"zpr.org/vs/pkg/agent"
	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vsx/snio/zds"

	"zpr.org/vsx/polio"
)

var (
	errAuthFailed  = errors.New("authentication failed")
	errAuthRevoked = errors.New("key or credential has been revoked")
	errQueryFailed = errors.New("query operation failed")
)

// Authenticator is responsible for running all authentication on the node either
// by calling to an external service or using local (cert-style) validation.
//
// Implements vsa.AuthService interface.
type Authenticator struct {
	log             logr.Logger
	local           *NodeValidator // For local cert validation
	ep              netip.Addr
	MaxAuthDuration time.Duration

	rvkSvc struct {
		sync.RWMutex
		service RevocationService
	}

	policy struct {
		sync.RWMutex

		configID uint64         // active configuration
		version  string         // active policy
		policy   *policy.Policy // is-a CertificateDB
		//cdb           CertificateDB   // certs from active policy
		localPrefixes map[string]bool // prefix -> TRUE (derived from policy)
		validators    *Directory      // (derived from policy)
	}
}

type ValidateResult struct {
	Prefix       string                // Prefix which did the validation
	DomainCredID string                // Credential ID of the validation domain (if any)
	VResp        *zds.ValidateResponse // The Validate response
}

// NewAuthenticator
// It is critical to keep this instance up to date with policy version so that it
// is using the correct revocation details.
//
// `ep` is this nodes ZPR address (used as a point-of-entry ID)
// `nodename` is this nodes name (added as metadata to all JWTs we create)
// `privateKey` is the key used to sign JWTs we create post validation.
//
// To make this fully functional you must call `SetRevocationService` at some point.
func NewAuthenticator(mlog logr.Logger, ep netip.Addr, maxAuthLifetime time.Duration, nodeName string, privateKey *rsa.PrivateKey) *Authenticator {
	ath := &Authenticator{
		log:             mlog,
		ep:              ep,
		MaxAuthDuration: maxAuthLifetime,
		local:           NewNodeValidator(mlog, maxAuthLifetime, nodeName, privateKey),
	}
	ath.policy.validators = NewDirectory(snauth.NewCertCollection(), mlog)
	ath.policy.localPrefixes = make(map[string]bool)
	return ath
}

func (a *Authenticator) SetRevocationService(service RevocationService) {
	a.rvkSvc.Lock()
	defer a.rvkSvc.Unlock()
	a.rvkSvc.service = service
}

// SetCurrentPolicy extracts the datasource information from the given policy.
// After this call, all auth operations will make use of these datasources.
//
// Ignores `slot` arg.
//
// Implementation for policy.PolicyListener
func (a *Authenticator) InstallPolicy(configID uint64, _ byte, p *policy.Policy) {
	a.policy.Lock()
	defer a.policy.Unlock()

	if a.policy.version != "" && (a.policy.configID != configID || a.policy.version != p.Version()) {
		// When a new policy or configuration is installed, we clear the revocation list for the
		// previous version.
		a.clearRevocationList(a.policy.configID, a.policy.version)
	}

	a.policy.version = p.Version()
	a.policy.configID = configID
	a.policy.policy = p

	a.log.Info("new policy version set", "configuration", configID, "version", a.policy.version)
	err := a.updateVStoreFromPolicy(p.ExportBundle())
	if err != nil {
		panic(err) // Should never happen if CheckPolicy was run first.
	}
}

// I believe that `InstallPolicy` function sets the new configuration.
// This just verifies it.
//
// deactivates all other configurations
// Implementation for policy.PolicyListener
func (a *Authenticator) ActivateConfiguration(id uint64, _ byte) {
	a.policy.RLock()
	defer a.policy.RUnlock()
	if id != a.policy.configID {
		a.log.Error("activating configuration does not match state", "activating", id, "has_config", a.policy.configID)
	}
}

// RemoveServiceByPrefix delegates to internal ValidatorStore.
// `domain` is the TLS domain value.
// Returns the number of services removed.
func (a *Authenticator) RemoveServiceByPrefix(pfx string) int {
	a.policy.RLock()
	defer a.policy.RUnlock()
	return a.policy.validators.RemoveServiceByPrefix(pfx)
}

// GetAuthEndpoint returns and "endponint" for the polio.service.
func getAuthEndpoint(svc *polio.Service) *snip.Endpoint {
	if _, p, err := net.SplitHostPort(svc.Addr); err == nil {
		if pn, err := strconv.Atoi(p); err == nil {
			return snip.NewEndpoint(polio.AuthProtocol, uint16(pn))
		}
	}
	return nil
}

// Sets the agent providing the datasource.
//
// The `configID` is the configuration ID at the last time the agent authenticated and was
// permitted to advertise the service.
//
// TODO: Needs configuration-ID attached.
func (a *Authenticator) AddDatasourceProvider(service string, contactAddr netip.Addr, configID uint64) error {
	a.policy.RLock()
	defer a.policy.RUnlock()

	psvc := a.policy.policy.ServiceByName(service)
	if psvc == nil {
		return fmt.Errorf("datasource unknown: %v", service)
	}
	if psvc.Type != polio.SvcT_SVCT_AUTH {
		return fmt.Errorf("not an auth service: %v", service)
	}

	features := DSFeatures{
		SupportValidation: psvc.ValidateApiVersion > 0,
		SupportQuery:      psvc.QueryApiVersion > 0,
		ValidationAPIVer:  int(psvc.ValidateApiVersion),
		QueryAPIVer:       int(psvc.QueryApiVersion),
	}

	return a.policy.validators.AddService(psvc.GetPrefix(), psvc.GetDomain(), contactAddr, getAuthEndpoint(psvc).Port, &features, configID)
}

// Authenticate - perform authentication at the node.
//
// Returns error if authentication fails for any reason.
//
// A non nil error return from this means that caller must signal the link
// with failure signal. If nil, it is taken care of.
//
// `extDsPrefix` is used to look up an external validation service (if applicable).
//
// TODO: Eventually we want to support multiple prefixes. The calling code actually may end
// up setting extDsPrefix to a comma separated list. That is not yet supported here.
//
// It is also a little odd that we expect this function to determine if it needs
// to use external auth or not, yet we also need to provide a DsPrefix only if
// external auth is needed.
func (a *Authenticator) Authenticate(extDsPrefix string,
	epID netip.Addr, chal *zds.Challenge, chalResp []*zds.ChallengeResponse,
	unauthClaims map[string]string) (*AuthenticateOK, error) {

	var err error

	a.policy.RLock() // No messing with policy while performing an authentication
	defer a.policy.RUnlock()

	if a.policy.version == "" {
		return nil, errors.New("cannot authenticate because policy is not set")
	}

	internReq := &zds.ValidateRequest{
		ChallengerAddr: a.ep.AsSlice(),
		Chal:           chal,
		Claims:         unauthClaims,
	}
	externReq := &zds.ValidateRequest{
		ChallengerAddr: a.ep.AsSlice(),
		Chal:           chal,
		Claims:         unauthClaims,
	}

	for _, crb := range chalResp {
		aa, err := agent.ParseAuthAttr(crb.GetRespSpec())
		if err != nil {
			a.log.Warn("invalid challenge response block", "spec", crb.GetRespSpec())
			continue
		}
		if aa.IsExternal() {
			externReq.CrespSet = append(externReq.CrespSet, crb)
		} else {
			internReq.CrespSet = append(internReq.CrespSet, crb)
		}
	}

	useInt := len(internReq.CrespSet) > 0
	useExt := len(externReq.CrespSet) > 0

	if !(useInt || useExt) {
		return nil, fmt.Errorf("no challenge response")
	}

	var internResponse, externResponse *ValidateResult
	var credentials []string // Will hold all "credential identifiers" (eg, key fingerprints)
	var idents []string

	// We keep the minimum expire time.
	var expires time.Time
	revokes := a.loadRevocationData()

	if useExt {
		externResponse, err = a.authenticateExtern(externReq, extDsPrefix, revokes)
		if err != nil {
			return nil, err
		}
		if externResponse.VResp.GetStat() == zds.ValidateResponse_SUCCESS {
			idents = append(idents, string(externResponse.VResp.GetToken()))
			expTS, credentialID := a.extractExpireAndCredFromJWT(string(externResponse.VResp.GetToken()))
			expires = expTS
			if credentialID != "" {
				credentials = append(credentials, credentialID)
			}
			if externResponse.DomainCredID != "" {
				credentials = append(credentials, externResponse.DomainCredID)
			}
		}
	}

	// Now check internal if we have any creds for that.  Also only if external succeeded.
	if useInt && (!useExt || (externResponse.VResp.GetStat() == zds.ValidateResponse_SUCCESS)) {
		internResponse, err = a.authenticateIntern(internReq, revokes)
		if err != nil {
			return nil, err
		}
		if internResponse.VResp.GetStat() == zds.ValidateResponse_SUCCESS {
			idents = append(idents, string(internResponse.VResp.GetToken()))
			expTS, credentialID := a.extractExpireAndCredFromJWT(string(internResponse.VResp.GetToken()))
			if credentialID != "" {
				credentials = append(credentials, credentialID)
			}
			if expires.IsZero() || expTS.Before(expires) {
				expires = expTS
			}
			if internResponse.DomainCredID != "" {
				credentials = append(credentials, internResponse.DomainCredID)
			}
		}
	}

	// Expiration time should be in the future. And we may have a policy about
	// the maximum lifetime of authentication credentials.
	//
	// TODO: We should probably share our MaxAuthDuration with the auth service
	//       so that it can create tokens that have an expiration time that is
	//       same as ours. As it is, the JWT in the auth response (ident) will
	//       have an independent expires time that surenet is ignorant of.

	// Since multiple sources could validate this, there may be multiple agent IDs.

	localOK := (!useInt) || (internResponse.VResp.GetStat() == zds.ValidateResponse_SUCCESS)
	extOK := (!useExt) || (externResponse.VResp.GetStat() == zds.ValidateResponse_SUCCESS)

	if !(localOK && extOK) {
		return nil, errAuthFailed
	}

	// ELSE: success !

	var prefixes []string
	authClaims := make(map[string]*agent.ClaimV)
	if useInt {
		for _, kvx := range internResponse.VResp.Attrs {
			authClaims[kvx.Key] = &agent.ClaimV{V: kvx.Val, Exp: time.Unix(kvx.Exp, 0)}
		}
		// Internal could be using any number of CA names
		prefixes = append(prefixes, internResponse.Prefix)
	}
	if useExt {
		for _, kvx := range externResponse.VResp.Attrs {
			authClaims[kvx.Key] = &agent.ClaimV{V: kvx.Val, Exp: time.Unix(kvx.Exp, 0)}
		}
		prefixes = append(prefixes, externResponse.Prefix)
	}
	if expires.After(time.Now()) && time.Until(expires) > a.MaxAuthDuration {
		// Limit to MaxAuthDuration
		expires = time.Now().Add(a.MaxAuthDuration)
	}
	return &AuthenticateOK{
		Identities:  idents, // TODO: Maybe we loose this and just use attributes?
		Expire:      expires,
		Credentials: credentials,
		Claims:      authClaims,
		Prefixes:    prefixes,
	}, nil
}

// Query runs an attribute query against datasources.
// Note that the attributes passed in the request will have prefixes on them, and
// the attributes in the response will too.
func (a *Authenticator) Query(fedreq *zds.QueryRequest) (*zds.QueryResponse, error) {
	var result *zds.QueryResponse

	a.policy.RLock() // no policy update while doing a Query
	defer a.policy.RUnlock()

	pfxq := make(map[string][]string)
	for _, k := range fedreq.GetAttrKeys() {
		pfx, ak := prefixRest(k)
		if pfx == "" {
			// No prefix? ignore.
			continue
		}
		pfxq[pfx] = append(pfxq[pfx], ak)
	}
	if len(pfxq) == 0 {
		return nil, fmt.Errorf("query failed: no prefixes in query keys")
	}
	revokes := a.loadRevocationData()
	errcount := 0
	for pfx, attrlist := range pfxq {
		var err error
		var resp *zds.QueryResponse
		if a.policy.localPrefixes[pfx] {
			// Is a local prefix, so no query.
			err = ErrNotSupported
		} else {
			preq := &zds.QueryRequest{
				TokenList: fedreq.TokenList, // pass all tokens
				AttrKeys:  attrlist,         // but only attrs from the prefix
			}
			resp, err = a.policy.validators.QueryByPrefix(pfx, preq, revokes)
		}
		if err != nil {
			// If there are multiple prefixes to search, just log the error and continue.
			// If there is just the one, return the error.
			errcount++
			if len(pfxq) == 1 {
				return nil, err
			}
			a.log.WithError(err).Warn("query failed", "prefix", "pfx")
			continue
		}
		if resp != nil {
			// TODO: Could use TTL to cache entire query...
			if len(resp.GetAttrs()) > 0 {
				if result.Ttl == 0 || resp.Ttl < result.Ttl {
					result.Ttl = resp.Ttl
				}
				for _, a := range resp.GetAttrs() {
					a.Key = fmt.Sprintf("%v.%v", pfx, a.Key)
					result.Attrs = append(result.Attrs, a)
				}
			}
		}
	}
	if errcount == len(pfxq) {
		return nil, errQueryFailed
	}
	return result, nil
}

// revoke by a KEY id
func (a *Authenticator) RevokeAuthority(ID string) error {
	var rs RevocationService
	a.rvkSvc.RLock()
	rs = a.rvkSvc.service
	a.rvkSvc.RUnlock()
	if rs == nil {
		return errors.New("revocation service is not set")
	}
	a.policy.RLock()
	defer a.policy.RUnlock()
	rs.ProposeRevokeAuthority(fmt.Sprintf("%d%s", a.policy.configID, a.policy.version), ID)
	return nil
}

// revoke by a JTI
func (a *Authenticator) RevokeCredential(ID string) error {
	var rs RevocationService
	a.rvkSvc.RLock()
	rs = a.rvkSvc.service
	a.rvkSvc.RUnlock()
	if rs == nil {
		return errors.New("revocation service is not set")
	}
	a.policy.RLock()
	defer a.policy.RUnlock()
	rs.ProposeRevokeCredential(fmt.Sprintf("%d%s", a.policy.configID, a.policy.version), ID)
	return nil
}

// isJWTRevoked check if the passed JWT has an id value (jti) that matches a revoked
// credential.
func isJWTRevoked(jwtStr string, revokes []*snauth.CredID) bool {
	jti := snauth.GetStrClaimFromJWTStr("jti", jwtStr)
	if jti == "" {
		return false
	}
	// Only possible if we have a JTI type revocation...
	found := false
	for _, rv := range revokes {
		if rv.CType == snauth.CredIDTypeCertificate {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	for _, rv := range revokes {
		if rv.CType == snauth.CredIDTypeCertificate {
			if rv.ID == jti {
				return true
			}
		}
	}
	return false
}

// loadRevocation data massages the revocation data from shared state into an array of snauth.CredID
// (which is an older interface).
//
// Must hold the a.policy mutex.
func (a *Authenticator) loadRevocationData() []*snauth.CredID {
	var rs RevocationService
	a.rvkSvc.RLock()
	rs = a.rvkSvc.service
	a.rvkSvc.RUnlock()
	if rs == nil {
		return nil
	}

	var revokes []*snauth.CredID
	for _, rk := range rs.ListRevocationKeysFor(fmt.Sprintf("%d%s", a.policy.configID, a.policy.version)) {
		if revRec := rs.GetRevoke(rk); revRec != nil {
			if ctv := raftRevokeTypeToSnauthCredIDType(revRec.GetRType()); ctv != snauth.CredIDTypeNil {
				revokes = append(revokes, &snauth.CredID{
					CType: ctv,
					ID:    revRec.GetCredId(),
				})
			}
		}
	}
	return revokes
}

// Call with mutex on a.policy
func (a *Authenticator) authenticateExtern(externReq *zds.ValidateRequest, dsPrefix string, revokes []*snauth.CredID) (*ValidateResult, error) {
	// TODO: How come we do not need to check policy auths with the EXT
	//       validation?
	externResponse, err := a.policy.validators.Validate(dsPrefix, externReq, revokes)
	if err != nil {
		a.log.WithError(err).Info("external validate failed, auth denied", "prefix", dsPrefix)
		return nil, err
	}
	// Finally:
	if externResponse.VResp.GetStat() == zds.ValidateResponse_SUCCESS {
		// The AgentID is a JWT token. Its possible this has been revoked by JTI value.
		if isJWTRevoked(string(externResponse.VResp.GetToken()), revokes) {
			a.log.Info("externally generated JWT is on revoke list, auth fails")
			return nil, errAuthRevoked
		}
	} else {
		a.log.Info("external validation has failed", "error", externResponse.VResp.GetError())
	}
	return externResponse, nil
}

// Should have a mutex on a.policy
func (a *Authenticator) authenticateIntern(internReq *zds.ValidateRequest, revokes []*snauth.CredID) (*ValidateResult, error) {
	internResponse, err := a.local.Validate(internReq, a.policy.policy, revokes)
	if err != nil {
		a.log.WithError(err).Info("internal validate failed")
		return internResponse, nil
	}
	if internResponse.VResp.GetStat() != zds.ValidateResponse_SUCCESS {
		a.log.Info("internal validation has failed", "error", internResponse.VResp.GetError())
		return internResponse, nil
	}
	if isJWTRevoked(string(internResponse.VResp.GetToken()), revokes) {
		a.log.Info("internally generated JWT is on revoke list, auth fails")
		return nil, errAuthRevoked
	}
	return internResponse, nil
}

func (a *Authenticator) extractExpireAndCredFromJWT(token string) (time.Time, string) {
	// The TTL value is for the attributes, the token itself has the auth expiration
	// on it.
	var expires time.Time
	tokExp := snauth.GetInt64ClaimFromJWTStr("exp", token)
	if tokExp == 0 {
		a.log.Warn("token without expires")
		expires = time.Now().Add(a.MaxAuthDuration)
	} else {
		expires = time.Unix(tokExp, 0)
	}
	var credentialID string
	// The credential ID value is the JTI value in the token
	if jti := snauth.GetStrClaimFromJWTStr("jti", token); jti != "" {
		// TODO: Figure out how to segregate the credential IDs using a namespace or something.
		credentialID = jti
	} else {
		a.log.Warn("token without jti")
	}
	return expires, credentialID
}

// prefixRest takes an attribute key (assumed to have a datasource prefix on the front)
// and returns the prefix and then the remaining part of the key.
//
// eg, prefixRest(foo.bah.ha) -> (foo, bah.ha)
func prefixRest(key string) (string, string) {
	bits := strings.Split(key, ".")
	if len(bits) == 1 {
		return "", bits[0] // hmm, no prefix?
	}
	return bits[0], strings.Join(bits[1:], ".")
}

// ClearRevocationList should be called when a new policy is installed.
func (a *Authenticator) clearRevocationList(forConfig uint64, forPolicy string) {
	a.rvkSvc.RLock()
	defer a.rvkSvc.RUnlock()
	if a.rvkSvc.service != nil {
		a.rvkSvc.service.ProposeClearAllRevokes(fmt.Sprintf("%d%s", forConfig, forPolicy))
	}
}

// setInternalPrefixes sets the list of internal prefixes from policy.
// Must hold the policy mutex.
func (a *Authenticator) setInternalPrefixes(pfxs []string) {
	locals := make(map[string]bool)
	for _, p := range pfxs {
		locals[p] = true
	}
	a.policy.localPrefixes = locals
}

// updateVStoreFromPolicy checks policy to see if there is an auth service defined.
// If so, extract the certifiate and install it into the validator store.
//
// Should hold read mutex over the local policy.
//
// TODO: Though we set the internal prefixes here too, it's not clear how they relate to validation.
func (a *Authenticator) updateVStoreFromPolicy(p *polio.Policy) error {
	extPrefixes := make(map[string]string) // prefix -> Name
	var intPrefixes []string

	// This installs non-internal certificates.
	for _, svc := range p.GetServices() {
		if svc.Type == polio.SvcT_SVCT_AUTH {
			a.log.Info("found external prefix", "prefix", svc.Prefix)
			extPrefixes[svc.Prefix] = svc.GetName()
		}
	}

	pool := snauth.NewCertCollection()

	for _, c := range p.GetCertificates() {
		if svcName, found := extPrefixes[c.Name]; found {
			cert, err := x509.ParseCertificate(c.GetAsn1Data())
			if err != nil {
				// Uh oh, invalid cert embedded in policy
				return fmt.Errorf("failed to parse cert for %v: %v", c.Name, err)
			}
			// In the authenticator, certs are associated with a service
			// name (aka a domain):
			pool.AddCert(svcName, cert) // TODO: Why not just use prefix? Why do we need a name too?
			a.log.Info("adding certificate", "prefix", c.Name, "name", svcName)
		} else {
			// Must be in internal prefix.
			a.log.Info("found internal prefix", "prefix", c.Name)
			intPrefixes = append(intPrefixes, c.Name)
		}
	}

	a.policy.validators.Pool = pool
	a.setInternalPrefixes(intPrefixes)
	return nil
}
