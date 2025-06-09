package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"zpr.org/vs/pkg/actor"
	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/tsapi"

	"zpr.org/vsx/polio"
)

var (
	errAuthFailed  = errors.New("authentication failed")
	errAuthRevoked = errors.New("key or credential has been revoked")
	errQueryFailed = errors.New("query operation failed")
)

const AUTH_PREFIX_BOOTSTRAP = "zpr.ss"

// Authenticator is responsible for running all authentication on the node either
// by calling to an external service or using local (cert-style) validation.
//
// Implements vsa.AuthService interface.
type Authenticator struct {
	log             logr.Logger
	ep              netip.Addr
	MaxAuthDuration time.Duration
	privateKey      *rsa.PrivateKey
	name            string // name of this visa service

	rvkSvc struct {
		rdb     *RevokeDB
		service RevocationService // let over from protytpe -- now is just self
	}

	policy struct {
		sync.RWMutex

		configID               uint64          // active configuration
		version                string          // active policy
		policy                 *policy.Policy  // is-a CertificateDB
		localPrefixes          map[string]bool // prefix -> TRUE (derived from policy)
		validators             *Directory      // (derived from policy)
		authenticationServices []string        // list of authentication service names
	}
}

type ValidateResult struct {
	Prefix       string // Prefix which did the validation
	DomainCredID string // Credential ID of the validation domain (if any)
	Token        string // The JWT identity token
	Attrs        map[string]*actor.ClaimV
	Expiration   time.Time
}

// NewAuthenticator
// It is critical to keep this instance up to date with policy version so that it
// is using the correct revocation details.
//
// `ep` is this nodes ZPR address (used as a point-of-entry ID)
// `vsName` is a name for this visa service -- added as metadata to all JWTs we create.
// `privateKey` is the key used to sign JWTs we create post validation.
func NewAuthenticator(mlog logr.Logger, ep netip.Addr, maxAuthLifetime time.Duration, vsName string, privateKey *rsa.PrivateKey) *Authenticator {
	ath := &Authenticator{
		log:             mlog,
		ep:              ep,
		MaxAuthDuration: maxAuthLifetime,
		privateKey:      privateKey,
		name:            vsName,
	}
	ath.policy.validators = NewDirectory(snauth.NewCertCollection(), mlog)
	ath.policy.localPrefixes = make(map[string]bool)
	ath.rvkSvc.rdb = NewRevokeDB()
	ath.rvkSvc.service = ath
	return ath
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
// This is computed from the validate-uri.
// TODO: We want the protocol name too (URI scheme).
func getAuthEndpoint(svc *polio.Service) *snip.Endpoint {
	if svc.ValidateUri == "" {
		return nil
	}
	svcUrl, err := url.Parse(svc.ValidateUri)
	if err != nil {
		return nil
	}
	if pn, err := strconv.Atoi(svcUrl.Port()); err == nil {
		return snip.NewEndpoint(policy.AuthProtocol, uint16(pn)) // TCP
	}
	return nil
}

// Sets the actor providing the datasource.
//
// The `configID` is the configuration ID at the last time the actor authenticated and was
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

	// In policy an auth service has URIs that use localhost since at policy time
	// we don't know the actual address.  We rewrite them here.  The URIs also
	// use our own custom SCHEMEs so we can use that to use different protocols
	// for auth services.   Currently we only support "zpr-validation2" which is
	// actually HTTPS using our special OAuth protocol (eg, what BAS provides).
	urlp, err := url.Parse(psvc.ValidateUri)
	if err != nil {
		a.log.Error("failed to parse validate-uri stored in policy", "service", service, "uri", psvc.ValidateUri, "error", err)
		return errors.New("policy error: invalid validate-uri")
	}
	if urlp.Scheme != "zpr-validation2" {
		a.log.Error("invalid validate-uri scheme (expected zpr-validation2)", "service", service, "uri", psvc.ValidateUri)
		return errors.New("policy error: invalid validate-uri scheme")

	}
	urlp.Scheme = "https"
	urlp.Host = fmt.Sprintf("[%s]", contactAddr.String()) // Note IPv6
	urlp.Path = "/token"
	fixedValidateUri := urlp.String()

	nsMap := a.createNamespaceMap(service, psvc.GetAttrs(), psvc.GetIdAttrs())

	// TODO: Update this when we implement Query

	features := DSFeatures{
		SupportValidation: psvc.ValidateUri != "",
		SupportQuery:      psvc.QueryUri != "",
		ValidationUri:     fixedValidateUri,
		QueryUri:          psvc.QueryUri,
		TLSDomain:         psvc.Domain,
		NsMap:             nsMap,
	}

	// TODO: Needs thought
	// - What are we doing with the adapter facing service info?
	return a.policy.validators.AddService(
		psvc.GetPrefix(),
		contactAddr,
		&features,
		configID)
}

// createNamespaceMap creates a map of attribute keys to their namespaces and identity status based
// on information held in policy for the trusted service.
func (a *Authenticator) createNamespaceMap(service string, attrs []string, idAttrs []string) map[string]AttrInfo {
	nsMap := make(map[string]AttrInfo)
	for _, attrWithPfx := range attrs {
		key, ns, ok := a.keyAndNsForAttr(attrWithPfx)
		if !ok {
			a.log.Warn("failed to parse prefix from attribute in policy", "attr", attrWithPfx, "service", service)
			continue
		}
		nsMap[key] = AttrInfo{
			namespace: ns,
			identity:  false,
		}
	}
	for _, attrWithPfx := range idAttrs {
		key, ns, ok := a.keyAndNsForAttr(attrWithPfx)
		if !ok {
			a.log.Warn("failed to parse prefix from identity attribute in policy", "attr", attrWithPfx, "service", service)
			continue
		}
		if ai, found := nsMap[key]; found {
			// If we already have this key, just set the identity flag.
			ai.identity = true
			nsMap[key] = ai
		} else {
			nsMap[key] = AttrInfo{
				namespace: ns,
				identity:  true,
			}
		}
	}
	return nsMap
}

func (a *Authenticator) keyAndNsForAttr(attr string) (string, actor.Namespace, bool) {
	pfxstr, rest, ok := strings.Cut(attr, ".")
	if !ok {
		return "", 0, false // no prefix
	}
	if pfx, ok := actor.ParseNamespace(pfxstr); ok {
		return rest, pfx, true
	}
	return "", 0, false
}

// Authenticate - perform authentication at the node.
//
// Returns error if authentication fails for any reason.
//
// A non nil error return from this means that caller must signal the link
// with failure signal. If nil, it is taken care of.
//
// TODO: Eventually we want to support multiple prefixes. The calling code actually may end
// up setting extDsPrefix to a comma separated list. That is not yet supported here.
//
// It is also a little odd that we expect this function to determine if it needs
// to use external auth or not, yet we also need to provide a DsPrefix only if
// external auth is needed.
func (a *Authenticator) Authenticate(dsPrefix string, epID netip.Addr, blob Blob, unauthClaims map[string]string) (*AuthenticateOK, error) {

	var err error

	a.policy.RLock()
	if a.policy.version == "" {
		a.policy.RUnlock()
		return nil, errors.New("cannot authenticate because policy is not set")
	}
	a.policy.RUnlock()

	// If prefix is our special BOOTSTRAP type, we check that we got a self-signed
	// blob and validate the signature based on public key for the CN held in policy.
	//
	// Prefix must be known to us as a configured and active authentication service.
	// If so, we can use the http api to talk to the service by sending over the blob
	// and asking them to confirm it and return attributes. (TODO)
	//
	// If prefix is unknown we just return error.

	var vresponse *ValidateResult
	if dsPrefix == AUTH_PREFIX_BOOTSTRAP {
		vresponse, err = a.authenticateSS(epID, blob, unauthClaims)
	} else {
		vresponse, err = a.authenticateAC(dsPrefix, epID, blob, unauthClaims)
	}

	if err != nil {
		a.log.WithError(err).Info("authentication error", "prefix", dsPrefix)
		return nil, errAuthFailed
	}

	// We keep the minimum expire time.
	var expires time.Time
	var credentials []string // certficate IDs

	expTS, credentialID := a.extractExpireAndCredFromJWT(vresponse.Token)

	if credentialID != "" {
		credentials = append(credentials, credentialID)
	}

	if expires.IsZero() || expTS.Before(expires) {
		expires = expTS
	}

	if vresponse.DomainCredID != "" {
		credentials = append(credentials, vresponse.DomainCredID)
	}

	for _, cd := range a.loadRevocationData() {
		for _, credential := range credentials {
			switch cd.CType {
			case snauth.CredIDTypeAuthority:
				a.log.Info("TODO: not sure how to check this revocation type AUTHORITY", "value", cd.ID) // TODO
			case snauth.CredIDTypeCertificate:
				if cd.ID == credential {
					a.log.Info("auth fails due to revoked credential", "credential_id", cd.ID)
					return nil, errAuthRevoked
				}
			case snauth.CredIDTypeVisaID:
				// nothing to do with us
			case snauth.CredIDTypeCN:
				if actorCn, ok := vresponse.Attrs[actor.KAttrCN]; ok {
					if strings.ToLower(actorCn.V) == cd.ID {
						a.log.Info("auth fails due to revoked CN", "cn", cd.ID)
						return nil, errAuthRevoked
					}
				}
			default:
				panic("unknown credential type")
			}
		}
	}

	if expires.After(time.Now()) && time.Until(expires) > a.MaxAuthDuration {
		// Limit to MaxAuthDuration
		expires = time.Now().Add(a.MaxAuthDuration)
	}

	return &AuthenticateOK{
		Identities:  []string{vresponse.Token},
		Expire:      expires,
		Credentials: credentials,
		Claims:      vresponse.Attrs,
		Prefixes:    []string{vresponse.Prefix},
	}, nil
}

func (a *Authenticator) authenticateAC(dsPrefix string, epID netip.Addr, blob Blob, _unauthClaims map[string]string) (*ValidateResult, error) {
	acBlob, ok := blob.(*ZdpAuthCodeBlob)
	if !ok {
		return nil, fmt.Errorf("authentication failed: blob is not an auth-code blob")
	}

	a.policy.RLock()
	vdators := a.policy.validators
	configID := a.policy.configID
	a.policy.RUnlock()

	vres, err := vdators.Validate(dsPrefix, acBlob, a.loadRevocationData())
	if err != nil {
		return nil, err
	}

	// Hmm what do we do with unauthClaims?
	// How to get expiration? Should come from auth service (exp value on a JWT??)
	if epID.IsValid() {
		vres.Attrs[actor.KAttrEPID] = actor.NewClaimV(epID.String(), vres.Expiration)
	}
	vres.Attrs[actor.KAttrAuthority] = actor.NewClaimV(dsPrefix, vres.Expiration)
	vres.Attrs[actor.KAttrConfigID] = actor.NewClaimV(strconv.FormatUint(configID, 10), vres.Expiration)
	vres.Attrs[actor.KAttrCN] = actor.NewClaimV(acBlob.ClientId, vres.Expiration)

	return vres, nil
}

// TODO: Note that if authentication (based on key in policy) is successful, we will copy the
// passed `epID` address here into the claims as a 'zpr.addr' claim. This is not quite correct
// and we have not yet determined where we will make the address assignments.  For now the
// adapter is still setting its own address and telling the node which ends up passing it
// up here to the visa service.
func (a *Authenticator) authenticateSS(epID netip.Addr, blob Blob, unauthClaims map[string]string) (*ValidateResult, error) {

	ssb, ok := blob.(*ZdpSelfSignedBlob)
	if !ok {
		return nil, fmt.Errorf("authentication failed: blob is not a self-signed blob")
	}

	// TODO: We could accept the CN in the blob since the node should have checked it.
	// But I think the node sets the CN in the authenticated claims, so we load it there.
	// At any rate, that one must match the blob too.
	var actorCN string
	if cn, ok := unauthClaims[actor.KAttrCN]; ok {
		actorCN = cn
	} else {
		return nil, fmt.Errorf("authentication failed: no CN found in unauthenticated claims")
	}

	expiration := time.Now().Add(a.MaxAuthDuration)

	a.policy.RLock()
	configID := a.policy.configID
	a.policy.RUnlock()

	// TODO: Should we integrate nodes with our bootstrap scheme?  For now presence of the node claim skips signature checking.

	isNode := false
	if nv, ok := unauthClaims[actor.KAttrRole]; ok {
		if nv == "node" {
			isNode = true
		}
	}

	if !isNode {
		a.policy.RLock()
		pubkey, err := a.policy.policy.GetPublicKeyForCN(actorCN)
		a.policy.RUnlock()
		if err != nil {
			return nil, fmt.Errorf("authentication failed: no public key found for CN %v", actorCN)
		}

		success, err := ssb.VerifySignature(actorCN, pubkey)
		if err != nil {
			return nil, fmt.Errorf("authentication failed: %v", err)
		}
		if !success {
			return nil, fmt.Errorf("authentication failed: signature verification failed")
		}
		a.log.Info("bootstrap blob signature verified", "cn", actorCN)
	}

	// TODO: What else to put in claims?
	attrs := make(map[string]*actor.ClaimV)

	if epID.IsValid() {
		attrs[actor.KAttrEPID] = &actor.ClaimV{
			V:   epID.String(),
			Exp: expiration,
		}
	}
	attrs[actor.KAttrAuthority] = &actor.ClaimV{
		V:   AUTH_PREFIX_BOOTSTRAP,
		Exp: expiration,
	}
	attrs[actor.KAttrConfigID] = &actor.ClaimV{
		V:   strconv.FormatUint(configID, 10),
		Exp: expiration,
	}
	attrs[actor.KAttrCN] = &actor.ClaimV{
		V:   actorCN,
		Exp: expiration,
	}

	snjwt, err := a.makeJWT(actorCN, expiration, nil, nil)
	if err != nil {
		a.log.WithError(err).Error("authenticateSS: JWT create failed")
		snjwt = "jwt_create_failed"
	}

	vr := ValidateResult{
		Prefix:       AUTH_PREFIX_BOOTSTRAP,
		DomainCredID: "",
		Token:        snjwt,
		Attrs:        attrs,
	}

	return &vr, nil
}

// makeJWT construct a signed JWT for returning as the "actorID". This can
// be retrieved by clients on surenet using the whois function.
func (a *Authenticator) makeJWT(subject string, expiration time.Time, issuers, credIDs []string) (string, error) {
	claims := jwt.MapClaims{
		actor.JWTXAuthCount: len(issuers),
		"sub":               subject,
		"aud":               "zpr",
		"iss":               a.name,
		"iat":               time.Now().Unix(),
		"exp":               expiration.Unix(),
		"nbf":               time.Now().Add(-1 * time.Minute).Unix(),
		"jti":               snauth.NewJTI(),
	}
	for i, isr := range issuers {
		claims[fmt.Sprintf("%s.%d", actor.JWTXAuthIssuerPfx, i)] = isr
		claims[fmt.Sprintf("%s.%d", actor.JWTXAuthIDPfx, i)] = credIDs[i]
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(a.privateKey)
}

// Query runs an attribute query against datasources.
// Note that the attributes passed in the request will have prefixes on them, and
// the attributes in the response will too.
func (a *Authenticator) Query(fedreq *tsapi.QueryRequest) (*tsapi.QueryResponse, error) {
	return nil, fmt.Errorf("query not yet implemented")
	/* OFF FOR NOW - not yet implemented for ref impl
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
	*/
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

// Returns the expiration time and the JTI value from the token.
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

// revoke by a KEY id (just updates the revocation list)
func (a *Authenticator) RevokeAuthority(ID string) error {
	rs := a.rvkSvc.service
	a.policy.RLock()
	defer a.policy.RUnlock()
	rs.ProposeRevokeAuthority(fmt.Sprintf("%d%s", a.policy.configID, a.policy.version), ID)
	return nil
}

// revoke by a JTI (just updates the revocation list)
func (a *Authenticator) RevokeCredential(ID string) error {
	rs := a.rvkSvc.service
	a.policy.RLock()
	defer a.policy.RUnlock()
	rs.ProposeRevokeCredential(fmt.Sprintf("%d%s", a.policy.configID, a.policy.version), ID)
	return nil
}

// revoke by a CN (just updates the revocation list)
func (a *Authenticator) RevokeCN(cn string) error {
	rs := a.rvkSvc.service
	a.policy.RLock()
	defer a.policy.RUnlock()
	rs.ProposeRevokeCN(fmt.Sprintf("%d%s", a.policy.configID, a.policy.version), cn)
	return nil
}

// loadRevocation data massages the revocation data from shared state into an array of snauth.CredID
// (which is an older interface).
//
// Must hold the a.policy mutex.
func (a *Authenticator) loadRevocationData() []*snauth.CredID {
	rs := a.rvkSvc.service
	if rs == nil {
		return nil
	}
	var revokes []*snauth.CredID
	for _, rk := range rs.ListRevocationKeysFor(fmt.Sprintf("%d%s", a.policy.configID, a.policy.version)) {
		if revRec := rs.GetRevoke(rk); revRec != nil {
			revokes = append(revokes, &snauth.CredID{
				CType: raftRevokeTypeToSnauthCredIDType(revRec.GetRType()),
				ID:    revRec.GetCredId(),
			})
		}
	}
	return revokes
}

// ClearRevocationList should be called when a new policy is installed.
func (a *Authenticator) clearRevocationList(forConfig uint64, forPolicy string) {
	a.rvkSvc.service.ProposeClearAllRevokes(fmt.Sprintf("%d%s", forConfig, forPolicy))
}

func (a *Authenticator) ClearAllRevokes() uint32 {
	return a.rvkSvc.service.ProposeClearAllRevokes("")
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

// setAuthenticationServices sets the list of authentication service names from policy.
func (a *Authenticator) setAuthenticationServices(services []string) {
	a.policy.authenticationServices = services
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
	var authServices []string

	// This installs non-internal certificates.
	for _, svc := range p.GetServices() {

		switch svc.Type {
		case polio.SvcT_SVCT_AUTH:
			a.log.Info("found external prefix", "prefix", svc.Prefix)
			extPrefixes[svc.Prefix] = svc.GetName()

		case polio.SvcT_SVCT_ACTOR_AUTH:
			a.log.Info("found actor authentication service", "prefix", svc.Name)
			authServices = append(authServices, svc.Name)
		}

		if svc.Type == polio.SvcT_SVCT_AUTH {
		}
	}

	pool := snauth.NewCertCollection()
	for _, c := range p.GetCertificates() {
		a.log.Info("found a certifiate", "name", c.Name)
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
			a.log.Info("found internally validated prefix", "prefix", c.Name)
			intPrefixes = append(intPrefixes, c.Name)
		}
	}

	a.policy.validators.Pool = pool
	a.setInternalPrefixes(intPrefixes)
	a.setAuthenticationServices(authServices)
	return nil
}
