package auth

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"zpr.org/vs/pkg/actor"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/tsapi"
)

const AuthServiceTimeout = 77 * time.Second

var (
	errInvalidAddress   = errors.New("empty/invalid IP service address")
	errValidateFail     = errors.New("validate failed")
	errUnknownValidator = errors.New("unknown validator domain")
	ErrNotSupported     = errors.New("operation not supported")
	ErrUnknownPrefix    = errors.New("unknown prefix")
)

// DSFeatures for data source features
type DSFeatures struct {
	SupportValidation bool
	ValidationUri     string
	SupportQuery      bool
	QueryUri          string
	TLSDomain         string              // optional TLS domain name
	NsMap             map[string]AttrInfo // Namespace map for attributes
}

type OAuthValidateResponse struct {
	AccessToken string // JWT
	ExpiresIn   time.Duration
}

type NewQueryResponse struct{} // TODO

func (f *DSFeatures) ShortStr() string {
	if f.SupportValidation && f.SupportQuery {
		return "V+Q"
	} else if f.SupportValidation {
		return "V"
	} else if f.SupportQuery {
		return "Q"
	} else {
		return "NONE"
	}
}

type AttrInfo struct {
	namespace actor.Namespace
	identity  bool
}

// VLoc is a "Validation service LOCation"
type VLoc struct {
	configID      uint64 // Config ID when actor connected and was permitted to add itself
	contactAddr   netip.Addr
	Prefix        string // The data source prefix for this source
	Domain        string // Used for TLS (must match the TLS cert)
	log           logr.Logger
	allowQuery    bool
	allowValidate bool
	queryUri      string
	validationUri string
	nsMap         map[string]AttrInfo // Namespace map for attributes
}

// Directory manages a collection of (external) validators (ie, simplev)
// This has turned out to be somewhat overkill as there is as most one (external) validator in surenet.
type Directory struct {
	mtx     *sync.RWMutex
	m       map[string]*VLoc // prefix -> VLoc
	CertDir string
	Pool    *snauth.CertCollection
	log     logr.Logger
}

// NewValidatorStore create store, also set the certDir where certificates
// can be located.
func NewDirectory(certs *snauth.CertCollection, log logr.Logger) *Directory {
	if certs == nil {
		certs = snauth.NewCertCollection()
	}
	return &Directory{
		mtx:  &sync.RWMutex{},
		m:    make(map[string]*VLoc),
		Pool: certs,
		log:  log,
	}
}

// Empty returns true if there are no validators.
func (vs *Directory) Empty() bool {
	vs.mtx.Lock()
	defer vs.mtx.Unlock()
	return len(vs.m) == 0
}

// Size returns number of services
func (vs *Directory) Size() int {
	vs.mtx.RLock()
	defer vs.mtx.RUnlock()
	return len(vs.m)
}

// Possibly slow function. Needs to make a RPC call to a validator.
//
// The `revokes` revocation list is used to deny validation to certificates from
// the external service.
// For certificate type revocations, we use the JWT `jti` property to match.
// For authority type revocations we use the authority key fingerprint.
//
// Returns ErrNotSupported if domain (why not prefix?) does not support validate.
func (vs *Directory) Validate(dsPrefix string, msg *ZdpAuthCodeBlob, revokes []*snauth.CredID) (*ValidateResult, error) {
	vs.mtx.RLock()
	v, ok := vs.m[dsPrefix]
	if ok && !v.allowValidate {
		vs.mtx.RUnlock()
		return nil, ErrNotSupported
	}
	vs.mtx.RUnlock()
	if !ok {
		return nil, errUnknownValidator
	}

	var err error
	var pool *x509.CertPool
	var domFinger *snauth.Fingerprint
	if v.Domain != "" {
		pool, domFinger, err = vs.certPoolForDomain(v.Domain, revokes)
		if err != nil {
			return nil, err
		}
	}
	resp, err := v.validate(pool, msg)
	if err != nil {
		if errors.Is(err, ErrNotSupported) {
			vs.mtx.Lock()
			v.allowValidate = false
			vs.mtx.Unlock()
		}
		return nil, err
	}
	// The external service may succeed but the credential may be revoked.
	// So need to check the JTI.
	if jti := snauth.GetStrClaimFromJWTStr("jti", resp.AccessToken); jti != "" {
		for _, cd := range revokes {
			if cd.CType == snauth.CredIDTypeCertificate {
				if cd.ID == jti {
					vs.log.Info("auth fails due to revoked credential", "credential_id", cd.ID)
					return nil, errAuthRevoked
				}
			}
		}
	}

	expiration := time.Now().Add(resp.ExpiresIn)
	exp := snauth.GetStrClaimFromJWTStr("exp", resp.AccessToken)
	if exp != "" {
		if expInt, err := strconv.ParseInt(exp, 10, 64); err == nil {
			exptime := time.Unix(expInt, 0)
			if exptime.Before(expiration) {
				expiration = exptime // JWT is earlier than expiresIn so use that.
			}
		}
	}

	// ZPR allows setting attributes in tokens using claims with "zpra/"
	rawClaims := vs.parseZPRClaimsFromJWT(resp.AccessToken, expiration)

	// The attribute from the service are mapped into namespaces using the
	// attribute (returns & identity) information from the policy.  The claims
	// returned above are raw, eg if the policy says the service returns "user.id"
	// then the claim will have an "id" value in it (no namespace).
	claims := make(map[string]*actor.ClaimV)
	for attrName, cv := range rawClaims {
		if info, found := v.nsMap[attrName]; found {
			newName := fmt.Sprintf("%s.%s", info.namespace, attrName)
			// TODO: For now ignoring identity bit
			claims[newName] = cv
		} else {
			// Attribute from service not listed in policy, warn.
			vs.log.Warn("attribute from trusted service not listed in policy",
				"prefix", dsPrefix, "attr", fmt.Sprintf("%s:%s", attrName, cv.V))
		}
	}

	vres := &ValidateResult{
		Prefix:     dsPrefix,
		Token:      string(resp.AccessToken),
		Attrs:      claims,
		Expiration: expiration,
	}
	// Add the key fingerprint for this domain auth to the response.
	if domFinger != nil {
		vres.DomainCredID = domFinger.String()
	}
	return vres, nil
}

// parseZPRClaimsFromJWT parses the ZPR special properties from the JWT and returns a map of claims.
//
// The ZPR properties start with "zpra/" and are attribute/value pairs.
func (vs *Directory) parseZPRClaimsFromJWT(jwtStr string, expiration time.Time) map[string]*actor.ClaimV {
	claims := make(map[string]*actor.ClaimV)
	jwtClaims, err := snauth.GetAllClaimsAsStrings(jwtStr)
	if err != nil {
		vs.log.WithError(err).Error("failed to parse JWT claims", "jwt", jwtStr)
		return nil
	}
	for jwtKey, jwtVal := range jwtClaims {
		if strings.HasPrefix(jwtKey, "zpra/") {
			keyv := strings.TrimPrefix(jwtKey, "zpra/")
			claims[keyv] = actor.NewClaimV(jwtVal, expiration)
		}
	}
	return claims
}

// QueryByPrefix may return ErrNotSupported if the datasource does not support query.
// If prefix is unknown returns ErrUnknownPrefix
func (vs *Directory) QueryByPrefix(pfx string, req *tsapi.QueryRequest, revokes []*snauth.CredID) (*NewQueryResponse, error) {
	vs.mtx.RLock()
	vloc, ok := vs.m[pfx]
	vs.mtx.RUnlock()
	if !ok || vloc == nil {
		vs.log.Info("query fails, datasource prefix not found", "prefix", pfx)
		return nil, ErrUnknownPrefix
	}
	if !vloc.allowQuery {
		vs.log.Info("query fails, datasource does not support query", "prefix", pfx)
		return nil, ErrNotSupported
	}
	pool, _, err := vs.certPoolForDomain(vloc.Domain, revokes)
	if err != nil {
		return nil, err
	}
	resp, err := vloc.query(req, pool)
	if err != nil && errors.Is(err, ErrNotSupported) {
		vs.mtx.Lock()
		vloc.allowQuery = false
		vs.mtx.Unlock()
	}
	return resp, err
}

// certPoolForDomain creates and return cert pool with revokes processed. Also return
// key fingerprint for the domain cert (if found).
func (vs *Directory) certPoolForDomain(domain string, revokes []*snauth.CredID) (*x509.CertPool, *snauth.Fingerprint, error) {
	// We use the filtered pool below so the RPC call will fail if the certificate
	// is not in the pool. But, that is slow so we also do a check of the revocation
	// list first.
	domCert := vs.Pool.CertFor(domain)
	var domFinger *snauth.Fingerprint
	if domCert != nil {
		domFinger, _ = snauth.NewSHA1Fingerprint(domCert.Raw)
		for _, cd := range revokes {
			if cd.CType == snauth.CredIDTypeAuthority && domFinger.EqualAsStr(cd.ID) {
				vs.log.Info("auth fails due to revoked authority", "credential_id", cd.ID)
				return nil, domFinger, errAuthRevoked
			}
		}
	}
	return FilteredPool(vs.Pool, revokes), domFinger, nil
}

// AddLocalService registers the validation service
// It is ok to add same service more than once (does not change underlying DB)
func (vs *Directory) AddService(prefix string, contactAddr netip.Addr, features *DSFeatures, configID uint64) error {
	if !contactAddr.IsValid() || contactAddr.IsUnspecified() {
		return errInvalidAddress
	}
	if features.NsMap == nil {
		return fmt.Errorf("features.nsMap is nil for prefix %s", prefix)
	}
	vs.log.Debug("AddService", "prefix", prefix)
	vs.mtx.Lock()
	defer vs.mtx.Unlock()
	vs.log.Info("adding validations service",
		"prefix", prefix, "support", features.ShortStr(), "addr", contactAddr,
		"configID", configID)
	vs.m[prefix] = &VLoc{
		configID:      configID,
		contactAddr:   contactAddr,
		Prefix:        prefix,
		log:           vs.log,
		allowQuery:    features.SupportQuery,
		allowValidate: features.SupportValidation,
		queryUri:      features.QueryUri,
		validationUri: features.ValidationUri,
		Domain:        features.TLSDomain,
		nsMap:         features.NsMap,
	}
	return nil
}

// RemoveServiceOnContactAddr removes all services at the given contact address.
// Returns number of services removed.
func (vs *Directory) RemoveServiceOnContactAddr(addr netip.Addr) int {
	vs.mtx.Lock()
	defer vs.mtx.Unlock()
	count := 0
	for pfx, v := range vs.m {
		if addr == v.contactAddr {
			vs.log.Info("lost validator", "prefix", pfx)
			delete(vs.m, pfx)
			count++
		}
	}
	return count
}

// RemoveServiceByDomain removes the service mapped to the given domain.
// Returns number of services removed (1 or 0).
func (vs *Directory) RemoveServiceByPrefix(pfx string) int {
	vs.mtx.Lock()
	defer vs.mtx.Unlock()
	if _, found := vs.m[pfx]; found {
		delete(vs.m, pfx)
		return 1
	}
	return 0
}

func (vs *Directory) HasAuthPrefix(p string) bool {
	vs.mtx.RLock()
	defer vs.mtx.RUnlock()
	_, found := vs.m[p]
	return found
}

// JSON struct returned from the oauth token request interface on an Authorization service.
type AuthorizationToken struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    uint64 `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Error        string `json:"error"`
}

// TODO: Enable real checking of the auth service cert on TLS.
// TODO: Not sure why we are using a CertPool and not just passing a certificate?
func (v *VLoc) validate(cert *x509.CertPool, checkBlob *ZdpAuthCodeBlob) (*OAuthValidateResponse, error) {

	tr := &http.Transport{
		ResponseHeaderTimeout: 5 * time.Second,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   6 * time.Second,
	}

	// Post to try to get an authorization token.
	// Need to send form-encoded data.
	formData := url.Values{}
	formData.Set("grant_type", "authorization_code")
	formData.Set("code", checkBlob.Code)
	formData.Set("client_id", checkBlob.ClientId)
	formData.Set("redirect_url", "auth.zpr")

	v.log.Info("contacting auth service for validation", "uri", v.validationUri, "client", checkBlob.ClientId)
	resp, err := client.PostForm(v.validationUri, formData)
	if err != nil {
		// TODO: Not sure if error is set for non-200 responses...
		v.log.WithError(err).Error("failed to contact auth service", "uri", v.validationUri, "service", v.Prefix)
		return nil, fmt.Errorf("request for auth token failed")
	}

	defer resp.Body.Close()
	jsonData, err := io.ReadAll(resp.Body)
	if err != nil {
		v.log.WithError(err).Error("failed to read auth service response", "uri", v.validationUri, "service", v.Prefix)
		return nil, fmt.Errorf("i/o error with auth service")
	}
	var tokenResp AuthorizationToken
	if err = json.Unmarshal(jsonData, &tokenResp); err != nil {
		v.log.WithError(err).Error("failed to parse auth service response", "uri", v.validationUri, "service", v.Prefix, "data", string(jsonData))
		return nil, fmt.Errorf("failed to parse auth service response")
	}
	if resp.StatusCode != http.StatusOK || tokenResp.Error != "" {
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("(%d) ", resp.StatusCode))
		if tokenResp.Error != "" {
			sb.WriteString(tokenResp.Error)
		} else {
			sb.WriteString("unknown error")
		}
		errMsg := sb.String()
		v.log.Warn("auth service retruns error", "uri", v.validationUri, "service", v.Prefix, "code", resp.StatusCode, "message", errMsg)
		return nil, fmt.Errorf("auth service denied token: %s", errMsg)
	}
	return &OAuthValidateResponse{
		AccessToken: tokenResp.AccessToken,
		ExpiresIn:   time.Duration(tokenResp.ExpiresIn) * time.Second,
	}, nil
}

// query used to make a GRPC query call. Needs to be reworked with a new HTTPS api.
func (v *VLoc) query(req *tsapi.QueryRequest, pool *x509.CertPool) (*NewQueryResponse, error) {
	//creds := credentials.NewClientTLSFromCert(pool, "")
	//if err := creds.OverrideServerName(v.Domain); err != nil {
	//	return nil, fmt.Errorf("override server name failed: %w", err)
	//}
	return nil, fmt.Errorf("not implemented")
}

// FilteredPool returns a CertPool with revoked certificates not included.
func FilteredPool(cc *snauth.CertCollection, revokes []*snauth.CredID) *x509.CertPool {
	if len(revokes) == 0 {
		return cc.Pool()
	}
	var authRevs []string
	for _, cd := range revokes {
		if cd.CType == snauth.CredIDTypeAuthority {
			authRevs = append(authRevs, cd.ID)
		}
	}
	if len(authRevs) == 0 {
		return cc.Pool()
	}
	newpool := x509.NewCertPool()
	for _, c := range cc.List() {
		revoked := false
		if print, err := snauth.NewSHA1Fingerprint(c.Raw); err == nil {
			// TODO: we are ignoring errors
			for _, rev := range authRevs {
				if print.EqualAsStr(rev) {
					revoked = true
					break
				}
			}
		}
		if !revoked {
			newpool.AddCert(c)
		}
	}
	return newpool
}
