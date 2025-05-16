package auth

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"zpr.org/vs/pkg/actor"
	"zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vsx/snio/zds"
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
	TLSDomain         string // optional TLS domain name
}

type OAuthValidateResponse struct{} // TODO
type NewQueryResponse struct{}      // TODO

func (vr *OAuthValidateResponse) GetToken() []byte {
	return nil // TODO
}

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
	resp, pfx, err := v.validate(pool, msg)
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
	if jti := snauth.GetStrClaimFromJWTStr("jti", string(resp.GetToken())); jti != "" {
		for _, cd := range revokes {
			if cd.CType == snauth.CredIDTypeCertificate {
				if cd.ID == jti {
					vs.log.Info("auth fails due to revoked credential", "credential_id", cd.ID)
					return nil, errAuthRevoked
				}
			}
		}
	}
	vres := &ValidateResult{
		Prefix: pfx,
		Token:  string(resp.GetToken()),
		Attrs:  make(map[string]*actor.ClaimV), // TODO
	}
	// Add the key fingerprint for this domain auth to the response.
	if domFinger != nil {
		vres.DomainCredID = domFinger.String()
	}
	return vres, nil
}

// QueryByPrefix may return ErrNotSupported if the datasource does not support query.
// If prefix is unknown returns ErrUnknownPrefix
func (vs *Directory) QueryByPrefix(pfx string, req *zds.QueryRequest, revokes []*snauth.CredID) (*NewQueryResponse, error) {
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

// validate used to run the GRPC validation call.
//
// TODO: Now needs to run the oauth style check call to the auth service given an
// auth-code type BLOB from an adapter.
//
// Returns the PREFIX along with the response.
func (v *VLoc) validate(pool *x509.CertPool, checkBlob *ZdpAuthCodeBlob) (*OAuthValidateResponse, string, error) {

	// We may need this for TLS.  (TBD)
	// domain := v.Domain

	return nil, v.Prefix, errors.New("not implemented")
}

// query used to make a GRPC query call. Needs to be reworked with a new HTTPS api.
func (v *VLoc) query(req *zds.QueryRequest, pool *x509.CertPool) (*NewQueryResponse, error) {
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
