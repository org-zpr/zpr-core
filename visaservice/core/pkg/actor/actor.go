package actor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	fmt "fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	JWTXAuthCount     = "xsnz"
	JWTXAuthIssuerPfx = "xsna"
	JWTXAuthIDPfx     = "xsnc"
)

var ZeroAddr = netip.Addr{}

// ClaimV is an actor claim with an expiration
type ClaimV struct {
	V   string    // the claim value
	Exp time.Time // claim valid until time
}

func NewClaimV(value string, exp time.Time) *ClaimV {
	return &ClaimV{
		V:   value,
		Exp: exp,
	}
}

// Actor has attributes (called claims). These are either authenticated or unsubstantiated.
// The unsubstantiated claims are submitted by the actor at connect time, these are checked
// by an authentication service which produces the authenticated claims.
//
// Nobody but authentication services should look at or trust the unsubstantiated claims.
type Actor struct {
	authenticated bool
	configID      uint64
	authClaims    map[string]*ClaimV
	authorityIDs  []string
	authTokens    []string // JWTs
	authExpires   time.Time
	authedEPID    netip.Addr // ZPR contact address
	tetherAddr    netip.Addr // ZPR tether address
	unubClaims    map[string]string
	hashval       string
	ident         string
	provides      []string // policy ID values, set at connect time.
}

func EmptyActor() *Actor {
	return &Actor{}
}

// NewActor from credentials (auth attr strings) and claims.
// Note that EPID claim must be IPv6 format.
func NewActorFromUnsubstantiatedClaims(claims map[string]string) *Actor {
	uc := make(map[string]string) // create a copy of the claims
	for k, v := range claims {
		uc[k] = v
	}
	a := &Actor{
		unubClaims: uc,
	}
	a.updateHash()
	return a
}

func NewClaimvWithExp(claims map[string]string, exp time.Time) map[string]*ClaimV {
	res := make(map[string]*ClaimV)
	for k, v := range claims {
		res[k] = &ClaimV{
			V:   v,
			Exp: exp,
		}
	}
	return res
}

// String for actor produce view of the claims.
func (a *Actor) String() string {
	var sb strings.Builder
	for k, v := range a.authClaims {
		sb.WriteString(fmt.Sprintf("(%v=%v)", k, v))
	}
	return fmt.Sprintf("Actor{ config_id:%d, AuthdClaims:%v }", a.configID, sb.String())
}

// String for a claim produce human readable claim value with expiration.
func (c *ClaimV) String() string {
	var expv string
	if c.Exp.IsZero() {
		expv = "never"
	} else {
		expv = c.Exp.Format(time.RFC3339)
	}
	return fmt.Sprintf("%v (exp=%v)", c.V, expv)
}

// SetAuthenticated sets the authenticated claims amoung other things.
//
// Note that we expect that the auth services will include some sort of actor identifer
// in the claims. We use the authenticated claims to create an actor HASH which is
// assumed to be unique (in a ZPRnet).
func (a *Actor) SetAuthenticated(authedClaims map[string]*ClaimV, expires time.Time, authorityIDs, tokens []string, configID uint64) {
	a.authClaims = make(map[string]*ClaimV)
	for k, v := range authedClaims {
		a.setAuthedClaimIgnoreHash(k, v)
	}
	a.configID = configID
	a.authExpires = expires
	a.authorityIDs = make([]string, len(authorityIDs))
	copy(a.authorityIDs, authorityIDs)
	a.authTokens = make([]string, len(tokens))
	copy(a.authTokens, tokens)
	a.authenticated = true
	a.updateHash()
}

// GetAuthExpires return the expriation time set on the authenticated state of this actor.
func (a *Actor) GetAuthExpires() time.Time {
	return a.authExpires
}

// Get configID in effect when this actor was authenticated.
func (a *Actor) GetConfigID() uint64 {
	return a.configID
}

// Update the configID
func (a *Actor) SetConfigID(id uint64) {
	a.configID = id
}

// Hash returns the actors "hashval".
func (a *Actor) Hash() string {
	return a.hashval
}

// GetIdentity returns a hash over the actor claims, excluding any that are transitory (ZPR address or dock).
func (a *Actor) GetIdentity() string {
	return a.ident
}

// SetAuthedClaim sets an authenticated claim. Alters the actor.Hash.
func (a *Actor) SetAuthedClaim(k string, v *ClaimV) {
	a.setAuthedClaimIgnoreHash(k, v)
	a.updateHash()
}

// SetAuthedClaimWithExp sets a claim and its expiration.
func (a *Actor) SetAuthedClaimWithExp(k string, v string, x time.Time) {
	a.setAuthedClaimIgnoreHash(k, &ClaimV{
		V:   v,
		Exp: x,
	})
	a.updateHash()
}

// Replaces current authed claims with the ones passed in.
func (a *Actor) SetAuthedClaims(claims map[string]*ClaimV) {
	a.authClaims = make(map[string]*ClaimV)
	for k, v := range claims {
		a.authClaims[k] = v
	}
	a.updateHash()
}

func (a *Actor) setAuthedClaimIgnoreHash(k string, v *ClaimV) {
	if a.authClaims == nil {
		a.authClaims = make(map[string]*ClaimV)
	}
	a.authClaims[k] = v
	if k == KAttrEPID {
		ipa, err := netip.ParseAddr(v.V)
		if err != nil {
			// TODO: Return error from this method!
			panic(fmt.Sprintf("invalid ZPRID (not an IPv6 address): %v", v))
		}
		a.authedEPID = ipa
		// We aren't currently using tether addrs
		a.SetTetherAddr(ipa)
	}
}

// updateHash updates the internal hashval and identity.
func (a *Actor) updateHash() {
	var identKeys, keys []string
	for k := range a.authClaims {
		if k == KAttrConnectVia {
			// Expriment: do not put connect via in hash. This helps in case where a node connects and ends up generating
			// two connect records (one locally when the remote node connects, and another from the remote node). The only
			// difference in the records is the connect_via.
			continue
		}
		keys = append(keys, k)
		if k == KAttrEPID {
			// Identity is not dependent on ZPR address (well, maybe for a service??)
			continue
		}
		identKeys = append(identKeys, k)
	}
	a.hashval = a.mkhash(keys)
	a.ident = a.mkhash(identKeys)
}

func (a *Actor) mkhash(keys []string) string {
	sort.Slice(keys, func(i, j int) bool {
		return strings.Compare(keys[i], keys[j]) < 0
	})
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte(a.authClaims[k].V))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// GetAuthedClaims READ ONLY !!
func (a *Actor) GetAuthedClaims() map[string]*ClaimV {
	return a.authClaims
}

func (a *Actor) HasAuthedClaim(key, val string) bool {
	if c, ok := a.authClaims[key]; ok {
		return c.V == val
	}
	return false
}

// GetClaims returns the unsubstantiated claims (read only)
func (a *Actor) GetClaims() map[string]string {
	return a.unubClaims
}

func (a *Actor) IsAuthenticated() bool {
	return a.authenticated
}

// GetEPID returns the authenticated ZPRID value if it is set.
// Returns ({}, FALSE) if not set.
func (a *Actor) GetZPRID() (netip.Addr, bool) {
	if a.authedEPID == ZeroAddr {
		return netip.Addr{}, false
	}
	return a.authedEPID, true
}

func (a *Actor) GetZPRIDIfSet() netip.Addr {
	addr, ok := a.GetZPRID()
	if !ok {
		return netip.Addr{}
	}
	return addr
}

func (a *Actor) SetTetherAddr(addr netip.Addr) {
	a.tetherAddr = addr
}

func (a *Actor) GetTetherAddr() netip.Addr {
	return a.tetherAddr
}

func (a *Actor) HasAuthorities() bool {
	return a.authenticated && len(a.authorityIDs) > 0
}

func (a *Actor) HasAuthority(n string) bool {
	for _, a := range a.authorityIDs {
		if a == n {
			return true
		}
	}
	return false
}

// GetAuthIDs (read only please)
func (a *Actor) GetAuthIDs() []string {
	return a.authorityIDs
}

// GetAuthTokens (read only)
func (a *Actor) GetAuthTokens() []string {
	return a.authTokens
}

func (a *Actor) SetProvides(p []string) {
	a.provides = p
}

// GetProvides list of services provided by actor. Read only.
func (a *Actor) GetProvides() []string {
	return a.provides
}

func (a *Actor) IsNode() bool {
	return a.getRole() == "node"
}

func (a *Actor) IsAdapter() bool {
	return a.getRole() == "adapter"
}

func (a *Actor) getRole() string {
	if a.authClaims == nil {
		return ""
	}
	if v, ok := a.authClaims[KAttrRole]; ok {
		return v.V
	}
	return ""
}

func (a *Actor) DoesProvide(serviceID string) bool {
	for _, id := range a.provides {
		if id == serviceID {
			return true
		}
	}
	return false
}

// TokenClaimForKey runs through all the auth tokens on this actor, gets the
// value maped to the given key for each one, and returns the set of values.
//
// Not very efficient as it requires a json decode and map build for each token.
func (a *Actor) TokenClaimForKey(key string) []interface{} {
	var vals []interface{}
	for _, tok := range a.authTokens {
		if claims, err := jwtPayload(tok); err == nil {
			if v, ok := claims[key]; ok {
				vals = append(vals, v)
			}
		}
	}
	return vals
}

// TokenKeyIDs returns the set of key IDs contained in any auth tokens on this actor.
func (a *Actor) TokenKeyIDs() []string {
	var keyIDList []string
	for _, tok := range a.authTokens {
		if claims, err := jwtPayload(tok); err == nil {
			if cns, ok := claims[JWTXAuthCount]; ok {
				if nf, ok := cns.(float64); ok {
					n := int(nf)
					// There are 'n' keys attached to this token.
					for i := 0; i < n; i++ {
						if keyID, ok := claims[fmt.Sprintf("%s.%d", JWTXAuthIDPfx, i)]; ok {
							if keyIDstr, ok := keyID.(string); ok {
								keyIDList = append(keyIDList, keyIDstr)
							}
						}
					}
				}
			}
		}
	}
	return keyIDList
}

// TokenIDs returns the set of token IDs (JTI values)  on any auth tokens on this actor.
func (a *Actor) TokenIDs() []string {
	var ids []string
	for _, jtiv := range a.TokenClaimForKey("jti") {
		if jtis, ok := jtiv.(string); ok {
			ids = append(ids, jtis)
		}
	}
	return ids
}

func jwtPayload(ss string) (map[string]interface{}, error) {
	parts := strings.Split(ss, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT, expected three parts")
	}
	parser := jwt.NewParser()
	js, err := parser.DecodeSegment(parts[1])
	if err != nil {
		return nil, err
	}

	jwtClaims := make(map[string]interface{})
	if err = json.Unmarshal(js, &jwtClaims); err != nil {
		return nil, err
	}
	return jwtClaims, nil
}
