package agent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	fmt "fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"zpr.org/vsx/snio/vsio"
)

const (
	JWTXAuthCount     = "xsnz"
	JWTXAuthIssuerPfx = "xsna"
	JWTXAuthIDPfx     = "xsnc"
)

var ZeroAddr = netip.Addr{}

// ClaimV is an agent claim with an expiration
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

// Agent has attributes (called claims). These are either authenticated or unsubstantiated.
// The unsubstantiated claims are submitted by the agent at connect time, these are checked
// by an authentication service which produces the authenticated claims.
//
// Nobody but authentication services should look at or trust the unsubstantiated claims.
type Agent struct {
	authenticated bool
	configID      uint64
	authClaims    map[string]*ClaimV
	authorityIDs  []string
	authTokens    []string // JWTs
	authExpires   time.Time
	authedEPID    netip.Addr
	unubClaims    map[string]string
	hashval       string
	ident         string
	provides      []string // policy ID values, set at connect time.
}

func EmptyAgent() *Agent {
	return &Agent{}
}

// NewAgent from credentials (auth attr strings) and claims.
// Note that EPID claim must be IPv6 format.
func NewAgentFromUnsubstantiatedClaims(claims map[string]string) *Agent {
	uc := make(map[string]string) // create a copy of the claims
	for k, v := range claims {
		uc[k] = v
	}
	a := &Agent{
		unubClaims: uc,
	}
	a.updateHash()
	return a
}

// NewAgentFromSnioAgent populate this agent directly from the protocol buffer struct. No error checking.
// TODO: remove panic in here
func NewAgentFromSnioAgent(sa *vsio.Agent) *Agent {
	var exp time.Time
	if sa.GetAuthExpires() != "" {
		tv, err := time.Parse(time.RFC3339, sa.GetAuthExpires())
		if err != nil {
			panic(fmt.Sprintf("time format error: %v", err))
		}
		exp = tv
	}

	authedEPID := netip.Addr{}
	if aa := sa.GetAuthAddr(); aa != nil {
		authedEPID, _ = netip.AddrFromSlice(aa)
	}

	a := &Agent{
		authenticated: sa.GetAuthenticated(),
		configID:      sa.GetConfigId(),
		authClaims:    make(map[string]*ClaimV),
		authorityIDs:  sa.GetAuthIds(),
		authTokens:    sa.GetAuthTokens(),
		authExpires:   exp,
		authedEPID:    authedEPID,
		unubClaims:    sa.GetUnsubClaims(),
		hashval:       sa.GetHashval(),
		ident:         sa.GetIdent(),
		provides:      sa.GetProvides(),
	}
	for k, ac := range sa.GetAuthClaims() {
		a.authClaims[k] = &ClaimV{
			V:   ac.GetCval(),
			Exp: time.Unix(ac.GetExp(), 0),
		}
	}
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

// String for agent produce view of the claims.
func (a *Agent) String() string {
	var sb strings.Builder
	for k, v := range a.authClaims {
		sb.WriteString(fmt.Sprintf("(%v=%v)", k, v))
	}
	return fmt.Sprintf("Agent{ config_id:%d, AuthdClaims:%v }", a.configID, sb.String())
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
// Note that we expect that the auth services will include some sort of agent identifer
// in the claims. We use the authenticated claims to create an agent HASH which is
// assumed to be unique (in a ZPRnet).
func (a *Agent) SetAuthenticated(authedClaims map[string]*ClaimV, expires time.Time, authorityIDs, tokens []string, configID uint64) {
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

// GetAuthExpires return the expriation time set on the authenticated state of this agent.
func (a *Agent) GetAuthExpires() time.Time {
	return a.authExpires
}

// Get configID in effect when this agent was authenticated.
func (a *Agent) GetConfigID() uint64 {
	return a.configID
}

// Update the configID
func (a *Agent) SetConfigID(id uint64) {
	a.configID = id
}

// Hash returns the agents "hashval".
func (a *Agent) Hash() string {
	return a.hashval
}

// GetIdentity returns a hash over the agent claims, excluding any that are transitory (ZPR address or dock).
func (a *Agent) GetIdentity() string {
	return a.ident
}

func encodeByteFieldSig(signagure []byte) string {
	return fmt.Sprintf(":%s:", base64.StdEncoding.EncodeToString(signagure))
}

// DecodeByteFieldSig decodes a signature string value as produced by the Sign() function into a byte buffer.
func DecodeByteFieldSig(sig string) ([]byte, error) {
	if len(sig) < 2 {
		return nil, fmt.Errorf("invalid signature string")
	}
	sig = sig[1 : len(sig)-1]
	return base64.StdEncoding.DecodeString(sig)
}

// Add a signature attribute to the agents authenticated claims.
// Signautre key uses a special prefix of "zpr.signature." and the passed signature buffer
// is written in base64 surrounded by colons, `':'+base64(signature)+':'`.
func (a *Agent) Sign(keyID string, signature []byte) {
	skey := fmt.Sprintf("%s%s", KAttrSignaturePfx, keyID)
	a.setAuthedClaimIgnoreHash(skey, &ClaimV{
		V:   encodeByteFieldSig(signature),
		Exp: a.authExpires,
	})
}

// Retrieve a signature buffer previously stored on the agent.
// Ignores expiration.
func (a *Agent) GetSignature(keyID string) ([]byte, bool) {
	skey := fmt.Sprintf("%s%s", KAttrSignaturePfx, keyID)
	if v, ok := a.authClaims[skey]; ok {
		if sigbuf, err := DecodeByteFieldSig(v.V); err == nil {
			return sigbuf, true
		}
	}
	return nil, false
}

// SetAuthedClaim sets an authenticated claim. Alters the agent.Hash.
func (a *Agent) SetAuthedClaim(k string, v *ClaimV) {
	a.setAuthedClaimIgnoreHash(k, v)
	a.updateHash()
}

// SetAuthedClaimWithExp sets a claim and its expiration.
func (a *Agent) SetAuthedClaimWithExp(k string, v string, x time.Time) {
	a.setAuthedClaimIgnoreHash(k, &ClaimV{
		V:   v,
		Exp: x,
	})
	a.updateHash()
}

func (a *Agent) setAuthedClaimIgnoreHash(k string, v *ClaimV) {
	if a.authClaims == nil {
		a.authClaims = make(map[string]*ClaimV)
	}
	a.authClaims[k] = v
	if k == KAttrEPID {
		if ipa := net.ParseIP(v.V); ipa != nil {
			a.authedEPID, _ = netip.AddrFromSlice(ipa)
		} else {
			// TODO: Return error from this method!
			panic(fmt.Sprintf("invalid ZPRID (not an IPv6 address): %v", v))
		}
	}
}

// updateHash updates the internal hashval and identity.
func (a *Agent) updateHash() {
	var identKeys, keys []string
	for k := range a.authClaims {
		if k == KAttrConnectVia {
			// Expriment: do not put connect via in hash. This helps in case where a node connects and ends up generating
			// two connect records (one locally when the remote node connects, and another from the remote node). The only
			// difference in the records is the connect_via.
			continue
		}
		if strings.HasPrefix(k, KAttrSignaturePfx) {
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

func (a *Agent) mkhash(keys []string) string {
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
func (a *Agent) GetAuthedClaims() map[string]*ClaimV {
	return a.authClaims
}

// GetClaims returns the unsubstantiated claims (read only)
func (a *Agent) GetClaims() map[string]string {
	return a.unubClaims
}

func (a *Agent) IsAuthenticated() bool {
	return a.authenticated
}

// GetEPID returns the authenticated ZPRID value if it is set.
// Returns ({}, FALSE) if not set.
func (a *Agent) GetZPRID() (netip.Addr, bool) {
	if a.authedEPID == ZeroAddr {
		return netip.Addr{}, false
	}
	return a.authedEPID, true
}

func (a *Agent) HasAuthorities() bool {
	return a.authenticated && len(a.authorityIDs) > 0
}

func (a *Agent) HasAuthority(n string) bool {
	for _, a := range a.authorityIDs {
		if a == n {
			return true
		}
	}
	return false
}

// GetAuthIDs (read only please)
func (a *Agent) GetAuthIDs() []string {
	return a.authorityIDs
}

// GetAuthTokens (read only)
func (a *Agent) GetAuthTokens() []string {
	return a.authTokens
}

func (a *Agent) SetProvides(p []string) {
	a.provides = p
}

// GetProvides list of services provided by agent. Read only.
func (a *Agent) GetProvides() []string {
	return a.provides
}

func (a *Agent) GetRole() string {
	if a.authClaims == nil {
		return ""
	}
	if v, ok := a.authClaims[KAttrRole]; ok {
		return v.V
	}
	return ""
}

func (a *Agent) DoesProvide(serviceID string) bool {
	for _, id := range a.provides {
		if id == serviceID {
			return true
		}
	}
	return false
}

// TokenClaimForKey runs through all the auth tokens on this agent, gets the
// value maped to the given key for each one, and returns the set of values.
//
// Not very efficient as it requires a json decode and map build for each token.
func (a *Agent) TokenClaimForKey(key string) []interface{} {
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

// TokenKeyIDs returns the set of key IDs contained in any auth tokens on this agent.
func (a *Agent) TokenKeyIDs() []string {
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

// TokenIDs returns the set of token IDs (JTI values)  on any auth tokens on this agent.
func (a *Agent) TokenIDs() []string {
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
	js, err := jwt.DecodeSegment(parts[1])
	if err != nil {
		return nil, err
	}

	jwtClaims := make(map[string]interface{})
	if err = json.Unmarshal(js, &jwtClaims); err != nil {
		return nil, err
	}
	return jwtClaims, nil
}
