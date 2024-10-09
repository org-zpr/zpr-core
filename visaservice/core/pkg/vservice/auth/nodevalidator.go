package auth

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"zpr.org/vs/pkg/agent"
	log "zpr.org/vs/pkg/logr"
	"zpr.org/vs/pkg/snauth"
	"zpr.org/vsx/snio/zds"
)

var (
	errInvalidSignature    = errors.New("invalid signature")
	errUnsupportedCertType = errors.New("unsupported certificate type")
	errInternal            = errors.New("authentication failed (internal error)")
	errInvalidAttributes   = errors.New("invalid x509 attributes")
	errInvalidCertificate  = errors.New("invalid certificate")
	errCertificateExpired  = errors.New("certificate expired")
	errNotRSAPublicKey     = errors.New("not an RSA public key")
)

// NodeValidator takes care of running credential validation directly on the
// node -- as opposed to using an external validation service.
type NodeValidator struct {
	Log             log.Logger
	name            string
	privateKey      *rsa.PrivateKey
	maxAuthDuration time.Duration
}

// ValidityChain to hold chain of authorities. Usually just the one.
type ValidityChain struct {
	Authority string // CN
	Finger    *snauth.Fingerprint
	Parent    *ValidityChain
}

// ValidityTok is returned through validation if it succeeds.
type ValidityTok struct {
	Subject         string    // Eg, CN field
	Expires         time.Time // Expiration of auth (from certificate)
	Authority       *ValidityChain
	CertID          string            // For example a certificate fingerprint
	AA              *agent.AuthAttr   // The policy AuthAttr
	AuthorityPrefix string            // Eg, "ca0"
	AttrKey         string            // String for base attribute key.
	Claims          map[string]string // asserted properties
}

// CertificateDB can retrieve a certificate given its identifier.
// Instead of saying that we need the whole Policy struct, we can get by
// with just this interface.
type CertificateDB interface {
	ListCertificateIDs() []uint32
	GetCertificate(uint32) (*x509.Certificate, string, error)
	// TODO: We will need the "names" given to authorities in the policy file.
}

// NewNodeValidator. The `privateKey` is the key used to sign the JWT we create
// when auth succeeds. Normally this should be the surenet private key (used by
// node for the TLS connection).
//
// `name` is added as the `iss` property to all tokens we create.
func NewNodeValidator(alog log.Logger, maxAuthDuration time.Duration, name string, privateKey *rsa.PrivateKey) *NodeValidator {
	return &NodeValidator{
		Log:             alog,
		name:            name,
		privateKey:      privateKey,
		maxAuthDuration: maxAuthDuration,
	}
}

// Validate performs standalone node validation of a challenge response.
//
// `requiredAuths` are the auth attr strings from policy these may include some
// external auths and if so we ignore those.
// All required, non-external auths must be in the response from the client.
func (v *NodeValidator) Validate(msg *zds.ValidateRequest, cdb CertificateDB, revokes []*snauth.CredID) (*ValidateResult, error) {

	// TODO: At some point in future we want to support mutliple schemes for a single user.
	var vtok *ValidityTok
	for _, crb := range msg.GetCrespSet() {
		aa, err := agent.ParseAuthAttr(crb.GetRespSpec())
		if err != nil {
			return nil, fmt.Errorf("invalid spec %v", crb.GetRespSpec())
		}
		if aa.IsExternal() {
			v.Log.Info("[NV] ignoring external credential", "cred", aa.String())
			continue
		}

		if aa.T != agent.AuthTCert {
			v.Log.Info("[NV] internal validation scheme not supported", "scheme", aa.T, "auth", aa.String())
			continue
		}

		if vt, err := v.validateCert(aa, msg, crb, cdb, revokes); err != nil {
			return v.failResponse(msg, err.Error()), nil
		} else {
			vtok = vt
			break // First one wins
		}
	}
	if vtok == nil {
		// Hmm, nothing ran?
		v.Log.Warn("[NV] attempted validation with zero methods, auth fails")
		return nil, errAuthFailed
	}

	// TODO: We probably need to have multiple agent IDs -- maybe we return the
	//       certs that we have verified?  For now we are fabricating a sort of
	//       node "attestation" token, signed with surenet key and listing the
	//       type of auth and the CN of the authority who checks it.

	claims := make(map[string]*zds.Attribute)
	for k, v := range vtok.Claims {
		key := fmt.Sprintf("%v.%v", vtok.AttrKey, strings.ToLower(k))
		claims[key] = &zds.Attribute{Key: key, Val: v, Exp: vtok.Expires.Unix()}
	}

	expiration := time.Now().Add(v.maxAuthDuration)
	if vtok.Expires.Before(expiration) {
		expiration = vtok.Expires
	}

	// The JWT will get (authority_name, presetned_cert_fingerprint) pairs
	var snas []string
	snas = append(snas, fmt.Sprintf("%v:%v", vtok.AA.TypeStr(), vtok.Authority.Authority))

	// Put all the credential IDs into the JWTR
	var tokIDs []string
	if vtok.CertID != "" {
		tokIDs = append(tokIDs, vtok.CertID)
	}
	if nextC := vtok.Authority; nextC != nil {
		for nextC != nil {
			tokIDs = append(tokIDs, nextC.Finger.String())
			nextC = nextC.Parent
		}
	}
	snjwt, err := v.makeJWT(vtok.Subject, expiration, snas, tokIDs)
	if err != nil {
		v.Log.WithError(err).Error("[NV] JWT create failed")
		snjwt = "jwt_create_failed"
	}

	// Copy some claims from the user over:
	for k, kv := range msg.Claims {
		switch kk := strings.ToLower(k); kk {
		case agent.KAttrEPID:
			// Here we allow the user to request an EPID. It is therefore up to policy
			// writers to ensure that they have sufficient details in their agent lines
			// to prevent epid masquerading!
			//
			// TODO: Why is this here? This returns the EPID requested by the adapter as a "validated" claim.
			//       But why should we trust what the adapter is sending? This is not covered by the cert!
			//       Ideally we need a way to put the claims in the certificate.
			claims[kk] = &zds.Attribute{Key: kk, Val: kv, Exp: vtok.Expires.Unix()}
		default:
			// Nope! Do not copy.
			v.Log.Debug("[NV] discarding submitted claim", "claim", fmt.Sprintf("%v=%v", kk, kv))
		}
	}
	v.Log.Info("[NV] validation success", "expires", time.Until(expiration).String(), "subject", vtok.Subject)
	var attrs []*zds.Attribute // Convert the claims map into a list
	for _, a := range claims {
		attrs = append(attrs, a)
	}
	// On our response, we list the fingerprints for all credentials.
	resp := &ValidateResult{
		Prefix:       vtok.AuthorityPrefix,
		DomainCredID: vtok.CertID,
		VResp: &zds.ValidateResponse{
			Stat:  zds.ValidateResponse_SUCCESS,
			Ttl:   uint32(time.Until(expiration) / time.Second),
			Token: []byte(snjwt),
			Attrs: attrs,
		},
	}
	return resp, nil
}

// Fake validation for use during initial version of node-visaservice integration.
// To be removed eventually.
//
// This produces a result that is similar enough to a "real" validation result that the
// visa service is able to use it to enforce policy.
func (v *NodeValidator) SelfAuthenticate(reqAddr netip.Addr, claims map[string]string) (*AuthenticateOK, error) {
	expiration := time.Now().Add(v.maxAuthDuration)

	if claims[agent.KAttrCN] == "" {
		return nil, fmt.Errorf("missing required claim: %v", agent.KAttrCN)
	}

	snjwt, err := v.makeJWT(claims[agent.KAttrCN], expiration, nil, nil)
	if err != nil {
		v.Log.WithError(err).Error("[NV] JWT create failed")
		snjwt = "jwt_create_failed"
	}

	aok := &AuthenticateOK{
		Identities:  []string{snjwt},
		Expire:      expiration,
		Credentials: []string{},
		Prefixes:    []string{"zpr.adapter"},
		Claims:      make(map[string]*agent.ClaimV),
	}
	for k, v := range claims {
		if k == agent.KAttrCN {
			aok.Claims[agent.KAttrCN] = &agent.ClaimV{V: v, Exp: aok.Expire}
			continue
		}
	}
	aok.Claims[agent.KAttrEPID] = &agent.ClaimV{V: reqAddr.String(), Exp: aok.Expire}
	return aok, nil
}

// validateCert validates one of our cert type auth schemes. Either x509 or
// U2F.
func (v *NodeValidator) validateCert(submittedAA *agent.AuthAttr, msg *zds.ValidateRequest, crb *zds.ChallengeResponse, cdb CertificateDB, revokes []*snauth.CredID) (*ValidityTok, error) {
	switch submittedAA.CT {
	case agent.AuthCertTX509:
		// See if the cert has correct authority signature
		// On the node, our authorities are identifiers.

		presented, err := x509.ParseCertificate(crb.GetCertificate())
		if err != nil {
			v.Log.WithError(err).Error("[NV] failed to parse presented certificate")
			return nil, errInvalidCertificate
		}

		var authority *x509.Certificate
		signatureValid := false
		var sigErr error
		var prefix string
		tryCount := 0
		for _, cID := range cdb.ListCertificateIDs() {
			if aCert, aCertName, err := cdb.GetCertificate(cID); err == nil {
				tryCount++
				if sigErr = presented.CheckSignatureFrom(aCert); sigErr == nil {
					authority = aCert
					signatureValid = true
					prefix = aCertName
					break
				}
			}
		}
		if !signatureValid {
			if tryCount == 0 {
				v.Log.Info("[NV] no certificates, unable to validate credential, auth fails")
				return nil, errAuthFailed
			}
			v.Log.WithError(sigErr).Info("[NV] invalid signature, auth fails", "attempts", tryCount)
			return nil, errInvalidSignature
		}
		fprint, err := snauth.NewSHA1Fingerprint(presented.Raw)
		if err != nil {
			v.Log.WithError(err).Error("[NV] failed go generate cert fingerprint, auth fails")
			return nil, errAuthFailed
		}
		afprint, err := snauth.NewSHA1Fingerprint(authority.Raw)
		if err != nil {
			v.Log.WithError(err).Error("[NV] failed go generate authority cert fingerprint")
			return nil, errAuthFailed
		}
		for _, revoked := range revokes {
			if revoked.CType == snauth.CredIDTypeAuthority {
				if afprint.EqualAsStr(revoked.ID) {
					// Authority has been revoked.
					v.Log.Info("[NV] authority has been revoked", "authority_id", revoked.ID)
					return nil, errAuthRevoked
				}
				if fprint.EqualAsStr(revoked.ID) {
					v.Log.Info("[NV] certificate has been revoked", "certificate_id", revoked.ID)
					return nil, errAuthRevoked
				}
			}
		}
		if now := time.Now(); now.Before(presented.NotBefore) || now.After(presented.NotAfter) {
			v.Log.Info("[NV] certificate expired", "notBefore", presented.NotBefore, "notAfter", presented.NotAfter)
			return nil, errCertificateExpired
		}

		// Check and "validate" the "<prefix>.x509.cn" claim from the user.
		// If `ok` is TRUE then there will be a single claim in the authedClaims.
		// This is a bit generic, but the idea is that eventually we may be able to validate more claims.
		authedClaims, ok := v.validateClaims(presented, msg.Claims, prefix)
		if !ok {
			return nil, errInvalidAttributes
		}

		// Now validate the payload
		pubkey, ok := presented.PublicKey.(*rsa.PublicKey)
		if !ok {
			// Not an RSA key
			return nil, errNotRSAPublicKey
		}
		authm := snauth.NewRSAv2()
		nonce, err := snauth.TakeNonce(msg.GetChal().GetNonce(), int(crb.GetNonceOffset()))
		if err != nil {
			return nil, err
		}
		if ok, err := authm.ValidateWithKey(pubkey, nonce, crb); ok && err == nil {
			auth := &ValidityChain{
				Authority: authority.Subject.CommonName,
				Finger:    afprint,
			}
			// Success!
			return &ValidityTok{
				Subject:         presented.Subject.CommonName,
				Expires:         presented.NotAfter,
				Authority:       auth,
				CertID:          fprint.String(),
				AA:              submittedAA,
				AuthorityPrefix: prefix,
				AttrKey:         fmt.Sprintf("%v.x509", prefix),
				Claims:          authedClaims,
			}, nil
		} else if err != nil {
			v.Log.WithError(err).Info("[NV] RSAV1 validation failed") // Is this a program error or just a cert fail?
		}
		return nil, errValidateFail

	case agent.AuthCertTU2F:
		// See if the cert has correct authority signature
		// See if the props on the AuthAttr from POLICY are present in the cert.
		// Now, use the public key in the cert to check the U2F response block.
		v.Log.Error("[NV] U2F validation not implemented")
		return nil, errInternal

	default:
		return nil, errUnsupportedCertType
	}
}

func (v *NodeValidator) failResponse(req *zds.ValidateRequest, msg string) *ValidateResult {
	return &ValidateResult{
		Prefix:       "",
		DomainCredID: "",
		VResp: &zds.ValidateResponse{
			Stat:  zds.ValidateResponse_FAIL,
			Error: msg,
			Ttl:   60, // 1 minute,
		},
	}
}

// Returns the validated claims and a boolean indicating if validation succeeds or fails.
// If validation succeeds, there will be a "cn" claim in the returned.
//
// Even though the input claim has the key '<PREFIX>.x509.cn' the returned claim will have a key of 'cn'.
// TODO: This is for historical reasons and should be addressed.
func (v *NodeValidator) validateClaims(cert *x509.Certificate, claims map[string]string, prefix string) (map[string]string, bool) {
	// We only match on CN, so
	cnClaimKey := fmt.Sprintf("%s.x509.cn", strings.ToLower(prefix))
	authedClaims := make(map[string]string)

	claimVal, ok := claims[cnClaimKey]
	if !ok {
		v.Log.Error("[NV] x509 claim check fails due to missing CN claim", "expected_key", cnClaimKey)
		return authedClaims, false
	}
	if cert.Subject.CommonName != claimVal {
		v.Log.Error("[NV] CN mismatch", "expect", claimVal, "found", cert.Subject.CommonName)
		return authedClaims, false
	}

	authedClaims["cn"] = claimVal
	return authedClaims, true
}

// makeJWT construct a signed JWT for returning as the "agentID". This can
// be retrieved by clients on surenet using the whois function.
func (v *NodeValidator) makeJWT(subject string, expiration time.Time, issuers, credIDs []string) (string, error) {
	claims := jwt.MapClaims{
		agent.JWTXAuthCount: len(issuers),
		"sub":               subject,
		"aud":               "zpr",
		"iss":               v.name,
		"iat":               time.Now().Unix(),
		"exp":               expiration.Unix(),
		"nbf":               time.Now().Add(-1 * time.Minute).Unix(),
		"jti":               snauth.NewJTI(),
	}
	for i, isr := range issuers {
		claims[fmt.Sprintf("%s.%d", agent.JWTXAuthIssuerPfx, i)] = isr
		claims[fmt.Sprintf("%s.%d", agent.JWTXAuthIDPfx, i)] = credIDs[i]
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(v.privateKey)
}
