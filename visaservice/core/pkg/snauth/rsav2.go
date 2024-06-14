package snauth

// This was rsav1.go in the prototype.  Renamted it to v2 in anticipation
// of reworking this scheme for reference implementation.

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"path/filepath"

	"zpr.org/vsx/snio/zds"
)

type RSAV2 struct {
	BaseDir string
}

func NewRSAv2() *RSAV2 {
	return &RSAV2{}
}

func (a *RSAV2) Spec() string { return "cert:x509" }

func (a *RSAV2) WorkingDir(d string) {
	a.BaseDir = d
}

// Respond means to respond to an auth challenge. Only the holder of the
// private key can respond to the challenge ... so this is run on a CA or Node.
// config requires:
//
//	key - Path to a private key file (PEM encoded, PKCS1)
//
// optional:
//
//	cert - Path to a certificate
func (a *RSAV2) Respond(config map[string]string, chal *zds.Challenge, nonceOffset int) ([]*zds.ChallengeResponse, error) {
	var err error
	var rsaCert []byte
	if certPath, ok := config["cert"]; ok {
		rsaCert, err = LoadRSACert(certPath)
		if err != nil {
			return nil, err
		}
	} else if certData, ok := config["cert_data"]; ok {
		buf, err := base64.StdEncoding.DecodeString(certData)
		if err != nil {
			return nil, err
		}
		rsaCert, err = LoadRSACertFromPEM(buf)
		if err != nil {
			return nil, err
		}
	}
	nonce, err := TakeNonce(chal.GetNonce(), nonceOffset)
	if err != nil {
		return nil, err
	}
	tok, err := a.RespondWithToken(config, nonce)
	if err != nil {
		return nil, err
	}

	cr := &zds.RawChalResp{
		Data: tok,
	}
	crb := &zds.ChallengeResponse{
		ChalSpec:    chal.GetSpec(),
		RespSpec:    a.Spec(),
		Result:      &zds.ChallengeResponse_CrRaw{cr},
		NonceOffset: uint32(nonceOffset),
		NonceLen:    uint32(len(nonce)),
	}
	if rsaCert != nil {
		crb.Certificate = rsaCert
	}
	return []*zds.ChallengeResponse{crb}, nil
}

// RespondWithToken returns the raw signature (not yet a JWT token)
func (a *RSAV2) RespondWithToken(config map[string]string, nonce []byte) ([]byte, error) {
	var err error
	var rsapk *rsa.PrivateKey
	if kfile, ok := config["key"]; ok {
		rsapk, err = a.LoadRSAKey(kfile)
		if err != nil {
			return nil, err
		}
	} else if kdata, ok := config["key_data"]; ok {
		buf, err := base64.StdEncoding.DecodeString(kdata)
		if err != nil {
			return nil, err
		}
		rsapk, err = LoadRSAKeyFromPEM(buf)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, ErrMissingPrivateKey
	}

	// Hmm, what about the certificate?
	tok, err := a.RespondWithKeyAndCert(rsapk, nonce)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

func (a *RSAV2) RespondWithKeyAndCert(key *rsa.PrivateKey, nonce []byte) ([]byte, error) {
	sig, err := computeRSAHMAC(key, nonce)
	if err != nil {
		return nil, fmt.Errorf("signing error: %v", err)
	}
	return sig, nil
}

// Validate checks the RSA signature over the challenge from the private key holder.
// This is run in simplev.
// config requires either:
//
//	pubkey - string which is a base64 encoded, defaults to PKCS1 rsa public key (deprecated)
//	encoding - optional, can be "pkix" or "pkcs1"
//	  or
//	pubkeyfile - a PEM file relative to working dir with a PKIX encoded rsa key.
/*
func (a *RSAV2) Validate(config map[string]string, chal *zds.Challenge, ar *zds.ChallengeResponse) (*ValidationResult, error) {
	if len(config["pubkey"]) == 0 && len(config["pubkeyfile"]) == 0 {
		return nil, ErrMissingPublicKey
	}
	var err error
	var pubKey *rsa.PublicKey

	if len(config["pubkey"]) > 0 {
		buf, err := base64.StdEncoding.DecodeString(config["pubkey"])
		if err != nil {
			return nil, fmt.Errorf("failed to decode b64 encoded public key: %v", err)
		}
		if enc := strings.ToLower(config["encoding"]); enc == "" || enc == "pkcs1" {
			// Extract a base64 encoded PKCS1 rsa public key.
			pubKey, err = x509.ParsePKCS1PublicKey(buf)
			if err != nil {
				return nil, fmt.Errorf("failed to parse pkcs1 public key: %v", err)
			}
		} else if enc == "pkix" {
			pub, err := x509.ParsePKIXPublicKey(buf)
			if err != nil {
				return nil, err
			}
			if pk, ok := pub.(*rsa.PublicKey); ok {
				pubKey = pk
			} else {
				return nil, ErrUnsupportedPublicKeyType
			}
		} else {
			return nil, fmt.Errorf("unsupported key encoding: %v", enc)
		}
	} else {
		pemfile := filepath.Join(a.BaseDir, config["pubkeyfile"])
		pubKey, err = LoadRSAPublicKeyFromPKIXPEM(pemfile)
		if err != nil {
			return nil, err
		}
	}

	nonce, err := TakeNonce(chal.GetNonce(), int(ar.GetNonceOffset()))
	if err != nil {
		return nil, err
	}
	ok, err := a.ValidateWithKey(pubKey, nonce, ar)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrValidationFailed
	}
	vres := NewValidationResult(a.Spec())
	vres.Allow = true
	return vres, nil
}
*/

func (a *RSAV2) ValidateWithKey(pubKey *rsa.PublicKey, nonce []byte, ar *zds.ChallengeResponse) (bool, error) {
	sig := ar.GetCrRaw()
	if sig == nil {
		return false, fmt.Errorf("missing signature")
	}
	if err := a.ValidateSignatureWithKey(pubKey, nonce, sig.GetData()); err != nil {
		return false, err
	}
	return true, nil
}

func (a *RSAV2) ValidateSignatureWithKey(pubKey *rsa.PublicKey, nonce []byte, signature []byte) error {
	var msg bytes.Buffer
	msg.Write(nonce)
	hashed := sha256.Sum256(msg.Bytes())
	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return fmt.Errorf("signature validation failed %d byte nonce: %w", len(nonce), err)
	}
	return nil
}

func (a *RSAV2) resolvePath(p string) string {
	if !filepath.IsAbs(p) && len(a.BaseDir) > 0 {
		return filepath.Join(a.BaseDir, p)
	}
	return p
}

func (a *RSAV2) LoadRSAKey(path string) (*rsa.PrivateKey, error) {
	if path == "" {
		return nil, ErrMissingPrivateKey
	}
	kef := a.resolvePath(path)
	if len(kef) == 0 {
		return nil, fmt.Errorf("failed to locate private key at %v", path)
	}
	return LoadRSAKeyFromFile(kef)
}
