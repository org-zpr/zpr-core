package vservice

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"zpr.org/vs/pkg/agent"
	"zpr.org/vsx/snio/vsio"
)

func computeSignatureOverAgent(agnt *agent.Agent, key *rsa.PrivateKey) ([]byte, error) {
	digest := generateAgentCryptHash(agnt)
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func verifySignatureOverAgent(agnt *agent.Agent, keyID string, key *rsa.PublicKey) error {
	digest := generateAgentCryptHash(agnt)
	signature, ok := agnt.GetSignature(keyID)
	if !ok {
		return errors.New("signature not found or garbled")
	}
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, signature); err != nil {
		return err
	}
	return nil
}

// Returns nil if signature is valid. Does not check expiration.
func verifySignatureOverVsioAgent(agnt *vsio.Agent, keyID string, key *rsa.PublicKey) error {
	digest := generateVsioAgentCryptHash(agnt)
	signature, err := func() ([]byte, error) {
		skey := fmt.Sprintf("%s%s", agent.KAttrSignaturePfx, keyID)
		if v, ok := agnt.AuthClaims[skey]; ok {
			if sigbuf, err := agent.DecodeByteFieldSig(v.Cval); err == nil {
				return sigbuf, nil
			} else {
				return nil, fmt.Errorf("signature encoding error: %w", err)
			}
		}
		return nil, errors.New("signature not found")
	}()
	if err != nil {
		return err
	}
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, signature); err != nil {
		return err
	}
	return nil
}

func generateAgentCryptHash(agnt *agent.Agent) []byte {
	var provides []string
	provides = append(provides, agnt.GetProvides()...)
	sort.Strings(provides)
	h := sha256.New()
	h.Write([]byte(agnt.GetIdentity()))
	for _, p := range provides {
		h.Write([]byte(p))
	}
	return h.Sum(nil)
}

func generateVsioAgentCryptHash(agnt *vsio.Agent) []byte {
	var provides []string
	provides = append(provides, agnt.GetProvides()...)
	sort.Strings(provides)
	h := sha256.New()
	h.Write([]byte(agnt.GetIdent()))
	for _, p := range provides {
		h.Write([]byte(p))
	}
	return h.Sum(nil)
}
