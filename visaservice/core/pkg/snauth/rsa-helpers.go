package snauth

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

var (
	ErrMissingPrivateKey        = errors.New("missing private key")
	ErrMissingCertificate       = errors.New("missing certificate")
	ErrPEMDecode                = errors.New("failed to decode private key from PEM")
	ErrMissingPublicKey         = errors.New("missing pubkey config for signature validation")
	ErrCertLoad                 = errors.New("certificate failed to load")
	ErrUnsupportedPublicKeyType = errors.New("unsupported public key type")
)

func computeRSAHMAC(rsapk *rsa.PrivateKey, nonce []byte) ([]byte, error) {
	var msg bytes.Buffer
	msg.Write(nonce)

	hashed := sha256.Sum256(msg.Bytes())
	rng := rand.Reader

	sig, err := rsa.SignPKCS1v15(rng, rsapk, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("signing error: %v", err)
	}
	return sig, nil
}

func ValidateSignatureWithKey(pubKey *rsa.PublicKey, nonce []byte, signature []byte) error {
	var msg bytes.Buffer
	msg.Write(nonce)
	hashed := sha256.Sum256(msg.Bytes())
	err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return fmt.Errorf("signature validation failed %d byte nonce: %w", len(nonce), err)
	}
	return nil
}

func LoadRSAKeyFromFile(kef string) (*rsa.PrivateKey, error) {
	// Load private key:
	pemdata, err := os.ReadFile(kef)
	if err != nil {
		return nil, err
	}
	k, err := LoadRSAKeyFromPEM(pemdata)
	if err != nil {
		return nil, fmt.Errorf("failed to load RSA key from file: %v: %v", kef, err)
	}
	return k, nil
}

func LoadRSAKeyFromPEM(pemdata []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemdata)
	if block == nil {
		return nil, ErrPEMDecode
	}
	if !strings.Contains(block.Type, "PRIVATE KEY") {
		return nil, fmt.Errorf("not a PEM private key: %v", block.Type)
	}
	rsapk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		rsapk2, err2 := x509.ParsePKCS8PrivateKey(block.Bytes) // sn and openssl generate these
		if err2 != nil {
			return nil, err
		}
		if rsak, ok := rsapk2.(*rsa.PrivateKey); ok {
			rsapk = rsak
		} else {
			return nil, err
		}
	}
	return rsapk, nil
}

func LoadRSACert(path string) ([]byte, error) {
	fdata, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadRSACertFromPEM(fdata)
}

func LoadRSACertFromPEM(pemdata []byte) ([]byte, error) {
	blk, _ := pem.Decode(pemdata)
	// TODO: Handle multiple certs (eg, certificate chain)
	if blk == nil {
		return nil, ErrCertLoad
	}
	// TODO: Check type
	return blk.Bytes, nil
}

func LoadRSAPublicKeyFromPKIXPEM(fname string) (*rsa.PublicKey, error) {
	pemdata, err := os.ReadFile(fname)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key in PEM file: %v: %v", fname, err)
	}
	block, _ := pem.Decode(pemdata)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in key file: %v", fname)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, ErrUnsupportedPublicKeyType
	}
}

func LoadRSAPublicKeyFromPKIXPEMBuffer(pemdata []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemdata)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, ErrUnsupportedPublicKeyType
	}
}

func LoadRSAPublicKeyFromPEMBuffer(pemdata []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemdata)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	return rsaPublicKey, nil
}
