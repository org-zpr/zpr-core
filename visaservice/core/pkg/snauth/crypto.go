package snauth

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

const (
	ChallengeNonceSize = 32
	AuthChallengeV1    = "chal-node-v1"
)

var (
	ErrOutOfNonce         = errors.New("out of available nonce")
	ErrInvalidNonceOffset = errors.New("invalid nonce offset")
)

// TakeNonce copies the fixed-size (see cfg) amount of random data from the
// source `nonce` and returns it in a slice. You get an error if there is
// not enough data left in `nonce`.
func TakeNonce(nonce []byte, offset int) ([]byte, error) {
	if offset < 0 || offset > len(nonce) {
		return nil, ErrInvalidNonceOffset
	}
	if len(nonce) < (offset + ChallengeNonceSize) {
		return nil, ErrOutOfNonce
	}
	nbuf := make([]byte, ChallengeNonceSize)
	copy(nbuf, nonce[offset:])
	return nbuf, nil
}

// NewNonce fill `b` with random bytes.
func NewNonce(b []byte) {
	io.ReadFull(rand.Reader, b)
}

func LoadCertFromPEMBuffer(pemdata []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemdata)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return x509.ParseCertificate(block.Bytes)
}
