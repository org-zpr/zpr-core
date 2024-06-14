package snauth

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidFingerprint = errors.New("invalid fingerprint")
)

type Fingerprint struct {
	Alg FPAlg
	fp  []byte
}

type FPAlg string

const (
	FPSHA1 FPAlg = "SHA1"
)

func NewSHA1Fingerprint(asn1data []byte) (*Fingerprint, error) {
	cert, err := x509.ParseCertificate(asn1data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	fbuf := sha1.Sum(cert.Raw)
	return &Fingerprint{
		Alg: FPSHA1,
		fp:  fbuf[:],
	}, nil
}

func NewSHA1FingerprintFromBytes(fp []byte) (*Fingerprint, error) {
	if len(fp) != 20 {
		return nil, fmt.Errorf("SHA1 fingerprint requires 20 bytes, not %d", len(fp))
	}
	return &Fingerprint{
		Alg: FPSHA1,
		fp:  fp,
	}, nil
}

func ParseSHA1Fingerprint(s string) (*Fingerprint, error) {
	hexs := strings.Split(s, ":")
	if len(hexs) != 20 {
		return nil, fmt.Errorf("SHA1 fingerprint requires 20 bytes, not %d", len(hexs))
	}
	var fp []byte
	for _, hv := range hexs {
		bv, err := hex.DecodeString(hv)
		if err != nil || len(bv) != 1 {
			return nil, ErrInvalidFingerprint
		}
		fp = append(fp, bv[0])
	}
	return &Fingerprint{
		Alg: FPSHA1,
		fp:  fp,
	}, nil
}

func (f *Fingerprint) String() string {
	var bs []string
	for _, b := range f.fp {
		bs = append(bs, fmt.Sprintf("%0.2X", b))
	}
	return strings.Join(bs, ":")
}

func (f *Fingerprint) Bytes() []byte {
	return f.fp
}

func (f *Fingerprint) Equals(other *Fingerprint) bool {
	if f == nil && other == nil {
		return true
	}
	if f == nil || other == nil {
		return false
	}
	return f.Alg == other.Alg && bytes.Equal(f.fp, other.fp)
}

// EqualAsStr compares this fingerprint to the other fingerprint which is supplied
// in string form.
func (f *Fingerprint) EqualAsStr(other string) bool {
	return strings.ToUpper(f.String()) == strings.ToUpper(other)
}
