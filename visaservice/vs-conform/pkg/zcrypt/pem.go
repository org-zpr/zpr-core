package zcrypt

import (
	"crypto/x509"
	"encoding/pem"
)

func CertToPEM(cert *x509.Certificate) []byte {
	blk := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(&blk)
}
