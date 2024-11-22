package conform

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
)

func certToPEM(cert *x509.Certificate) []byte {
	blk := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return pem.EncodeToMemory(&blk)
}

// Milestone two no-crypto hmac value.
// See libnode/src/m2.rs
func newM2HMAC(challengeData []byte, sessionID int32, timestamp int64) []byte {
	var buf bytes.Buffer
	buf.Write(challengeData)
	binary.Write(&buf, binary.BigEndian, uint64(timestamp))
	binary.Write(&buf, binary.BigEndian, sessionID)
	hashed := sha256.Sum256(buf.Bytes())
	return hashed[:]
}
