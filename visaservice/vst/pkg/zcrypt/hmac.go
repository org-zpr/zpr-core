package zcrypt

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

// Milestone2 no-crypto hmac value.
// See libnode/src/m2.rs
func GenM2HMAC(challengeData []byte, sessionID int32, timestamp int64) []byte {
	var buf bytes.Buffer
	buf.Write(challengeData)
	binary.Write(&buf, binary.BigEndian, uint64(timestamp))
	binary.Write(&buf, binary.BigEndian, sessionID)
	hashed := sha256.Sum256(buf.Bytes())
	return hashed[:]
}
