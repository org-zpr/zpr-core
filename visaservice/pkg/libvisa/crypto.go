package libvisa

import (
	"crypto/rand"
	"io"
)

// NewNonce fill `b` with random bytes.
func NewNonce(b []byte) {
	io.ReadFull(rand.Reader, b)
}
