package libvisa_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/libvisa"
)

func TestEncodeDecode(t *testing.T) {
	skey := []byte("the quick brown fox jumped over the lazy dog")
	secret := []byte("secret phrase")
	ciphertext, err := libvisa.EncodeKey(skey, secret)
	require.Nil(t, err)
	plaintext, err := libvisa.DecodeKey(ciphertext, secret)
	require.Nil(t, err)
	require.Equal(t, skey, plaintext)
}

func TestSessionKeyEncodingFormat1(t *testing.T) {

	skey := []byte("this is a session key")

	inKey, outKey, err := libvisa.EncodeKeysFormat1(skey)
	require.Nil(t, err)
	require.NotNil(t, inKey)
	require.NotNil(t, outKey)
}
