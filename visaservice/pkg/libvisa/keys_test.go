package libvisa_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/libvisa"
	"zpr.org/vs/pkg/snio/vsio"
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

	visa := vsio.Visa{}

	err := libvisa.EncodeKeysFormat1(skey, &visa)
	require.Nil(t, err)

	plainEgress, err := libvisa.DecodeEgressKey(&visa, []byte("egress"))
	require.Nil(t, err)
	require.Equal(t, skey, plainEgress)

	plainIngress, err := libvisa.DecodeIngressKey(&visa, []byte("ingress"))
	require.Nil(t, err)
	require.Equal(t, skey, plainIngress)

}
