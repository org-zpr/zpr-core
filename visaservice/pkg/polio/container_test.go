package polio_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"zpr.org/vs/pkg/polio"

	"github.com/stretchr/testify/require"
)

func TestSignVerifyPolicy(t *testing.T) {

	plcy := &polio.Policy{
		SerialVersion:  polio.SerialVersion,
		PolicyVersion:  33,
		PolicyMetadata: "fee fie foh fum",
	}

	private, err := rsa.GenerateKey(rand.Reader, 768)
	require.Nil(t, err)

	pcont, err := polio.ContainPolicy(plcy, private)
	require.Nil(t, err)
	require.NotNil(t, pcont)

	require.NotNil(t, pcont.GetSignature())
	require.Equal(t, polio.ContainerVersion, pcont.GetContainerVersion())
	require.Equal(t, uint64(33), pcont.GetPolicyVersion())

	pp, err := polio.ReleasePolicy(pcont, &private.PublicKey)
	require.Nil(t, err)
	require.Equal(t, plcy.GetPolicyMetadata(), pp.GetPolicyMetadata())
}
