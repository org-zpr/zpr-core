package policy_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vsx/polio"
)

func TestSignVerifyPolicy(t *testing.T) {

	plcy := &polio.Policy{
		SerialVersion:  policy.SerialVersion,
		PolicyVersion:  33,
		PolicyMetadata: "fee fie foh fum",
	}

	private, err := rsa.GenerateKey(rand.Reader, 768)
	require.Nil(t, err)

	pcont, err := policy.ContainPolicy(plcy, private)
	require.Nil(t, err)
	require.NotNil(t, pcont)

	require.NotNil(t, pcont.GetSignature())
	require.Equal(t, policy.ContainerVersion, pcont.GetContainerVersion())
	require.Equal(t, uint64(33), pcont.GetPolicyVersion())

	pp, err := policy.ReleasePolicy(pcont, &private.PublicKey)
	require.Nil(t, err)
	require.Equal(t, plcy.GetPolicyMetadata(), pp.GetPolicyMetadata())
}
