package auth_test

/* TODO: Need to update and recompile the test data

const BAS_CN = "bas.zpr.org"

func TestAuthenticateWithSelfSignedBlob(t *testing.T) {

	authKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err)

	authsvc := auth.NewAuthenticator(logr.NewTestLogger(),
		netip.MustParseAddr("127.0.0.1"),
		1000*time.Hour,
		"vs.zpr",
		authKey)

	pfile := filepath.Join("testdata", "vs-auth-test.bin")
	cp, err := policy.OpenContainedPolicyFile(pfile, nil)
	require.Nil(t, err)
	polplcy := cp.Policy
	plcy := policy.NewPolicyFromPol(polplcy, logr.NewTestLogger())
	authsvc.InstallPolicy(1234, 0, plcy)

	pkey, err := snauth.LoadRSAKeyFromFile(filepath.Join("testdata", "bas.zpr.org_key.pem"))
	require.Nil(t, err)

	blob := auth.NewZdpSelfSignedBlobUnsiged(BAS_CN, []byte("fake-challenge-bytes-are-here"))
	err = blob.Sign(pkey)
	require.Nil(t, err)

	addr := netip.MustParseAddr("fd5a:5052::33")
	claims := make(map[string]string)
	claims[actor.KAttrCN] = BAS_CN
	aok, err := authsvc.Authenticate(auth.AUTH_PREFIX_BOOTSTRAP, addr, blob, claims)
	require.Nil(t, err)
	require.NotNil(t, aok)

	require.NotEmpty(t, aok.Identities)
	require.True(t, aok.Expire.After(time.Now()))
	require.Len(t, aok.Prefixes, 1)
	require.Equal(t, aok.Prefixes[0], auth.AUTH_PREFIX_BOOTSTRAP)
	require.NotEmpty(t, aok.Credentials)

	var keys []string
	for k := range aok.Claims {
		keys = append(keys, k)
	}
	require.Contains(t, keys, actor.KAttrCN)
	require.Contains(t, keys, actor.KAttrAuthority)
	require.Contains(t, keys, actor.KAttrConfigID)
	require.Contains(t, keys, actor.KAttrEPID)
}

*/
