package actor_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"zpr.org/vs/pkg/actor"
)

func TestParseAuthAttrExt(t *testing.T) {
	aa, err := actor.ParseAuthAttr("ext:auth0.spacelaser.net?alg=ca-rsa-v1")
	require.Nil(t, err)
	require.True(t, aa.IsExternal())
	require.Equal(t, "auth0.spacelaser.net", aa.GetExtService())
	require.Equal(t, "ca-rsa-v1", aa.GetExtScheme())
	require.Equal(t, "ext:auth0.spacelaser.net?alg=ca-rsa-v1", aa.String())
	require.Equal(t, "ext:?alg=ca-rsa-v1", aa.TypeStr())

	// Empty service and scheme is valid since it can be set globally.
	aa, err = actor.ParseAuthAttr("ext:")
	require.Nil(t, err)
	require.True(t, aa.IsExternal())
	require.Equal(t, "", aa.GetExtService())
	require.Equal(t, "", aa.GetExtScheme())

	// Missing alg is ok
	aa, err = actor.ParseAuthAttr("ext:foo")
	require.Nil(t, err)

	// No alg or service is a problem
	aa, err = actor.ParseAuthAttr("ext")
	require.NotNil(t, err)
}

func TestParseAuthAttrCert509(t *testing.T) {
	aa, err := actor.ParseAuthAttr("cert:x509:auth0?name=geddy&number=1")
	require.Nil(t, err)
	require.False(t, aa.IsExternal())
	require.Equal(t, actor.AuthTCert, aa.T)
	require.Equal(t, actor.AuthCertTX509, aa.CT)
	require.Equal(t, "auth0", aa.GetAuthority())
	require.Equal(t, 2, len(aa.Props))
	require.Equal(t, "geddy", aa.Props["name"])
	require.Equal(t, "1", aa.Props["number"])

	aa, err = actor.ParseAuthAttr("cert:x509:auth0?name=geddy")
	require.Nil(t, err)
	require.Equal(t, "geddy", aa.Props["name"])
	require.Equal(t, "auth0", aa.GetAuthority())

	aa, err = actor.ParseAuthAttr("cert:x509:auth0")
	require.Nil(t, err)
	require.Equal(t, "", aa.Props["name"])
	require.Equal(t, "auth0", aa.GetAuthority())

	// Empty authority is ok... uh, I guess.
	aa, err = actor.ParseAuthAttr("cert:x509:")
	require.Nil(t, err)
	require.Equal(t, "", aa.GetAuthority())

	aa, err = actor.ParseAuthAttr("cert")
	require.NotNil(t, err)
}

func TestParseAuthAttrCert509Minimal(t *testing.T) {
	aa, err := actor.ParseAuthAttr("cert:x509")
	require.Nil(t, err)
	require.False(t, aa.IsExternal())
	require.Equal(t, actor.AuthTCert, aa.T)
	require.Equal(t, actor.AuthCertTX509, aa.CT)

	// Empty authority is ok... uh, I guess.
	aa, err = actor.ParseAuthAttr("cert:x509:")
	require.Nil(t, err)
	require.Equal(t, "", aa.GetAuthority())
}

func TestParseAuthAttrCertU2F(t *testing.T) {
	aa, err := actor.ParseAuthAttr("cert:u2f:auth0?name=geddy&number=1")
	require.Nil(t, err)
	require.False(t, aa.IsExternal())
	require.Equal(t, actor.AuthTCert, aa.T)
	require.Equal(t, actor.AuthCertTU2F, aa.CT)
	require.Equal(t, "auth0", aa.GetAuthority())
	require.Equal(t, 2, len(aa.Props))
	require.Equal(t, "geddy", aa.Props["name"])
	require.Equal(t, "1", aa.Props["number"])

	aa, err = actor.ParseAuthAttr("cert:u2f:auth0")
	require.Nil(t, err)
	require.Equal(t, "auth0", aa.GetAuthority())

	aa, err = actor.ParseAuthAttr("cert:u2f:")
	require.Nil(t, err)

	aa, err = actor.ParseAuthAttr("cert:u2f")
	require.Nil(t, err)
}

func TestParseAuthAttrJWT(t *testing.T) {
	aa, err := actor.ParseAuthAttr("jwt:google?email=hammer@head.com")
	require.Nil(t, err)
	require.False(t, aa.IsExternal())
	require.Equal(t, actor.AuthTJWT, aa.T)
	require.Equal(t, actor.AuthCertTNil, aa.CT)
	require.Equal(t, "google", aa.GetAuthority())
	require.Equal(t, "hammer@head.com", aa.Props["email"])

	aa, err = actor.ParseAuthAttr("jwt:google")
	require.Nil(t, err)
	require.Equal(t, "google", aa.GetAuthority())

	aa, err = actor.ParseAuthAttr("jwt")
	require.NotNil(t, err)
}

func TestParseUnknown(t *testing.T) {
	_, err := actor.ParseAuthAttr("foo:bang:ha")
	require.NotNil(t, err)
}

func TestTypeStr(t *testing.T) {
	aa, _ := actor.ParseAuthAttr("cert:x509:auth0")
	require.Equal(t, "cert:x509", aa.TypeStr())
	aa, _ = actor.ParseAuthAttr("cert:u2f:auth0")
	require.Equal(t, "cert:u2f", aa.TypeStr())
	aa, _ = actor.ParseAuthAttr("jwt:google")
	require.Equal(t, "jwt", aa.TypeStr())
	aa, _ = actor.ParseAuthAttr("ext:")
	require.NotNil(t, aa)
	require.Equal(t, "ext:", aa.TypeStr())
	aa, _ = actor.ParseAuthAttr("ext:auth.host.com?alg=foo_scheme")
	require.NotNil(t, aa)
	require.Equal(t, "ext:?alg=foo_scheme", aa.TypeStr())
}

func TestMatchMinusAuth(t *testing.T) {
	a0, _ := actor.ParseAuthAttr("cert:x509:foo0?cn=fee")
	require.True(t, a0.MatchMinusAuth(a0))
	a1, _ := actor.ParseAuthAttr("cert:x509:foo99?cn=fee")
	require.True(t, a0.MatchMinusAuth(a1))
	require.True(t, a1.MatchMinusAuth(a0))
	e0, _ := actor.ParseAuthAttr("ext:service?alg=haha")
	require.True(t, e0.MatchMinusAuth(e0))
	e1, _ := actor.ParseAuthAttr("ext:otherservice?alg=haha")
	require.True(t, e0.MatchMinusAuth(e1))
	require.True(t, e1.MatchMinusAuth(e0))
	require.False(t, a0.MatchMinusAuth(e0))
	a2, _ := actor.ParseAuthAttr("cert:x509:foo0?cn=fox")
	require.False(t, a0.MatchMinusAuth(a2))
}

func TestParseGoogs(t *testing.T) {
	spec := "ext:?alg=google-openid&hd=appliedinvention.com"
	ah, err := actor.ParseAuthAttr(spec)
	require.Nil(t, err)
	require.Equal(t, "google-openid", ah.GetExtScheme())
}

func TestCreateNoService(t *testing.T) {
	alg := "google-openid"
	aa := actor.NewAuthAttrExt("", alg)
	require.Equal(t, "ext:?alg=google-openid", aa.String())
}
