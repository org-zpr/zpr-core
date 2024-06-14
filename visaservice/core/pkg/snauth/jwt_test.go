package snauth_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/snauth"
)

func TestGetInt64ClaimFromJWTStr(t *testing.T) {
	jwts := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2MzI3NzUzNjV9.sihZXX_ov3BTKPQXmtC42rCr6B3BXlehhgw7ahVwM5c"
	exp := snauth.GetInt64ClaimFromJWTStr("exp", jwts)
	require.NotZero(t, exp)
	require.Equal(t, int64(1632775365), exp)
}

func TestGetStrClaimFromJWTStr(t *testing.T) {
	jwts := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2MzI3NzUzNjV9.sihZXX_ov3BTKPQXmtC42rCr6B3BXlehhgw7ahVwM5c"
	name := snauth.GetStrClaimFromJWTStr("name", jwts)
	require.Equal(t, "John Doe", name)
}
