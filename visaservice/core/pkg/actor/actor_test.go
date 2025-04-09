package actor_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"zpr.org/vs/pkg/actor"
)

func NewActorFromClaims(c map[string]string, exp time.Time) *actor.Actor {
	a := actor.NewActorFromUnsubstantiatedClaims(nil)
	authedClaims := make(map[string]*actor.ClaimV)
	for k, v := range c {
		authedClaims[k] = &actor.ClaimV{
			V:   v,
			Exp: exp,
		}
	}
	a.SetAuthenticated(authedClaims, time.Time{}, []string{"auth"}, nil, 1) // no tokens
	return a
}

func TestDualAuth(t *testing.T) {
	claims := map[string]string{
		"zpr.addr": "fc00:3001:abd5:d0d:847a:9fd6:586:7777",
	}
	a := NewActorFromClaims(claims, time.Now().Add(1*time.Hour))
	require.Equal(t, "d955aaea9189bcb5b5ff3b1837a0c91ae7e7460c52650b1d322b132e369350bf", a.Hash())
}

func TestSame(t *testing.T) {
	cl1 := map[string]string{
		"alpha": "beta",
		"gamma": "delta",
	}
	a1 := NewActorFromClaims(cl1, time.Now().Add(1*time.Hour))

	cl2 := map[string]string{
		"gamma": "delta",
		"alpha": "beta",
	}
	a2 := NewActorFromClaims(cl2, time.Now().Add(1*time.Hour))
	require.Equal(t, a1.Hash(), a2.Hash())
}

func TestIdentity(t *testing.T) {
	cl1 := map[string]string{
		"alpha":         "beta",
		"gamma":         "delta",
		actor.KAttrEPID: "fc00:3001:abd5:d0d:847a:9fd6:586:3836",
	}
	a1 := NewActorFromClaims(cl1, time.Now().Add(1*time.Hour))

	cl2 := map[string]string{
		"gamma":         "delta",
		"alpha":         "beta",
		actor.KAttrEPID: "fc00:3001:abd5:d0d:847a:9fd6:586:9999",
	}
	a2 := NewActorFromClaims(cl2, time.Now().Add(1*time.Hour))
	require.NotEqual(t, a1.Hash(), a2.Hash())
	require.Equal(t, a1.GetIdentity(), a2.GetIdentity())
}

func TestEPID(t *testing.T) {
	clms := map[string]string{
		"ca0.x509.cn":   "n0.internal",
		"zpr.authority": "ca0",
		"zpr.addr":      "fc00:3001:abd5:d0d:847a:9fd6:586:3836",
	}
	a := actor.NewActorFromUnsubstantiatedClaims(clms)

	{
		_, ok := a.GetZPRID()
		require.False(t, ok)
	}

	// Attempt a self auth
	exp := time.Now().Add(6 * time.Hour)
	authedClaims := make(map[string]*actor.ClaimV)
	for k, v := range a.GetClaims() {
		authedClaims[k] = &actor.ClaimV{
			V:   v,
			Exp: exp,
		}
	}
	a.SetAuthenticated(authedClaims, time.Time{}, []string{"foo"}, nil, 1) // no tokens
	{
		epid, ok := a.GetZPRID()
		require.True(t, ok)
		require.Equal(t, clms["zpr.addr"], epid.String())
	}
}

func TestGetTokenKeys(t *testing.T) {
	exp := time.Now().Add(10 * time.Minute)
	toks := []string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ4c256IjoxLCJ4c25hLjAiOiJmb286YmFyIiwieHNuYy4wIjoiYTpiOmM6ZCJ9.f5Vsz5vG6RoQt1V_mWsntv3OSxHkwJmNBZ9NF6LKdLQ",
	}
	sa := actor.EmptyActor()
	sa.SetAuthenticated(nil, exp, nil, toks, 1)
	require.Empty(t, sa.TokenIDs()) // no jti
	keys := sa.TokenKeyIDs()
	require.Len(t, keys, 1)
	require.Equal(t, "a:b:c:d", keys[0])
}

func TestGetMultTokenKeys(t *testing.T) {
	exp := time.Now().Add(10 * time.Minute)
	toks := []string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ4c256IjoyLCJqdGkiOiIzMDAwIiwieHNuYS4wIjoiZm9vOmJhciIsInhzbmMuMCI6ImE6YjpjOmQiLCJ4c25hLjEiOiJmZWU6YmFoIiwieHNuYy4xIjoiZTpmOmc6aCJ9.9aHxqTijhtF2wrlNpB4D_1mS6p7VRVNT0YJxSuMyf7E",
	}
	sa := actor.EmptyActor()
	sa.SetAuthenticated(nil, exp, nil, toks, 1)
	keys := sa.TokenKeyIDs()
	require.Len(t, keys, 2)
	require.Contains(t, keys, "a:b:c:d")
	require.Contains(t, keys, "e:f:g:h")
}

func TestGetTokenIDs(t *testing.T) {
	exp := time.Now().Add(10 * time.Minute)
	// Has jti and also keys
	toks := []string{
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ4c256IjoxLCJqdGkiOiIzMDAwIiwieHNuYS4wIjoiZm9vOmJhciIsInhzbmMuMCI6ImE6YjpjOmQifQ.i-0M2bslRyXgGG0l5hJYR1CF17kypmjF8xiZKXadIJM",
	}
	sa := actor.EmptyActor()
	sa.SetAuthenticated(nil, exp, nil, toks, 1)
	keys := sa.TokenKeyIDs()
	require.Len(t, keys, 1)
	require.Equal(t, "a:b:c:d", keys[0])

	ids := sa.TokenIDs()
	require.Len(t, ids, 1)
	require.Equal(t, "3000", ids[0])
}
