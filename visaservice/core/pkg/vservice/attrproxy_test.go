package vservice_test

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"zpr.org/vs/pkg/actor"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/tsapi"
	"zpr.org/vs/pkg/vservice"
	"zpr.org/vs/pkg/vservice/auth"
)

// An auth service
type TAuthSvc struct {
	QueryCallCount int
	QueryResponses []*tsapi.QueryResponse
}

func (s *TAuthSvc) SetCurrentPolicy(_ uint64, _ *policy.Policy) error { return nil }
func (s *TAuthSvc) RevokeAuthority(string) error                      { return nil }
func (s *TAuthSvc) RevokeCredential(string) error                     { return nil }
func (s *TAuthSvc) RevokeCN(string) error                             { return nil }
func (s *TAuthSvc) ClearAllRevokes() uint32                           { return 0 }
func (s *TAuthSvc) InstallPolicy(uint64, byte, *policy.Policy)        {}
func (s *TAuthSvc) ActivateConfiguration(uint64, byte)                {}
func (s *TAuthSvc) RemoveServiceByPrefix(_ string) int                { return 0 }

func (s *TAuthSvc) AddDatasourceProvider(_ string, _ netip.Addr, _ uint64) error {
	return nil
}

func (s *TAuthSvc) Authenticate(domain string,
	epID netip.Addr,
	blob auth.Blob,
	claims map[string]string) (*auth.AuthenticateOK, error) {
	return nil, fmt.Errorf("Authenticate not implemented")
}

func (s *TAuthSvc) Query(*tsapi.QueryRequest) (*tsapi.QueryResponse, error) {
	s.QueryCallCount++
	var resp *tsapi.QueryResponse
	if len(s.QueryResponses) > 0 {
		resp, s.QueryResponses = s.QueryResponses[0], s.QueryResponses[1:]
		return resp, nil
	}
	// No responses.
	return nil, fmt.Errorf("query failed")
}

func attrsToMap(attrs []*tsapi.Attribute) map[string]*actor.ClaimV {
	am := make(map[string]*actor.ClaimV)
	for _, a := range attrs {
		am[a.Key] = &actor.ClaimV{
			V:   a.Val,
			Exp: time.Unix(a.Exp, 0),
		}
	}
	return am
}

// JWT token with sub = 99ballons
const ballons99Tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OWJhbGxvbnMiLCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.GxhJdvN14akuG8F-EYqbmcXpeQSpf7FXSJRSEJR_QGk"

func TestQueryUsesCache(t *testing.T) {
	svc := &TAuthSvc{}
	pxy := vservice.NewAttrProxy(svc)

	{
		exp := time.Now().Add(time.Hour).Unix()
		svc.QueryResponses = append(svc.QueryResponses,
			&tsapi.QueryResponse{
				Attrs: []*tsapi.Attribute{
					{Key: "foo", Val: "foo_val", Exp: exp},
					{Key: "fee", Val: "fee_val", Exp: exp},
					{Key: "fie", Val: "fie_val", Exp: exp},
				},
				Ttl: 10000,
			})
		svc.QueryResponses = append(svc.QueryResponses,
			&tsapi.QueryResponse{
				Attrs: []*tsapi.Attribute{
					{Key: "fox", Val: "foxy", Exp: exp},
				},
				Ttl: 10000,
			})
	}

	req := &tsapi.QueryRequest{
		TokenList: [][]byte{[]byte(ballons99Tok)},
		AttrKeys:  []string{"foo", "fee", "fie"},
	}

	// First query the cache will be empty
	{
		ss, as := pxy.Size()
		require.Zero(t, ss)
		require.Zero(t, as)
	}
	resp, err := pxy.Query(time.Now(), req)
	require.Nil(t, err)
	require.Equal(t, 1, svc.QueryCallCount) // Did invoke service call

	// All three attrs requested should be returned
	{
		amap := attrsToMap(resp.GetAttrs())
		require.Equal(t, "foo_val", amap["foo"].V)
		require.Equal(t, "fee_val", amap["fee"].V)
		require.Equal(t, "fie_val", amap["fie"].V)

		// And expire in the future
		require.True(t, amap["foo"].Exp.After(time.Now()))
	}

	// next query should use cache only
	{
		ss, as := pxy.Size()
		require.Equal(t, 1, ss)
		require.Equal(t, 3, as)
	}
	resp2, err := pxy.Query(time.Now(), req)
	require.Nil(t, err)
	require.Equal(t, 1, svc.QueryCallCount) // Did NOT invoke service call
	{
		amap := attrsToMap(resp2.GetAttrs())
		require.Equal(t, "foo_val", amap["foo"].V)
		require.Equal(t, "fee_val", amap["fee"].V)
		require.Equal(t, "fie_val", amap["fie"].V)
	}

	// Here is a query that needs to go to service again for one of the keys.
	req3 := &tsapi.QueryRequest{
		TokenList: [][]byte{[]byte(ballons99Tok)},
		AttrKeys:  []string{"foo", "fox"},
	}
	resp3, err := pxy.Query(time.Now(), req3)
	require.Nil(t, err)
	require.Equal(t, 2, svc.QueryCallCount)
	{
		amap := attrsToMap(resp3.GetAttrs())
		require.Equal(t, "foo_val", amap["foo"].V)
		require.Equal(t, "foxy", amap["fox"].V)
	}
	// But if we run it again, should all come from cache
	_, err = pxy.Query(time.Now(), req3)
	require.Nil(t, err)
	require.Equal(t, 2, svc.QueryCallCount) // Count does not increment.
}
