package vservice

import (
	"fmt"
	"sync"
	"time"

	"zpr.org/vs/pkg/snauth"
	"zpr.org/vs/pkg/tsapi"
	"zpr.org/vs/pkg/vservice/auth"
)

type AttrProxy struct {
	authr auth.AuthService
	cache map[string]map[string]*tsapi.Attribute // subject -> map_of_attrs
	mtx   sync.RWMutex
}

func NewAttrProxy(svc auth.AuthService) *AttrProxy {
	return &AttrProxy{
		authr: svc,
		mtx:   sync.RWMutex{},
		cache: make(map[string]map[string]*tsapi.Attribute),
	}
}

// Size returns (subject_count, attrs_count) for the cache.
func (p *AttrProxy) Size() (subCount int, attrCount int) {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	subCount = len(p.cache)
	for _, cc := range p.cache {
		attrCount += len(cc)
	}
	return
}

// Query the auth service through the cache.
// If the data source does not support Query interface, auth.ErrNotSupported is returned.
func (p *AttrProxy) Query(now time.Time, req *tsapi.QueryRequest) (*tsapi.QueryResponse, error) {

	queryKeys := make(map[string]bool)
	cacheHits := make(map[string]*tsapi.Attribute)
	var subs []string // extracted from tokens

	curTS := now.Unix()

	// Assume we need to query for all keys:
	for _, k := range req.AttrKeys {
		queryKeys[k] = true
	}

	for _, tok := range req.TokenList { // tok is a JWT.
		sub := snauth.GetStrClaimFromJWTStr("sub", string(tok))
		if sub == "" {
			continue
		}
		subs = append(subs, sub)
		p.mtx.RLock()
		if cached, ok := p.cache[sub]; ok {
			for akey, needsQ := range queryKeys {
				if !needsQ {
					continue
				}
				if cval, ok := cached[akey]; ok {
					// Found in cache
					if curTS < cval.Exp {
						// IS NOT expired
						cacheHits[akey] = cval  // grab the value
						queryKeys[akey] = false // note we do not need to query for this one
					}
				}
			}
		}
		p.mtx.RUnlock()
	}

	// Now we need to query for the cache misses
	var expired []string
	for k, needs := range queryKeys {
		if needs {
			expired = append(expired, k)
		}
	}
	var err error
	var resp *tsapi.QueryResponse
	if len(expired) == 0 {
		// Nothing has expired? Great!
		resp = &tsapi.QueryResponse{
			Ttl: 10000, // not sure this matters
		}
	} else {
		missreq := &tsapi.QueryRequest{
			TokenList: req.TokenList,
			AttrKeys:  expired,
		}
		resp, err = p.authr.Query(missreq)
		if err != nil {
			// TODO: Should I "cache" the error?
			return nil, err
		}
		p.mtx.Lock()
		for _, sub := range subs { // Hmm, this multiple IDs thing is a little strange.
			tokCache, ok := p.cache[sub]
			if !ok {
				tokCache = make(map[string]*tsapi.Attribute)
				p.cache[sub] = tokCache
			}
			for _, att := range resp.GetAttrs() {
				tokCache[att.Key] = att
			}
		}
		p.mtx.Unlock()
	}
	// Finally, append in the cache hits:
	for _, vx := range cacheHits {
		resp.Attrs = append(resp.Attrs, vx)
	}

	return resp, nil
}

// Dump for debugging
func (p *AttrProxy) Dump() {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	fmt.Printf("DUMP: AttrProxy with %d subject keys\n", len(p.cache))
	for sub, cache := range p.cache {
		fmt.Printf("   sub: %v  (%d entries)\n", sub, len(cache))
		for k, v := range cache {
			fmt.Printf("      (%v, %v)\n", k, v)
		}
	}
	fmt.Println()
}
