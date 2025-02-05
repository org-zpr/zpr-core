// authenticator-rs.go implements the RevocationService. Holds state for various types of revocations.
package auth

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

type RevokeDB struct {
	sync.RWMutex
	nextKeyNum uint64
	revokes    map[string]*PverRevokeDB
}

type PverRevokeDB struct {
	pver    string
	ctime   time.Time
	revokes map[string]*Revoke
}

func NewRevokeDB() *RevokeDB {
	return &RevokeDB{
		revokes: make(map[string]*PverRevokeDB),
	}
}

// TODO: In prototype pretty sure there was a RAFT event sent around that
// told everyone about the revoke operation.
func (db *RevokeDB) insert(pver string, rvk *Revoke) {
	db.Lock()
	defer db.Unlock()
	rkey := fmt.Sprintf("%d/%v", db.nextKeyNum, pver)
	db.nextKeyNum++
	if prdb, ok := db.revokes[pver]; ok {
		prdb.revokes[rkey] = rvk
	} else {
		db.revokes[pver] = &PverRevokeDB{
			pver:    pver,
			ctime:   time.Now(),
			revokes: map[string]*Revoke{rkey: rvk},
		}
	}
}

// `pver` is "<policy.config_id><policy.version>".
func (a *Authenticator) ProposeClearAllRevokes(pver string) uint32 {
	a.rvkSvc.rdb.Lock()
	defer a.rvkSvc.rdb.Unlock()
	var count uint32
	if pver == "" {
		for _, prdb := range a.rvkSvc.rdb.revokes {
			count += uint32(len(prdb.revokes))
		}
		a.rvkSvc.rdb.revokes = make(map[string]*PverRevokeDB) // create new,  empty db
	} else {
		if prdb, ok := a.rvkSvc.rdb.revokes[pver]; ok {
			count = uint32(len(prdb.revokes))
			delete(a.rvkSvc.rdb.revokes, pver)
		}
	}
	return count
}

// Revocations are for a particular configuration which is accessed
// with a key of the form "<policy.config_id><policy.version>".
//
// This returns a set of keys for all revocations under the given configuration.
// Note that the keys are unique over all configurations.
func (a *Authenticator) ListRevocationKeysFor(pver string) []string {
	var keys []string
	a.rvkSvc.rdb.RLock()
	defer a.rvkSvc.rdb.RUnlock()
	if prdb, ok := a.rvkSvc.rdb.revokes[pver]; ok {
		for k := range prdb.revokes {
			keys = append(keys, k)
		}
	}
	return keys
}

// Using the keys returned by `ListRevocationKeysFor“, this returns the actual
// revocation object.
func (a *Authenticator) GetRevoke(rkey string) *Revoke {
	parts := strings.Split(rkey, "/")
	if len(parts) != 2 {
		panic(fmt.Sprintf("GetRevoke: invalid key: %s", rkey))
	}
	a.rvkSvc.rdb.RLock()
	defer a.rvkSvc.rdb.RUnlock()
	if prdb, ok := a.rvkSvc.rdb.revokes[parts[0]]; ok {
		if rvk, ok := prdb.revokes[parts[1]]; ok {
			return rvk
		}
	}
	return nil
}

// Submit a revocation to the store.
// `pver` is "<policy.config_id><policy.version>".
func (a *Authenticator) ProposeRevokeCredential(pver, cred string) {
	rvk := &Revoke{
		t:   RevokeType_RT_CRED,
		cid: strings.ToLower(cred),
	}
	a.rvkSvc.rdb.insert(pver, rvk)
}

// Submit a revocation to the store.
// `pver` is "<policy.config_id><policy.version>".
func (a *Authenticator) ProposeRevokeAuthority(pver, credIdent string) {
	rvk := &Revoke{
		t:   RevokeType_RT_AUTH,
		cid: strings.ToLower(credIdent),
	}
	a.rvkSvc.rdb.insert(pver, rvk)
}

// Submit a revocation to the store.
// `pver` is "<policy.config_id><policy.version>".
func (a *Authenticator) ProposeRevokeCN(pver, cn string) {
	rvk := &Revoke{
		t:   RevokeType_RT_CN,
		cid: strings.ToLower(cn),
	}
	a.rvkSvc.rdb.insert(pver, rvk)
}
