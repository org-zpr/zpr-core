package auth

import (
	"fmt"

	"zpr.org/vs/pkg/snauth"
)

type Revoke struct {
	t   RevokeType
	cid string
}

type RevokeType int

const (
	RevokeType_RT_AUTH RevokeType = iota
	RevokeType_RT_CRED
	RevokeType_RT_EPID
	RevokeType_RT_CN // New for ref impl -- revoke by the adapter CN value (cid is a CN)
)

func (r *Revoke) GetRType() RevokeType {
	return r.t
}

func (r *Revoke) GetCredId() string {
	return r.cid
}

func (r *Revoke) Equals(o *Revoke) bool {
	return r.t == o.t && r.cid == o.cid
}

// The prototype used RAFT on the nodes to keep track of the revocations.
// All the "propose" verbiage is left over from raft.
//
// TODO: This needs to be taken over by visa service directly interacting with its node peers.
type RevocationService interface {
	// Clear all the revocation data for given `pver` value.
	// If empty `pver` clears EVERYTHING.
	// Returns number cleared
	ProposeClearAllRevokes(string) uint32

	// Revocations are for a particular configuration which is accessed
	// with a key of the form "<policy.config_id><policy.version>".
	//
	// This returns a set of keys for all revocations under the given configuration.
	ListRevocationKeysFor(string) []string

	// Using the keys returned by `ListRevocationKeysFor``, this returns the actual
	// revocation object.
	GetRevoke(string) *Revoke

	// Submit a revocation to the store.
	// `pver` is "<policy.config_id><policy.version>".
	ProposeRevokeCredential(pver, cred string)

	// Submit a revocation to the store.
	// `pver` is "<policy.config_id><policy.version>".
	ProposeRevokeAuthority(pver, credIdent string)

	ProposeRevokeCN(pver, cn string)
}

func raftRevokeTypeToSnauthCredIDType(rt RevokeType) snauth.CredIDType {
	switch rt {
	case RevokeType_RT_AUTH:
		return snauth.CredIDTypeAuthority
	case RevokeType_RT_CRED:
		return snauth.CredIDTypeCertificate
	case RevokeType_RT_CN:
		return snauth.CredIDTypeCN
	case RevokeType_RT_EPID:
		panic("unexpected RevokeType_RT_EPID")
	default:
		panic(fmt.Sprintf("unexpected RevokeType %v", rt))
	}
}
