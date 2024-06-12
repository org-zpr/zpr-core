package auth

import "zpr.org/vs/pkg/snauth"

type Revoke struct {
	t   RevokeType
	cid string
}

type RevokeType int

const (
	RevokeType_RT_AUTH RevokeType = iota
	RevokeType_RT_CRED
	RevokeType_RT_EPID
)

func (r *Revoke) GetRType() RevokeType {
	return r.t
}

func (r *Revoke) GetCredId() string {
	return r.cid
}

// Provided by visa support service
type RevocationService interface {
	ProposeClearAllRevokes(string)
	ListRevocationKeysFor(string) []string
	GetRevoke(string) *Revoke
	ProposeRevokeCredential(pver, cred string)
	ProposeRevokeAuthority(pver, credIdent string)
}

func raftRevokeTypeToSnauthCredIDType(rt RevokeType) snauth.CredIDType {
	switch rt {
	case RevokeType_RT_AUTH:
		return snauth.CredIDTypeAuthority
	case RevokeType_RT_CRED:
		return snauth.CredIDTypeCertificate
	case RevokeType_RT_EPID:
		// EPID type is not handled by this authenticator.
		return snauth.CredIDTypeNil
	default:
		return snauth.CredIDTypeNil
	}
}
