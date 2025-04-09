package snauth

type CredIDType int

const (
	CredIDTypeAuthority   CredIDType = iota + 1 // actually now just means a Key fingerprint (could be an authority key or a actor key)
	CredIDTypeCertificate                       // actually means a JTI value
	CredIDTypeVisaID
	CredIDTypeCN
)

// CredID is a credential identifier with some ID value and a type.
type CredID struct {
	CType CredIDType
	ID    string
}
