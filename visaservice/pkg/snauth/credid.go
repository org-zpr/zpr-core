package snauth

type CredIDType int

const (
	CredIDTypeNil         CredIDType = iota
	CredIDTypeAuthority              // actually now just means a Key fingerprint (could be an authority key or a agent key)
	CredIDTypeCertificate            // actually means a JTI value
)

// CredID is a credential identifier with some ID value and a type.
type CredID struct {
	CType CredIDType
	ID    string
}
