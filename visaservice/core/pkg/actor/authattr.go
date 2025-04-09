package actor

import (
	"errors"
	fmt "fmt"
	"net/url"
	"strings"
)

var (
	errInvalidAuthType = errors.New("invalid auth type")
	errInvalidCertType = errors.New("invalid auth cert type")
	errInvalidAuthArgs = errors.New("auth spec with invalid arguments")
)

type AuthType int

// Auth types
const (
	AuthTNil AuthType = iota
	AuthTExt
	AuthTCert
	AuthTJWT
)

type AuthCertType int

// Cert types
const (
	AuthCertTNil AuthCertType = iota
	AuthCertTX509
	AuthCertTU2F
)

type AuthAttr struct {
	T     AuthType
	CT    AuthCertType
	Props map[string]string // Hmm, shouldn't this be a map to []string??
	attrs map[string]string
}

// Keys for attrs
const (
	// AKService is for external service name (hostname)
	AKService = "service"

	// AKAuthority is for the authority identifier
	AKAuthority = "auth"
)

// Keys for props
const (
	// PAlg represents algorithm ID
	PAlg = "alg"
)

func (at AuthType) String() string {
	switch at {
	case AuthTNil:
		return ""
	case AuthTExt:
		return "ext"
	case AuthTCert:
		return "cert"
	case AuthTJWT:
		return "jwt"
	default:
		return fmt.Sprintf("?%d?", int(at))
	}
}

func (ct AuthCertType) String() string {
	switch ct {
	case AuthCertTNil:
		return ""
	case AuthCertTU2F:
		return "u2f"
	case AuthCertTX509:
		return "x509"
	default:
		return fmt.Sprintf("?%d?", int(ct))
	}
}

func (a *AuthAttr) String() string {
	// Note that string form must be deterministic.
	switch a.T {
	case AuthTExt:
		// ext:<service>?alg=<alg>
		return fmt.Sprintf("%v:%v%v", a.T, a.attrs[AKService], a.encodedProps())

	case AuthTCert:
		// cert:subt:<authname>?props
		return fmt.Sprintf("%v:%v:%v%v", a.T, a.CT, a.attrs[AKAuthority], a.encodedProps())

	case AuthTJWT:
		// jwt:<authname>?props
		return fmt.Sprintf("%v:%v%v", a.T, a.attrs[AKAuthority], a.encodedProps())
	default:
		return "AuthAttr???"
	}
}

// NewAuthAttrExt creates a new "ext:" type AuthAttr with the given (external) service name
// and algorithm/scheme string (the "alg").
func NewAuthAttrExt(service, scheme string) *AuthAttr {
	return &AuthAttr{
		T: AuthTExt,
		attrs: map[string]string{
			AKService: service,
		},
		Props: map[string]string{
			PAlg: scheme,
		},
	}
}

func newAuthAttr(t AuthType, ct AuthCertType, authority string, props map[string]string) *AuthAttr {
	aa := &AuthAttr{
		T:  t,
		CT: ct,
		attrs: map[string]string{
			AKAuthority: authority,
		},
		Props: make(map[string]string),
	}
	for k, v := range props {
		aa.Props[strings.ToLower(k)] = v
	}
	return aa
}

func NewAuthAttrCert(ct AuthCertType, authority string, props map[string]string) *AuthAttr {
	return newAuthAttr(AuthTCert, ct, authority, props)
}

func NewAuthAttrJWT(authority string, props map[string]string) *AuthAttr {
	return newAuthAttr(AuthTJWT, AuthCertTNil, authority, props)
}

func ParseAuthAttr(s string) (*AuthAttr, error) {
	// General form is:
	//    blah:blah:blah?foo=fee&food=yum

	// The auth form is BLAH[:BLAH...][?QUERY] where the query us form-URL encoded.

	aa := &AuthAttr{
		Props: make(map[string]string),
		attrs: make(map[string]string),
	}

	qidx := strings.Index(s, "?")
	if qidx > 0 {
		if m, err := url.ParseQuery(s[qidx+1:]); err == nil {
			for k, v := range m {
				aa.Props[strings.ToLower(k)] = v[0] // We only take first setting
			}
		}
	} else {
		// set qidx to end of string
		qidx = len(s)
	}

	parts := strings.Split(s[:qidx], ":")
	if len(parts) < 2 {
		return nil, errInvalidAuthType
	}
	switch parts[0] {
	case "ext":
		if len(parts) != 2 {
			return nil, errInvalidAuthArgs
		}
		aa.T = AuthTExt
		aa.attrs[AKService] = parts[1]

	case "cert":
		if len(parts) < 3 {
			parts = append(parts, "") // nil authority slot
		}
		aa.T = AuthTCert
		switch parts[1] {
		case "x509":
			aa.CT = AuthCertTX509
		case "u2f":
			aa.CT = AuthCertTU2F
		default:
			return nil, errInvalidCertType
		}
		// And authority
		aa.attrs[AKAuthority] = parts[2]

	case "jwt":
		aa.T = AuthTJWT
		aa.attrs[AKAuthority] = parts[1]

	default:
		return nil, errInvalidAuthType
	}
	return aa, nil
}

// MatchMinusAuth returns true if `a` is identical to `other` except for the
// authority (or service) name.
//
// Needed because in policy we set the authority or service name to a variable
// name that will not be known to connecting clients.
func (a *AuthAttr) MatchMinusAuth(other *AuthAttr) bool {
	if a.IsExternal() {
		if !other.IsExternal() {
			return false
		}
		return a.EqualProps(other)
	}
	if other.IsExternal() {
		return false
	}
	if a.TypeStr() != other.TypeStr() {
		return false
	}
	return a.EqualProps(other)
}

// EqualProps return true of `a` has same property set as `other`.
func (a *AuthAttr) EqualProps(other *AuthAttr) bool {
	for k, v := range a.Props {
		if other.Props[k] != v {
			return false
		}
	}
	if len(other.Props) > len(a.Props) {
		for k, v := range other.Props {
			if a.Props[k] != v {
				return false
			}
		}
	}
	return true
}

func (a *AuthAttr) TypeStr() string {
	if a.IsExternal() {
		return fmt.Sprintf("ext:%v", a.encodedProps())
	}
	if a.CT == AuthCertTNil {
		return a.T.String()
	}
	return fmt.Sprintf("%s:%s", a.T, a.CT)
}

// encodedProps uses URL encoding on the properties, always sorted by key.
func (a *AuthAttr) encodedProps() string {
	if len(a.Props) == 0 {
		return ""
	}
	up := &url.Values{}
	for k, v := range a.Props {
		up.Add(strings.ToLower(k), v)
	}
	return fmt.Sprintf("?%v", up.Encode())
}

func (a *AuthAttr) GetAuthority() string {
	return a.attrs[AKAuthority]
}

func (a *AuthAttr) GetExtService() string {
	return a.attrs[AKService]
}

func (a *AuthAttr) SetExtService(s string) { // TODO: should be immutable
	a.attrs[AKService] = s
}

func (a *AuthAttr) GetExtScheme() string {
	return a.Props[PAlg]
}

func (a *AuthAttr) SetExtScheme(s string) { // TODO: Should be immutable
	a.Props[PAlg] = s
}

func (a *AuthAttr) IsExternal() bool {
	return a.T == AuthTExt
}

// GetAdditionalPropsList retuns the properties (not `alg` property) in a list where
// each element is `key=value` form.
func (a *AuthAttr) GetAdditionalPropsList() []string {
	var plist []string
	for k, v := range a.Props {
		if k != PAlg {
			plist = append(plist, fmt.Sprintf("%v=%v", k, v)) // TODO: Escaping?
		}
	}
	return plist
}
