package auth

import (
	"net/netip"
	"time"

	"zpr.org/vs/pkg/actor"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vs/pkg/tsapi"
)

// TODO: Also in zprn/auth/authenticateok.go
type AuthenticateOK struct {
	Identities  []string                 // Identity tokens
	Expire      time.Time                // Expiration of the authentication (derived from the tokens)
	Credentials []string                 // Credential IDs used in the authentication
	Claims      map[string]*actor.ClaimV // These are attributes returned from validation service to use to augment/replace the user claims.
	Prefixes    []string                 // Eg, "ca0", "simplev"
}

// The VisaService requires help from an authentication system.
// AuthService also imlements policy.PolicyListener
type AuthService interface {
	AddDatasourceProvider(service string, contactAddr netip.Addr, configID uint64) error
	RemoveServiceByPrefix(string) int

	// Run an authentication request using the current policy.
	// TODO: The result struct AuthenticateOK should be defined here in visa service, not in auth package.
	Authenticate(prefix string,
		reqAddr netip.Addr,
		blob Blob,
		claims map[string]string) (*AuthenticateOK, error)

	// Query runs an attribute query against datasources.
	// Note that the attributes passed in the request will have prefixes on them, and
	// the attributes in the response will too.
	Query(*tsapi.QueryRequest) (*tsapi.QueryResponse, error)

	// Tell the auth sub-system about a new policy for the configuration.  The Authenticate and
	// Query functions will make use of the datasources in this policy.
	InstallPolicy(uint64, byte, *policy.Policy) // must install the policy under the given configuration.

	ActivateConfiguration(uint64, byte) // deactivates all other configurations

	// revoke by a KEY identifier
	RevokeAuthority(string) error

	// revoke by a JTI
	RevokeCredential(string) error

	// Revoke by zpr.adapter.cn
	RevokeCN(string) error

	// Clears all revocations and returns the count of revocations cleared.
	ClearAllRevokes() uint32
}
