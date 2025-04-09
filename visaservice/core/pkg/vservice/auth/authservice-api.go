package auth

import (
	"net/netip"
	"time"

	"zpr.org/vs/pkg/actor"
	"zpr.org/vs/pkg/policy"
	"zpr.org/vsx/snio/zds"
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
		chal *zds.Challenge,
		chalResp []*zds.ChallengeResponse,
		claims map[string]string) (*AuthenticateOK, error)

	SelfAuthenticate(reqAddr netip.Addr, claims map[string]string) (*AuthenticateOK, error)

	// Query runs an attribute query against datasources.
	// Note that the attributes passed in the request will have prefixes on them, and
	// the attributes in the response will too.
	Query(*zds.QueryRequest) (*zds.QueryResponse, error)

	// Tell the auth sub-system about a new policy for the configuration.  The Authenticate and
	// Query functions will make use of the datasources in this policy.
	//
	// TODO: Ideally, the visa service is the only part of ZPR network keeping tabs on the
	//       current policy.  AND, the visa service is also the only element that needs
	//       to maintain a connection to the auth services.
	// SetCurrentPolicy(configID uint64, p *policy.Policy) error

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
