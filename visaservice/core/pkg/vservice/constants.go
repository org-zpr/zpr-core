package vservice

import (
	"time"
)

const (
	// VisaServicePort is the ZPR visa service port
	VisaServicePort = 5002 // TCP

	// MaxVisaID counter value is 24 bits. Entire visa ID is 32 bits. Obviously don't mess with this unless
	// you also alter the whole visa ID generation bit scheme.
	maxVisaID = uint32((1 << 24) - 1)

	// MinVisaID is the minimum visa ID value. 0 is unused, and 1-7 are reserved for special purposes -- primarily for the
	// bootstrap visas.
	minVisaID = 8

	// DefaultReauthBumpTime is added to visa expiration if either of the actors
	// credentials are expiring at the visa expiration time. This gives the actors
	// a chance to re-auth before expiring the visa.
	//
	// For unit tests it is helpful to reduce this.
	DefaultReauthBumpTime = 5 * time.Minute

	// VSVisaRenewalTime is how much time is left on a visa-service access visa before
	// we trigger an automatic renewal (push) process.
	VSVisaRenewalTime = 10 * time.Minute

	// Time between a config update and all outstanding visas being expired.
	// The visa client poll interval needs to be smaller than this so that the
	// client nodes are able to get updated critical visas for the next configuration
	// before the old configuration expires.
	NetConfigSettleTime = 10 * time.Second

	// ZPR hard coded visa service address.
	VisaServiceAddress = "fd5a:5052::1"

	// AdminPort is the admin control port for visa service
	AdminPort = 8182 // TCP

	// Visa Support Service runs on each node
	VSSDefaultPort = 8183
)
