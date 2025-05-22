package policy

import (
	fmt "fmt"
	"time"

	"zpr.org/vsx/polio"
)

type CFKey uint32

const (
	CKMaxVisaLifetimeSeconds CFKey = 1    // ZPR max visa lifetime.
	CKBase                   CFKey = 1025 // embodiment (non ZPR) keys start here
)

func (k CFKey) String() string {
	switch k {
	case CKMaxVisaLifetimeSeconds:
		return "MaxVisaLifetimeSeconds"
	default:
		return fmt.Sprintf("CFKey#%d", uint32(k))
	}
}

// Key returns uint32 version of the key
func (k CFKey) Key() uint32 {
	return uint32(k)
}

// NewMaxVisaLifetime create a ConfigSetting for max visa lifetime (seconds)
func NewMaxVisaLifetime(d time.Duration) *polio.ConfigSetting {
	return &polio.ConfigSetting{
		Key: CKMaxVisaLifetimeSeconds.Key(),
		Val: &polio.ConfigSetting_U64V{
			U64V: uint64(d / time.Second),
		},
	}
}

// Stringify helper to convert a config "value" to a nice looking string.
func ValueString(c *polio.ConfigSetting) string {
	switch v := c.GetVal().(type) {
	case *polio.ConfigSetting_Bv:
		return fmt.Sprintf("%v", v.Bv)
	case *polio.ConfigSetting_Sv:
		return fmt.Sprintf("%v", v.Sv)
	case *polio.ConfigSetting_U32V:
		return fmt.Sprintf("%d", v.U32V)
	case *polio.ConfigSetting_U64V:
		return fmt.Sprintf("%d", v.U64V)
	default:
		return fmt.Sprintf("?%v?", v)
	}
}
