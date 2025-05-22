package policy

import (
	"zpr.org/vsx/polio"
)

type MatchedPolicy struct {
	CPol     *polio.CPolicy // Communication policy
	FWD      bool           // was a forward match?
	Metadata *MatchMetadata // optional metadata
}

type MatchMetadata struct {
	IcmpType               polio.ICMPT // ICMP Type (no code)
	IcmpRequiresAntecedent bool        // TRUE if we have an ICMP antecedent situation
	IcmpAntecedent         uint16      // The ICMP antecedent required
}

func NewMinimalMatchedPolicy(protocol uint32, destPort uint16, forward bool) *MatchedPolicy {
	mp := MatchedPolicy{
		CPol: &polio.CPolicy{
			Scope: []*polio.Scope{
				{
					Protocol: protocol,
					Protarg: &polio.Scope_Pspec{
						Pspec: &polio.PortSpecList{
							Spec: []*polio.PortSpec{
								{
									Parg: &polio.PortSpec_Port{
										Port: uint32(destPort),
									},
								},
							},
						},
					},
				},
			},
			Conditions:  nil,
			Constraints: nil,
		},
		FWD: forward,
	}
	return &mp
}
