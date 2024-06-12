package polio

type MatchedPolicy struct {
	CPol     *CPolicy       // Communication policy
	FWD      bool           // was a forward match?
	Metadata *MatchMetadata // optional metadata
}

type MatchMetadata struct {
	IcmpType               ICMPT  // ICMP Type (no code)
	IcmpRequiresAntecedent bool   // TRUE if we have an ICMP antecedent situation
	IcmpAntecedent         uint16 // The ICMP antecedent required
}

func NewMinimalMatchedPolicy(protocol uint32, destPort uint16, forward bool) *MatchedPolicy {
	mp := MatchedPolicy{
		CPol: &CPolicy{
			Scope: []*Scope{
				{
					Protocol: protocol,
					Protarg: &Scope_Pspec{
						Pspec: &PortSpecList{
							Spec: []*PortSpec{
								{
									Parg: &PortSpec_Port{
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
