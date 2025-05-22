package policy_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	snip "zpr.org/vs/pkg/ip"

	"zpr.org/vs/pkg/policy"
	"zpr.org/vsx/polio"
)

func TestAllows(t *testing.T) {
	// Empty
	m1 := policy.NewServiceMesh()
	m2 := policy.NewServiceMesh()
	require.False(t, m1.Allows(snip.ProtocolTCP, 23))
	require.False(t, m2.Allows(snip.ProtocolTCP, 23))

	m1.AddService(snip.ProtocolUDP, 88, "fc00:3001::100", "udp88", polio.SvcT_SVCT_DEF)
	require.True(t, m1.Allows(snip.ProtocolUDP, 88))
	require.False(t, m1.Allows(snip.ProtocolUDP, 89))
}

func TestProvides(t *testing.T) {
	// Empty
	m1 := policy.NewServiceMesh()
	m2 := policy.NewServiceMesh()
	require.False(t, m1.Provides("fc00:3001::100", snip.ProtocolTCP, 23))
	require.False(t, m2.Provides("fc00:3001::100", snip.ProtocolTCP, 23))

	m1.AddService(snip.ProtocolTCP, 23, "fc00:3001::100", "telnet", polio.SvcT_SVCT_DEF)
	require.True(t, m1.Provides("fc00:3001::100", snip.ProtocolTCP, 23))
	require.False(t, m2.Provides("fc00:3001::100", snip.ProtocolTCP, 23))
}

func TestIncludes(t *testing.T) {
	// Empty
	m1 := policy.NewServiceMesh()
	m2 := policy.NewServiceMesh()
	require.True(t, m1.Includes(m2))
	require.True(t, m2.Includes(m1))

	m1.AddService(snip.ProtocolUDP, 88, "fc00:3001::100", "udp88", polio.SvcT_SVCT_DEF)
	require.True(t, m1.Includes(m2))
	require.False(t, m2.Includes(m1))

	m2.AddService(snip.ProtocolUDP, 89, "fc00:3001::100", "udp89", polio.SvcT_SVCT_DEF)
	require.False(t, m1.Includes(m2))
	require.False(t, m2.Includes(m1))

	m1.AddService(snip.ProtocolUDP, 89, "fc00:3001::101", "udp89", polio.SvcT_SVCT_DEF)
	require.False(t, m1.Includes(m2)) // different host

	// redo m1 so that it includes m2:
	m1 = policy.NewServiceMesh()

	m1.AddService(snip.ProtocolUDP, 88, "fc00:3001::100", "udp88", polio.SvcT_SVCT_DEF)
	m1.AddService(snip.ProtocolUDP, 89, "fc00:3001::100", "udp89a", polio.SvcT_SVCT_DEF) // Note that we don't check name
	m1.AddService(snip.ProtocolUDP, 89, "fc00:3001::101", "udp89b", polio.SvcT_SVCT_DEF)
	require.True(t, m1.Includes(m2))
	require.False(t, m2.Includes(m1))
}

func TestIncludesWithConstraints(t *testing.T) {
	m1 := policy.NewServiceMesh()
	m2 := policy.NewServiceMesh()
	m3 := policy.NewServiceMesh()

	bwc1000 := &polio.Constraint{
		Carg: &polio.Constraint_Bw{
			&polio.BWConstraint{
				BitsPerSec: 1000,
			},
		},
	}

	m1.AddServiceWithConstraints(snip.ProtocolUDP, 88, "fc00:3001::100", "udp88", polio.SvcT_SVCT_DEF, []string{policy.HashHex(bwc1000)})
	require.True(t, m1.Includes(m2))
	require.False(t, m2.Includes(m1))

	// m2 gets same service but without a constraint
	m2.AddService(snip.ProtocolUDP, 88, "fc00:3001::100", "udp88", polio.SvcT_SVCT_DEF)
	require.False(t, m1.Includes(m2))
	require.False(t, m2.Includes(m1))

	// m3 gets same service as m1 including constraint
	m3.AddServiceWithConstraints(snip.ProtocolUDP, 88, "fc00:3001::100", "udp88", polio.SvcT_SVCT_DEF, []string{policy.HashHex(bwc1000)})
	require.True(t, m1.Includes(m3))
	require.True(t, m3.Includes(m1))
	require.False(t, m3.Includes(m2))

	// m3 gets a totally separate service
	m3.AddService(snip.ProtocolUDP, 89, "fc00:3001::101", "udp89", polio.SvcT_SVCT_DEF)
	require.False(t, m1.Includes(m3)) // m1 does not have udp89
	require.True(t, m3.Includes(m1))  // yes, m3 does have udp88 w/constraint
}

func TestParsesConstraints(t *testing.T) {

	p1 := new(polio.Policy)

	{ // Add the connect policy, procedure, and address
		proc := &polio.Proc{
			Proc: []*polio.Instruction{
				{
					Opcode: polio.OpCodeT_OP_Register,
					Args: []*polio.Argument{
						{
							Arg: &polio.Argument_Strval{"udp88"},
						},
						{
							Arg: &polio.Argument_Svcval{polio.SvcT_SVCT_DEF},
						},
						{
							Arg: &polio.Argument_Strval{"UDP/88"},
						},
					},
				},
			},
		}
		p1.Procs = append(p1.Procs, proc)

		p1.AttrKeyIndex = []string{policy.KAttrZPRAddr}
		p1.AttrValIndex = []string{"fc00:3001::100"}

		connect := &polio.Connect{
			Proc: 0,
			AttrExprs: []*polio.AttrExpr{
				{
					Key: 0,
					Op:  polio.AttrOpT_EQ,
					Val: 0,
				},
			},
		}
		p1.Connects = append(p1.Connects, connect)
	}

	bwc1000 := &polio.Constraint{
		Carg: &polio.Constraint_Bw{
			&polio.BWConstraint{
				BitsPerSec: 1000,
			},
		},
	}

	{ // add the communication policy, constraint, and scope
		cpol := &polio.CPolicy{
			ServiceId:   "udp88",
			Id:          "cpol_1",
			Constraints: []*polio.Constraint{bwc1000},
			Scope: []*polio.Scope{
				{
					Protocol: snip.ProtocolUDP.Num(),
					Protarg: &polio.Scope_Pspec{
						&polio.PortSpecList{
							Spec: []*polio.PortSpec{
								{
									Parg: &polio.PortSpec_Port{88},
								},
							},
						},
					},
				},
			},
		}
		p1.Policies = append(p1.Policies, cpol)
	}

	m1 := policy.NewServiceMeshFromPolicy(p1)

	m2 := policy.NewServiceMesh()
	m2.AddServiceWithConstraints(snip.ProtocolUDP, 88, "fc00:3001::100", "udp88", polio.SvcT_SVCT_DEF, []string{policy.HashHex(bwc1000)})

	require.True(t, m1.Includes(m2), "m1 should INCLUDE m2")
	require.True(t, m2.Includes(m1), "m2 should INCLUDE m1")
}
