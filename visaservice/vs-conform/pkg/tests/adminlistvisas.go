package tests

import (
	"zpr.org/vst/pkg/testfw"
)

type AdminListVisas struct{}

func init() {
	testfw.Register(&AdminListVisas{})
}

func (t *AdminListVisas) Name() string {
	return "AdminListVisas"
}

func (t *AdminListVisas) Order() testfw.Order {
	return testfw.OrderEarlier
}

func (t *AdminListVisas) Run(state *testfw.TestState) *testfw.RunResult {
	admin, err := state.GetAdminClient()
	if err != nil {
		return testfw.Faile(err)
	}

	// Just test the API call, we don't know how many visas there are.  Probably zero.
	vlist, err := admin.ListVisas()
	if err != nil {
		return testfw.Faile(err)
	}

	// Remove any visas in there.
	for _, v := range vlist {
		if err := admin.RevokeVisa(v.VisaId); err != nil {
			return testfw.Faile(err)
		}
	}

	{
		vlist, err := admin.ListVisas()
		if err != nil {
			return testfw.Faile(err)
		}
		if len(vlist) != 0 {
			return testfw.Fail("visa list not empty after delete")
		}
	}

	// Connect the node (should generate 2 visas)
	if err := reconnectNode(state); err != nil {
		return testfw.Faile(err)
	}
	state.Pause()

	{
		vlist, err := admin.ListVisas()
		if err != nil {
			return testfw.Faile(err)
		}
		if len(vlist) != 2 {
			return testfw.Failf("expected 2 new visas, found %d", len(vlist))
		}
	}

	return testfw.Ok()
}
