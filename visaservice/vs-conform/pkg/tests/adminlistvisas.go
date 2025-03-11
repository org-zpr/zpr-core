package tests

import (
	"fmt"

	"zpr.org/vst/pkg/testfw"
)

type AdminListVisas struct{}

func init() {
	testfw.Register(&AdminListVisas{})
}

func (t *AdminListVisas) Name() string {
	return "AdminListVisas"
}

func (t *AdminListVisas) Order() int {
	return 100
}

func (t *AdminListVisas) Run(state *testfw.TestState, ctest *testfw.TestRun) error {
	admin, err := state.GetAdminClient()
	if err != nil {
		ctest.Failed(err)
		return nil
	}

	// Just test the API call, we don't know how many visas there are.  Probably zero.
	vlist, err := admin.ListVisas()
	if err != nil {
		ctest.Failed(err)
		return nil
	}

	// Remove any visas in there.
	for _, v := range vlist {
		if err := admin.RevokeVisa(v.VisaId); err != nil {
			ctest.Failed(err)
			return nil
		}
	}

	{
		vlist, err := admin.ListVisas()
		if err != nil {
			ctest.Failed(err)
			return nil
		}
		if len(vlist) != 0 {
			ctest.Failedm("visa list not empty after delete")
			return nil
		}
	}

	// Connect the node (should generate 2 visas)
	if err := reconnectNode(state); err != nil {
		ctest.Failed(err)
		return nil
	}
	state.Pause()

	{
		vlist, err := admin.ListVisas()
		if err != nil {
			ctest.Failed(err)
			return nil
		}
		if len(vlist) != 2 {
			ctest.Failedm(fmt.Sprintf("expected 2 new visas, found %d", len(vlist)))
			return nil
		}
	}

	ctest.Passed()
	return nil
}
