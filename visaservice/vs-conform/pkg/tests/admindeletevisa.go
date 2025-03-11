package tests

import (
	"fmt"

	"zpr.org/vst/pkg/testfw"
)

type AdminDeleteVisas struct{}

func init() {
	testfw.Register(&AdminDeleteVisas{})
}

func (t *AdminDeleteVisas) Name() string {
	return "AdminDeleteVisas"
}

func (t *AdminDeleteVisas) Order() int {
	return 100
}

func (t *AdminDeleteVisas) Run(state *testfw.TestState, ctest *testfw.TestRun) error {
	admin, err := state.GetAdminClient()
	if err != nil {
		ctest.Failed(err)
		return nil
	}

	// Just test the API call, we don't know how many visas there are.  Probably zero.
	if vlist, err := admin.ListVisas(); err != nil {
		ctest.Failed(err)
		return nil
	} else {
		// Remove any visas in there.
		for _, v := range vlist {
			if err := admin.RevokeVisa(v.VisaId); err != nil {
				ctest.Failed(err)
				return nil
			}
		}
	}

	if vlist, err := admin.ListVisas(); err != nil {
		ctest.Failed(err)
		return nil
	} else if len(vlist) != 0 {
		ctest.Failedm("visa list not empty after delete")
		return nil
	}

	// Attempt a delete for a non-existent visa
	if err := admin.RevokeVisa(12345); err != nil {
		// good.
	} else {
		ctest.Failedm("expected error returned when deleting non-existent visa")
		return nil
	}

	// Connect the node (should generate 2 visas)
	if err := reconnectNode(state); err != nil {
		ctest.Failed(err)
		return nil
	}
	state.Pause()

	// Collect the visa IDs so we can delete one.  We want to start with at least two.
	vlist, err := admin.ListVisas()
	if err != nil {
		ctest.Failed(err)
		return nil
	}
	if len(vlist) < 2 {
		ctest.Failedm(fmt.Sprintf("expected at least 2 new visas, found %d", len(vlist)))
		return nil
	}

	prevLen := len(vlist)
	var vids []uint64
	for _, v := range vlist {
		vids = append(vids, v.VisaId)
	}
	deleteId := vids[0]
	if err := admin.RevokeVisa(deleteId); err != nil {
		ctest.Failedm(fmt.Sprintf("failed attempt to delete a visa: %v", err))
		return nil
	}

	{
		// Now we have deleted the visa, query again and make sure it is gone.
		vlist, err := admin.ListVisas()
		if err != nil {
			ctest.Failed(err)
			return nil
		}
		if len(vlist) != prevLen-1 {
			ctest.Failedm(fmt.Sprintf("expected %d visas after delete, found %d", prevLen, len(vlist)))
			return nil
		}
		for _, v := range vlist {
			if v.VisaId == deleteId {
				ctest.Failedm(fmt.Sprintf("visa %d still exists after explicit delete", deleteId))
				return nil
			}
		}
	}

	ctest.Passed()
	return nil
}
