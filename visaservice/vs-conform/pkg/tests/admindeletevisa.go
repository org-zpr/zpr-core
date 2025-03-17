package tests

import (
	"zpr.org/vst/pkg/testfw"
)

type AdminDeleteVisas struct{}

func init() {
	testfw.Register(&AdminDeleteVisas{})
}

func (t *AdminDeleteVisas) Name() string {
	return "AdminDeleteVisas"
}

func (t *AdminDeleteVisas) Order() testfw.Order {
	return testfw.OrderEarlier
}

func (t *AdminDeleteVisas) Run(state *testfw.TestState) *testfw.RunResult {
	admin, err := state.GetAdminClient()
	if err != nil {
		return testfw.Faile(err)
	}

	// Just test the API call, we don't know how many visas there are.  Probably zero.
	if vlist, err := admin.ListVisas(); err != nil {
		return testfw.Faile(err)
	} else {
		// Remove any visas in there.
		for _, v := range vlist {
			if err := admin.RevokeVisa(v.VisaId); err != nil {
				return testfw.Faile(err)
			}
		}
	}

	if vlist, err := admin.ListVisas(); err != nil {
		return testfw.Faile(err)
	} else if len(vlist) != 0 {
		return testfw.Fail("visa list not empty after delete")
	}

	// Attempt a delete for a non-existent visa
	if err := admin.RevokeVisa(12345); err != nil {
		// good.
	} else {
		return testfw.Fail("expected error returned when deleting non-existent visa")
	}

	// Connect the node (should generate 2 visas)
	if err := reconnectNode(state); err != nil {
		return testfw.Faile(err)
	}
	state.Pause()

	// Collect the visa IDs so we can delete one.  We want to start with at least two.
	vlist, err := admin.ListVisas()
	if err != nil {
		return testfw.Faile(err)
	}
	if len(vlist) < 2 {
		return testfw.Failf("expected at least 2 new visas, found %d", len(vlist))
	}

	prevLen := len(vlist)
	var vids []uint64
	for _, v := range vlist {
		vids = append(vids, v.VisaId)
	}
	deleteId := vids[0]
	if err := admin.RevokeVisa(deleteId); err != nil {
		return testfw.Failf("failed attempt to delete a visa: %v", err)
	}

	{
		// Now we have deleted the visa, query again and make sure it is gone.
		vlist, err := admin.ListVisas()
		if err != nil {
			return testfw.Faile(err)
		}
		if len(vlist) != prevLen-1 {
			return testfw.Failf("expected %d visas after delete, found %d", prevLen, len(vlist))
		}
		for _, v := range vlist {
			if v.VisaId == deleteId {
				return testfw.Failf("visa %d still exists after explicit delete", deleteId)
			}
		}
	}

	return testfw.Ok()
}
