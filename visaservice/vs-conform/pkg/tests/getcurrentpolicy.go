package tests

import (
	"zpr.org/vst/pkg/testfw"
)

type GetCurrentPolicy struct{}

func init() {
	testfw.Register(&GetCurrentPolicy{})
}

func (t *GetCurrentPolicy) Name() string {
	return "GetCurrentPolicy"
}

// If this works, it stores the current policy in the state.
func (t *GetCurrentPolicy) Run(state *testfw.TestState, ctest *testfw.TestRun) error {
	if _, err := state.LoadPolicy(); err != nil {
		ctest.Failed(err)
		return nil
	}
	ctest.Passed()
	return nil
}
