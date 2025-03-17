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

func (t *GetCurrentPolicy) Order() testfw.Order {
	return testfw.OrderFirst
}

// If this works, it stores the current policy in the state.
func (t *GetCurrentPolicy) Run(state *testfw.TestState) *testfw.RunResult {
	if _, err := state.LoadPolicy(); err != nil {
		return testfw.Faile(err)
	}
	return testfw.Ok()
}
