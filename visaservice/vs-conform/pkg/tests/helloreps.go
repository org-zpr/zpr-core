package tests

import (
	"zpr.org/vst/pkg/testfw"
)

const HelloRepsCount = 100

func init() {
	testfw.Register(&HelloReps{})
}

type HelloReps struct{}

func (hr *HelloReps) Name() string {
	return "HelloReps"
}

func (t *HelloReps) Order() testfw.Order {
	return testfw.OrderDontCare
}

// Send a bunch of hello messages in
func (hr *HelloReps) Run(state *testfw.TestState) *testfw.RunResult {
	reps := HelloRepsCount
	mockNode, err := state.GetNode()
	if err != nil {
		return testfw.RunFailsFatal(err)
	}
	mockNode.SetPlogEnabled(false) // too chatty
	sids := make(map[int32]bool)
	dupeCount := 0
	state.Log.Infow("testing hello from node", "reps", reps)
	for i := 0; i < reps; i++ {
		resp, err := mockNode.Hello()
		if err != nil {
			return testfw.Failf("hello failed at rep %d: %v", i, err)
		}
		if sids[resp.SessionID] {
			dupeCount++
		} else {
			sids[resp.SessionID] = true
		}
	}
	if dupeCount > 0 {
		state.Log.Warnw("repeat hello test complete", "reps", reps, "duplicate_session_ids", dupeCount)
	} else {
		state.Log.Infow("repeat hello test complete", "reps", reps, "duplicate_session_ids", dupeCount)
	}

	return testfw.Ok()
}
