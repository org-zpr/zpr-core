package tests

import (
	"fmt"

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

func (t *HelloReps) Order() int {
	return 200
}

// Send a bunch of hello messages in
func (hr *HelloReps) Run(state *testfw.TestState, ctest *testfw.TestRun) error {
	reps := HelloRepsCount
	mockNode, err := state.GetNode()
	if err != nil {
		return err
	}
	mockNode.SetPlogEnabled(false) // too chatty
	sids := make(map[int32]bool)
	dupeCount := 0
	state.Log.Infow("testing hello from node", "reps", reps)
	for i := 0; i < reps; i++ {
		resp, err := mockNode.Hello()
		if err != nil {
			ctest.Failedm(fmt.Sprintf("hello failed at rep %d: %v", i, err))
			return nil
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

	ctest.Passed()
	return nil
}
