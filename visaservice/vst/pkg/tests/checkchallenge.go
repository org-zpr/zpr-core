package tests

import (
	"fmt"

	"zpr.org/vst/pkg/testfw"
	"zpr.org/vst/pkg/vsapi"
)

const MinChallengeNonceSize = 32

type CheckChallenge struct{}

func init() {
	testfw.Register(&CheckChallenge{})
}

func (t *CheckChallenge) Name() string {
	return "CheckChallenge"
}

// Check challenge results from the visa service
func (t *CheckChallenge) Run(state *testfw.TestState, ctest *testfw.TestRun) error {
	mockNode, err := state.GetNode()
	if err != nil {
		return err
	}
	resp, err := mockNode.Hello()
	if err != nil {
		return err
	}

	if resp.SessionID == 0 {
		ctest.Failedm("session id is zero")
		return nil
	}
	if resp.Challenge == nil {
		ctest.Failedm("challenge is nil")
		return nil
	}
	if resp.Challenge.ChallengeType != vsapi.CHALLENGE_TYPE_HMAC_SHA256 {
		ctest.Failedm(fmt.Sprintf("unexpected challenge type: expected %d, got %d",
			vsapi.CHALLENGE_TYPE_HMAC_SHA256,
			resp.Challenge.ChallengeType))
		return nil
	}
	if len(resp.Challenge.ChallengeData) < MinChallengeNonceSize {
		ctest.Failedm(fmt.Sprintf("challenge data is too short: expected at least %d bytes, got %d",
			MinChallengeNonceSize,
			len(resp.Challenge.ChallengeData)))
		return nil
	}
	zeroCount := 0
	for _, b := range resp.Challenge.ChallengeData {
		if b == 0 {
			zeroCount++
		}
	}
	if zeroCount == len(resp.Challenge.ChallengeData) {
		ctest.Failedm("challenge data is all zeros")
		return nil
	}
	ctest.Passed()
	return nil
}
