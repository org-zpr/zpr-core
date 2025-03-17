package tests

import (
	"zpr.org/vsapi"
	"zpr.org/vst/pkg/testfw"
)

const MinChallengeNonceSize = 32

type CheckChallenge struct{}

func init() {
	testfw.Register(&CheckChallenge{})
}

func (t *CheckChallenge) Name() string {
	return "CheckChallenge"
}

func (t *CheckChallenge) Order() testfw.Order {
	return testfw.OrderFirst
}

// Check challenge results from the visa service
func (t *CheckChallenge) Run(state *testfw.TestState) *testfw.RunResult {
	mockNode, err := state.GetNode()
	if err != nil {
		return testfw.RunFailsFatal(err)
	}
	resp, err := mockNode.Hello()
	if err != nil {
		return testfw.Faile(err)
	}

	if resp.SessionID == 0 {
		return testfw.Fail("session id is zero")
	}
	if resp.Challenge == nil {
		return testfw.Fail("challenge is nil")
	}
	if resp.Challenge.ChallengeType != vsapi.CHALLENGE_TYPE_HMAC_SHA256 {
		return testfw.Failf("unexpected challenge type: expected %d, got %d",
			vsapi.CHALLENGE_TYPE_HMAC_SHA256,
			resp.Challenge.ChallengeType)
	}
	if len(resp.Challenge.ChallengeData) < MinChallengeNonceSize {
		return testfw.Failf("challenge data is too short: expected at least %d bytes, got %d",
			MinChallengeNonceSize,
			len(resp.Challenge.ChallengeData))
	}
	zeroCount := 0
	for _, b := range resp.Challenge.ChallengeData {
		if b == 0 {
			zeroCount++
		}
	}
	if zeroCount == len(resp.Challenge.ChallengeData) {
		return testfw.Fail("challenge data is all zeros")
	}
	return testfw.Ok()
}
