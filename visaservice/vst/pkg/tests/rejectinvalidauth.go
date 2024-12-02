package tests

import (
	"fmt"

	"zpr.org/vst/pkg/testfw"
	"zpr.org/vst/pkg/vsapi"
)

type RejectInvalidAuth struct{}

func init() {
	testfw.Register(&RejectInvalidAuth{})
}

func (t *RejectInvalidAuth) Name() string {
	return "RejectInvalidAuth"
}

// Send back a challenge response that is clearly not valid.
func (t *RejectInvalidAuth) Run(state *testfw.TestState, ctest *testfw.TestRun) error {
	mockNode, err := state.GetNode()
	if err != nil {
		return err
	}

	// NODE->VS : Hello
	resp, err := mockNode.Hello()
	if err != nil {
		return err
	}
	if resp.Challenge == nil {
		ctest.Failedm("challenge is nil")
		return nil
	}
	state.Pause()

	// NODE->VS : Authenticate
	authReq := vsapi.NodeAuthRequest{
		SessionID:  resp.SessionID,
		Challenge:  resp.Challenge,
		Timestamp:  0,
		NodeCert:   nil,
		Hmac:       nil,
		VssService: "",
		NodeAgent:  nil,
	}
	apiKey, err := mockNode.Authenticate(&authReq)
	if err == nil {
		ctest.Failedm(fmt.Sprintf("authenticate succeeded with invalid auth: %s", apiKey))
		return nil
	}
	ctest.Passed()
	return nil
}
