package tests

import (
	"zpr.org/vsapi"
	"zpr.org/vst/pkg/testfw"
)

type RejectInvalidAuth struct{}

func init() {
	testfw.Register(&RejectInvalidAuth{})
}

func (t *RejectInvalidAuth) Name() string {
	return "RejectInvalidAuth"
}

func (t *RejectInvalidAuth) Order() testfw.Order {
	return testfw.OrderDontCare
}

// Send back a challenge response that is clearly not valid.
func (t *RejectInvalidAuth) Run(state *testfw.TestState) *testfw.RunResult {
	mockNode, err := state.GetNode()
	if err != nil {
		return testfw.RunFailsFatal(err)
	}

	// NODE->VS : Hello
	resp, err := mockNode.Hello()
	if err != nil {
		return testfw.Faile(err)
	}
	if resp.Challenge == nil {
		return testfw.Fail("challenge is nil")
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
		NodeActor:  nil,
	}
	apiKey, err := mockNode.Authenticate(&authReq)
	if err == nil {
		return testfw.Failf("authenticate succeeded with invalid auth: %s", apiKey)
	}
	return testfw.Ok()
}
