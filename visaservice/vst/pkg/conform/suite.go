package conform

import (
	"crypto/x509"
	"fmt"
	"net/netip"

	"zpr.org/vst/pkg/mocks"
	"zpr.org/vst/pkg/vsadmin"

	"zpr.org/vsx/polio"

	"go.uber.org/zap"
)

var TestsToRun = []ConformanceTest{
	HelloReps,
	GetCurrentPolicy,
	CheckChallenge,
	RejectInvalidAuth,
	AcceptValidAuth,
	AuthorizeConnect,
}

type ConformanceTest int

const (
	HelloReps ConformanceTest = iota
	GetCurrentPolicy
	CheckChallenge
	RejectInvalidAuth
	AcceptValidAuth
	AuthorizeConnect
)

type runner func(*TestState, *TestRun) error

var runners = map[ConformanceTest]runner{
	HelloReps:         RunHelloReps,
	GetCurrentPolicy:  RunGetCurrentPolicy,
	CheckChallenge:    RunCheckChallenge,
	RejectInvalidAuth: RunRejectInvalidAuth,
	AcceptValidAuth:   RunAcceptValidAuth,
	AuthorizeConnect:  RunAuthorizeConnect,
}

func (ct ConformanceTest) String() string {
	switch ct {
	case HelloReps:
		return "HELLO repeats"
	case GetCurrentPolicy:
		return "GetCurrentPolicy"
	case CheckChallenge:
		return "CheckChallenge"
	case RejectInvalidAuth:
		return "RejectInvalidAuth"
	case AcceptValidAuth:
		return "AcceptValidAuth"
	case AuthorizeConnect:
		return "AuthorizeConnect"
	default:
		return fmt.Sprintf("ConformanceTest<%d>", ct)
	}
}

func RunTests(tests []ConformanceTest, vsAddr, adminAddr netip.AddrPort, nodeCert *x509.Certificate, log *zap.Logger) (*Scorecard, error) {
	zlog := log.Sugar()
	card := NewScorecard(len(tests))
	state := NewTestState(vsAddr, adminAddr, nodeCert, zlog)
	defer state.Close()
	for _, test := range tests {
		if err := RunTest(test, state, card); err != nil {
			return card, fmt.Errorf("test %s failed: %w", test, err)
		}
	}
	return card, nil
}

type TestState struct {
	vsAddr      netip.AddrPort // visa service address for thrift api
	adminAddr   netip.AddrPort // visa service admin HTTPS api
	nodeCert    *x509.Certificate
	log         *zap.SugaredLogger
	policy      *polio.Policy   // policy extracted from GetCurrentPolicy, may be nil
	adminClient *vsadmin.Client // use GetAdminClient
	node        *mocks.Node     // use GetNode
}

func NewTestState(vsAddr, adminAddr netip.AddrPort, nodeCert *x509.Certificate, log *zap.SugaredLogger) *TestState {
	return &TestState{
		vsAddr:    vsAddr,
		adminAddr: adminAddr,
		nodeCert:  nodeCert,
		log:       log,
	}
}

func (ts *TestState) GetAdminClient() (*vsadmin.Client, error) {
	if ts.adminClient == nil {
		vsadmin, err := vsadmin.NewVSAdminClient(ts.adminAddr, ts.log.Desugar())
		if err != nil {
			return nil, fmt.Errorf("failed to create visa service admin client: %v", err)
		}
		ts.adminClient = vsadmin
	}
	return ts.adminClient, nil
}

func (ts *TestState) GetNode() (*mocks.Node, error) {
	if ts.node == nil {
		mockNode, err := mocks.NewNode(ts.vsAddr, ts.log.Desugar())
		if err != nil {
			return nil, fmt.Errorf("failed to create mock node: %v", err)
		}
		ts.node = mockNode
	}
	return ts.node, nil
}

// May be empty string.
// This is set when authenticate is called on node and it succeeds.
func (ts *TestState) GetAPIKey() string {
	if ts.node != nil {
		return ts.node.GetAPIKey()
	}
	return ""
}

func (ts *TestState) Close() {
	if ts.node != nil {
		ts.node.Close()
		ts.node = nil
	}
}
