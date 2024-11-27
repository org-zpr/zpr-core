package testfw

import (
	"crypto/x509"
	"fmt"
	"net/netip"
	"time"

	"go.uber.org/zap"

	"zpr.org/vst/pkg/mocks"
	"zpr.org/vst/pkg/vsadmin"

	"zpr.org/vsx/polio"
)

type TestState struct {
	vsAddr      netip.AddrPort // visa service address for thrift api
	adminAddr   netip.AddrPort // visa service admin HTTPS api
	NodeCert    *x509.Certificate
	Log         *zap.SugaredLogger
	policy      *polio.Policy   // policy extracted from GetCurrentPolicy, may be nil
	adminClient *vsadmin.Client // use GetAdminClient
	node        *mocks.Node     // use GetNode
	lastOctect  uint32          // last octect of the IP address of the node
	pauseTime   time.Duration
}

func NewTestState(vsAddr, adminAddr netip.AddrPort, nodeCert *x509.Certificate, log *zap.SugaredLogger) *TestState {
	return &TestState{
		vsAddr:     vsAddr,
		adminAddr:  adminAddr,
		NodeCert:   nodeCert,
		Log:        log,
		lastOctect: 2,
		pauseTime:  2 * time.Second,
	}
}

func (ts *TestState) Pause() {
	time.Sleep(ts.pauseTime)
}

// Do whatever is needed to "reset" state before each test.
// We keep many things hanging around, but we do clear any message in the VSS queues.
func (ts *TestState) Reset() {
	if ts.node != nil {
		ts.node.Reset()
	}
}

func (ts *TestState) GetNextOctect() uint32 {
	ts.lastOctect++
	return ts.lastOctect
}

func (ts *TestState) GetAdminClient() (*vsadmin.Client, error) {
	if ts.adminClient == nil {
		vsadmin, err := vsadmin.NewVSAdminClient(ts.adminAddr, ts.Log.Desugar())
		if err != nil {
			return nil, fmt.Errorf("failed to create visa service admin client: %v", err)
		}
		ts.adminClient = vsadmin
	}
	return ts.adminClient, nil
}

// Get node with VSS running
func (ts *TestState) GetNode() (*mocks.Node, error) {
	if ts.node == nil {
		mockNode, err := mocks.NewNode(ts.vsAddr, ts.Log.Desugar())
		if err != nil {
			return nil, fmt.Errorf("failed to create mock node: %v", err)
		}
		if err := mockNode.EnableVSS(netip.MustParseAddrPort("0.0.0.0:8183")); err != nil {
			return nil, fmt.Errorf("failed to start VSS: %w", err)
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

// Trys to load policy.  Sets state.policy as side effect if all goes well.
func (ts *TestState) LoadPolicy() (*polio.Policy, error) {
	cli, err := ts.GetAdminClient()
	if err != nil {
		return nil, err
	}
	pol, err := cli.GetCurrentPolicy()
	if err != nil {
		return nil, fmt.Errorf("failed to get current policy using admin interface: %v", err)
	}
	ts.policy = pol
	ts.Log.Infow("policy extracted from container", "serial", pol.GetSerialVersion())
	return pol, nil
}

// Only loads policy if is not already loaded.
// If withPause is true, then it will pause after loading if loading was needed.
func (ts *TestState) GetOrLoadPolicy(withPause bool) (*polio.Policy, error) {
	if ts.policy != nil {
		return ts.policy, nil
	}
	if pol, err := ts.LoadPolicy(); err == nil {
		if withPause {
			ts.Pause()
		}
		return pol, nil
	} else {
		return nil, err
	}
}

func (ts *TestState) HasPolicy() bool {
	return ts.policy != nil
}
