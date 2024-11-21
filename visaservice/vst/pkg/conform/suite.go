package conform

import (
	"fmt"
	"net/netip"

	"go.uber.org/zap"
	"zpr.org/vst/pkg/mocks"
	"zpr.org/vst/pkg/vsadmin"
)

func RunTests(vsAddr, adminAddr netip.AddrPort, log *zap.Logger) (*Scorecard, error) {

	zlog := log.Sugar()

	card := NewScorecard()

	vsadmin, err := vsadmin.NewVSAdminClient(adminAddr, zlog.Desugar())
	if err != nil {
		return card, fmt.Errorf("failed to create visa service admin client: %v", err)
	}

	ctest := card.Start(GetCurrentPolicy)
	pol, err := vsadmin.GetCurrentPolicy()
	if err != nil {
		ctest.Failed(err)
		return card, fmt.Errorf("failed to get current policy using admin interface: %v", err)
	}
	ctest.Passed()

	zlog.Infow("policy extracted from container", "serial", pol.GetSerialVersion())
	mockNode, err := mocks.NewNode(vsAddr, log)
	if err != nil {
		return card, fmt.Errorf("failed to create mock node: %v", err)
	}
	defer mockNode.Close()

	ctest = card.Start(HelloReps)
	if err := mockNode.TestRepeatHello(100); err != nil {
		ctest.Failed(err)
		return card, fmt.Errorf("repeat hello test failed: %v", err)
	}
	ctest.Passed()

	return card, nil
}
