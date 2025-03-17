package testfw

import (
	"crypto/x509"
	"fmt"
	"net/netip"

	"go.uber.org/zap"
)

// RunTests runs all the tests in the given list of tests, and returns a scorecard with the results.
// If any test returns an explicit error, the whole suite aborts.
// A test may fail during its run by calling one of the fail functions on the TestRun struct
// passed to each test.
func RunTests(tests []Tester, vsAddr, adminAddr netip.AddrPort, nodeCert *x509.Certificate, log *zap.Logger) (*Scorecard, error) {
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

// Runs a test, only returns an error if the test returns a "fatal" RunResult.
func RunTest(test Tester, state *TestState, card *Scorecard) error {
	state.Reset()
	state.Log.Infow("running test", "test", test.Name())
	ctest := card.Start(test)
	result := test.Run(state)
	if result == nil || result.Success() {
		ctest.Passed()
		state.Log.Infow("test passed", "test", test.Name())
	} else {
		ctest.Failedm(result.FailReason())
		state.Log.Errorw("test failed", "test", test.Name())
		if result.Fatal() {
			return result.Error()
		}
	}
	return nil
}
