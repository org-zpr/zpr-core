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

func RunTest(test Tester, state *TestState, card *Scorecard) error {
	state.Reset()
	ctest := card.Start(test)
	state.Log.Infow("running test", "test", test.Name())
	if err := test.Run(state, ctest); err != nil {
		// Automatically fail the test and return the error if test returns an error.
		// Note that we do not automtically pass the test if no error is returned.
		state.Log.Errorw("test failed", "test", test.Name(), "error", err)
		ctest.Failed(err)
		return err
	}
	if ctest.Passing() {
		state.Log.Infow("test passed", "test", test.Name())
	} else {
		state.Log.Errorw("test failed", "test", test.Name())
	}
	return nil
}
