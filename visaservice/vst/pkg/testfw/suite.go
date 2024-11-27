package testfw

import (
	"crypto/x509"
	"fmt"
	"net/netip"

	"go.uber.org/zap"
)

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
	if err := test.Run(state, ctest); err != nil {
		// Automatically fail if error returned, but we do not automatically pass if nil returned.
		ctest.Failed(err)
		return err
	}
	return nil
}
