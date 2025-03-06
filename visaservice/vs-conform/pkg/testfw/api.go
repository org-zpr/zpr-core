package testfw

type Tester interface {
	Name() string

	// Smaller numbers here run before larger numbers.
	Order() int

	// Run runs a test.
	//
	// A test should not normally reuturn an error. Instead, it should call one of the
	// fail functions on the TestRun struct passed to it.  If a test does return an
	// explicit error, the suite will abort and any subsequent tests in the suite
	// will be skipped.
	Run(state *TestState, ctest *TestRun) error
}
