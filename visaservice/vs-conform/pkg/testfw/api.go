package testfw

type Tester interface {
	Name() string

	// Smaller numbers here run before larger numbers.
	Order() int

	// Run runs a test.
	//
	// Returning nil is same as returning a successful result.
	Run(state *TestState) *RunResult
}
