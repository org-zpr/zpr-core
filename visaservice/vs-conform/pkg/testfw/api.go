package testfw

type Order int

const (
	OrderFirst    Order = 0
	OrderEarlier  Order = 100
	OrderDontCare Order = 500
	OrderLater    Order = 1000
)

type Tester interface {
	Name() string

	// Smaller numbers here run before larger numbers.
	Order() Order

	// Run runs a test.
	//
	// Returning nil is same as returning a successful result.
	Run(state *TestState) *RunResult
}
