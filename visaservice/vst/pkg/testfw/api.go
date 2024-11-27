package testfw

type Tester interface {
	Name() string
	Run(state *TestState, ctest *TestRun) error
}
