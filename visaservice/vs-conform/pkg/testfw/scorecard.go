package testfw

import (
	"fmt"
	"time"

	"github.com/fatih/color"
)

// Scorecard keeps track of a number of test results.
type Scorecard struct {
	count int // total number of tests expected to run
	Tests []TestResult
}

// TestResult tracks a single test.
type TestResult struct {
	Test       string
	Pass       bool
	Elapsed    time.Duration
	FailReason string
}

// TestRun exists while a test is running.
type TestRun struct {
	Test    string
	Start   time.Time
	Card    *Scorecard
	passing bool
}

func NewScorecard(testCount int) *Scorecard {
	return &Scorecard{
		count: testCount,
	}
}

// Note that a test is starting. Should be followed later by a call to
// Passed or Failed.
func (s *Scorecard) Start(t Tester) *TestRun {
	// fmt.Printf("running test %d of %d: %s\n", len(s.Tests)+1, s.count, t.Name())
	color.Yellow("running test %d of %d: %s", len(s.Tests)+1, s.count, t.Name())
	tr := TestRun{
		Test:    t.Name(),
		Start:   time.Now(),
		Card:    s,
		passing: true,
	}
	return &tr
}

// Note that a test has passed.
func (tr *TestRun) Passed() {
	tr.Card.addTestResult(TestResult{
		Test:    tr.Test,
		Pass:    true,
		Elapsed: time.Since(tr.Start),
	})
}

// Note that a test has failed.
func (tr *TestRun) Failed(err error) {
	tr.passing = false
	tr.Failedm(err.Error())
}

// Note that a test has failed.
func (tr *TestRun) Failedm(msg string) {
	tr.passing = false
	tr.Card.addTestResult(TestResult{
		Test:       tr.Test,
		Pass:       false,
		Elapsed:    time.Since(tr.Start),
		FailReason: msg,
	})
}

func (tr *TestRun) Passing() bool {
	return tr.passing
}

func (s *Scorecard) addTestResult(tr TestResult) {
	s.Tests = append(s.Tests, tr)
}

func (s *Scorecard) Print() {
	red := color.New(color.FgRed).PrintfFunc()
	green := color.New(color.FgGreen).PrintfFunc()

	fmt.Printf("Conformance Test Results (%d test%s)\n", len(s.Tests), pluralize(len(s.Tests)))
	fmt.Printf("-----------------------------------------------------\n")
	failCount := 0
	for _, tr := range s.Tests {
		fmt.Printf("%-30v", tr.Test)
		if tr.Pass {
			green("  PASS")
			fmt.Printf("     (%8.3fms)\n", (float64(tr.Elapsed.Microseconds()) / 1000.0))
		} else {
			red("  FAIL")
			fmt.Println()
			red("     **  ")
			fmt.Println(tr.FailReason)
			failCount++
		}
	}
	fmt.Println()
	if failCount > 0 {
		fmt.Printf("❌ %d test%s failed\n", failCount, pluralize(failCount))
	} else {
		fmt.Printf("✅ All tests passed\n")
	}
}

func pluralize(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
