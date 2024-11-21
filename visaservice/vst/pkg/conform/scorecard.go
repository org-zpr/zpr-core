package conform

import (
	"fmt"
	"time"
)

type ConformanceTest int

const (
	HelloReps ConformanceTest = iota
	GetCurrentPolicy
)

func (ct ConformanceTest) String() string {
	switch ct {
	case HelloReps:
		return "node: HELLO repeats"
	case GetCurrentPolicy:
		return "admin: GetCurrentPolicy"
	default:
		return fmt.Sprintf("ConformanceTest<%d>", ct)
	}
}

type Scorecard struct {
	Tests []TestResult
}

type TestResult struct {
	Test       ConformanceTest
	Pass       bool
	Elapsed    time.Duration
	FailReason string
}

type TestRun struct {
	Test  ConformanceTest
	Start time.Time
	Card  *Scorecard
}

func NewScorecard() *Scorecard {
	return &Scorecard{}
}

func (s *Scorecard) Start(t ConformanceTest) *TestRun {
	tr := TestRun{
		Test:  t,
		Start: time.Now(),
		Card:  s,
	}
	return &tr
}

func (tr *TestRun) Passed() {
	tr.Card.AddTestResult(TestResult{
		Test:    tr.Test,
		Pass:    true,
		Elapsed: time.Since(tr.Start),
	})
}

func (tr *TestRun) Failed(err error) {
	tr.Card.AddTestResult(TestResult{
		Test:       tr.Test,
		Pass:       false,
		Elapsed:    time.Since(tr.Start),
		FailReason: err.Error(),
	})
}

func (s *Scorecard) AddTestResult(tr TestResult) {
	s.Tests = append(s.Tests, tr)
}

func (s *Scorecard) Print() {
	fmt.Printf("Conformance Test Results (%d test%s)\n", len(s.Tests), pluralize(len(s.Tests)))
	fmt.Printf("--------------------------------------------------------\n")
	failCount := 0
	for _, tr := range s.Tests {
		fmt.Printf("%-30v", tr.Test)
		if tr.Pass {
			fmt.Printf("  PASS (%s)\n", tr.Elapsed)
		} else {
			fmt.Printf("  FAIL %s\n", tr.FailReason)
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
