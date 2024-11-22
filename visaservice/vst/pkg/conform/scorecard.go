package conform

import (
	"fmt"
	"time"

	"github.com/fatih/color"
)

type Scorecard struct {
	count int // total number of tests expected to run
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

func NewScorecard(testCount int) *Scorecard {
	return &Scorecard{
		count: testCount,
	}
}

func (s *Scorecard) Start(t ConformanceTest) *TestRun {
	fmt.Printf("running test %d of %d: %s\n", len(s.Tests)+1, s.count, t.String())
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
	tr.Failedm(err.Error())
}

func (tr *TestRun) Failedm(msg string) {
	tr.Card.AddTestResult(TestResult{
		Test:       tr.Test,
		Pass:       false,
		Elapsed:    time.Since(tr.Start),
		FailReason: msg,
	})
}

func (s *Scorecard) AddTestResult(tr TestResult) {
	s.Tests = append(s.Tests, tr)
}

func (s *Scorecard) Print() {
	red := color.New(color.FgRed).PrintfFunc()
	green := color.New(color.FgGreen).PrintfFunc()

	fmt.Printf("Conformance Test Results (%d test%s)\n", len(s.Tests), pluralize(len(s.Tests)))
	fmt.Printf("--------------------------------------------------------\n")
	failCount := 0
	for _, tr := range s.Tests {
		fmt.Printf("%-30v", tr.Test)
		if tr.Pass {
			green("  PASS")
			fmt.Printf(" (%s)\n", tr.Elapsed)
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
