package testfw

import (
	"fmt"
	"strings"
)

type RunResult struct {
	success    bool
	fatal      bool
	failReason string
	failError  *error
}

func Ok() *RunResult {
	return &RunResult{
		success: true,
	}
}

func Fail(msg string) *RunResult {
	return &RunResult{
		failReason: msg,
	}
}

func Failf(format string, a ...any) *RunResult {
	return &RunResult{
		failReason: fmt.Sprintf(format, a...),
	}
}

func Faile(err error) *RunResult {
	return &RunResult{
		failError: &err,
	}
}

// RunResultFatalError returns a RunResult that is a fatal error which will cause
// the whole test run to stop.
func RunFailsFatal(err error) *RunResult {
	return &RunResult{
		fatal:     true,
		failError: &err,
	}
}

func (r *RunResult) Success() bool {
	return r.success
}

// Return true if is a fatal error that should halt all testing.
func (r *RunResult) Fatal() bool {
	return r.fatal
}

// Get the error of the unsuccessful run. Panics if this is a successful run.
func (r *RunResult) Error() error {
	if r.success {
		panic("RunResult.Error() called on non-error result")
	}
	if r.failError == nil {
		return fmt.Errorf(r.failReason)
	}
	return *r.failError
}

// Gets the fail reason as a string. Will get empty string if reason/error not
// set or it is a successful run.
func (r *RunResult) FailReason() string {
	var sb strings.Builder
	if r.failReason != "" {
		sb.WriteString(r.failReason)
		sb.WriteString(": ")
	}
	if r.failError != nil {
		sb.WriteString((*r.failError).Error())
	}
	return sb.String()
}
