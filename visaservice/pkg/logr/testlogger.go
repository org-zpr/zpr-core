package logr

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// TestLogger for use during unit testing.
type TestLogger struct {
	base *log.Logger
	args []interface{}
}

func kvToStr(kvargs ...interface{}) string {
	var b strings.Builder
	readK := true
	for _, k := range kvargs {
		if readK {
			fmt.Fprintf(&b, "%v=", k)
			readK = false
		} else {
			fmt.Fprintf(&b, "%v ", k)
			readK = true
		}
	}
	return b.String()
}

func NewTestLogger() *TestLogger {
	return &TestLogger{
		base: log.New(os.Stdout, "**", log.LstdFlags),
	}
}

func (t *TestLogger) DPanic(msg string, kvargs ...interface{}) {
	t.panicf("%v: %v", msg, kvToStr(kvargs...))
}
func (t *TestLogger) DPanicm(msg string) {
	t.panicf("%v", msg)
}
func (t *TestLogger) DPanicf(template string, args ...interface{}) {
	t.panicf(template, args...)
}

func (t *TestLogger) Panic(msg string, kvargs ...interface{}) {
	t.panicf("%v: %v", msg, kvToStr(kvargs...))
}

func (t *TestLogger) Panicm(msg string) {
	t.panicf("%v", msg)
}

func (t *TestLogger) Panicf(template string, args ...interface{}) {
	t.panicf(template, args...)
}

func (t *TestLogger) Error(msg string, kvargs ...interface{}) {
	t.logf("ERROR", "%v: %v", msg, kvToStr(kvargs...))
}

func (t *TestLogger) Errorm(msg string) {
	t.logf("ERROR", "%v", msg)
}

func (t *TestLogger) Errorf(template string, args ...interface{}) {
	t.logf("ERROR", template, args...)
}

func (t *TestLogger) Warn(msg string, kvargs ...interface{}) {
	t.logf("WARN", "%v: %v", msg, kvToStr(kvargs...))

}
func (t *TestLogger) Warnm(msg string) {
	t.logf("WARN", "%v", msg)
}
func (t *TestLogger) Warnf(template string, args ...interface{}) {
	t.logf("WARN", template, args...)
}

func (t *TestLogger) Info(msg string, kvargs ...interface{}) {
	t.logf("INFO", "%v: %v", msg, kvToStr(kvargs...))
}
func (t *TestLogger) Infom(msg string) {
	t.logf("INFO", "%v", msg)
}

func (t *TestLogger) Infof(template string, args ...interface{}) {
	t.logf("INFO", template, args...)
}

func (t *TestLogger) Debug(msg string, args ...interface{}) {
	t.logf("DEBUG", "%v: %v", msg, kvToStr(args...))
}
func (t *TestLogger) Debugm(msg string) {
	t.logf("DEBUG", "%v", msg)
}
func (t *TestLogger) Debugf(template string, args ...interface{}) {
	t.logf("DEBUG", template, args...)
}

func (t *TestLogger) With(args ...interface{}) Logger {
	aa := make([]interface{}, len(t.args))
	copy(aa, t.args)
	aa = append(aa, args...)
	return &TestLogger{
		base: t.base,
		args: aa,
	}
}

func (t *TestLogger) WithError(err error) Logger {
	return t.With("error", err)
}

func (t *TestLogger) Sync() {}

/////

func (t *TestLogger) logf(level, template string, args ...interface{}) {
	if len(t.args) > 0 {
		t.base.Printf("%v: %v: %v", level, fmt.Sprintf(template, args...), kvToStr(t.args))
	} else {
		t.base.Printf("%v: %v", level, fmt.Sprintf(template, args...))
	}
}

func (t *TestLogger) panicf(template string, args ...interface{}) {
	if len(t.args) > 0 {
		t.base.Panicf("%v: %v", fmt.Sprintf(template, args...), kvToStr(t.args))
	} else {
		t.base.Panicf(template, args...)
	}
}
