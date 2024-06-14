package compiler

import (
	"fmt"
	"os"
)

type LogLevel int

const (
	LLSILENT LogLevel = iota
	LLQUIET
	LLVERBOSE
)

func (c *Compilation) warn(s string) {
	c.warnings++
	if c.ll > LLSILENT {
		fmt.Fprintf(os.Stderr, "warning: %v\n", s)
	}
}

func (c *Compilation) warnf(format string, args ...interface{}) {
	c.warn(fmt.Sprintf(format, args...))
}

func (c *Compilation) info(s string) {
	if c.ll >= LLQUIET {
		fmt.Fprintf(os.Stderr, "**       %v\n", s)
	}
}

func (c *Compilation) infof(format string, args ...interface{}) {
	c.info(fmt.Sprintf(format, args...))
}

func (c *Compilation) debug(s string) {
	if c.ll >= LLVERBOSE {
		fmt.Fprintf(os.Stderr, "**       %v\n", s)
	}
}

func (c *Compilation) debugf(format string, args ...interface{}) {
	c.debug(fmt.Sprintf(format, args...))
}
