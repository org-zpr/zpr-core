package mocks

import "fmt"

type PLogger struct {
	enabled bool
	left    string
	right   string
}

type Direction int

const (
	Fwd Direction = iota
	Rev
)

func NewPLogger(left, right string) *PLogger {
	return &PLogger{
		enabled: true,
		left:    left,
		right:   right,
	}
}

func (p *PLogger) Enable() {
	p.enabled = true
}

func (p *PLogger) Disable() {
	p.enabled = false
}

func (p *PLogger) logFwd(msg string) {
	fmt.Printf("	%8s -> %-8s: %s\n", p.left, p.right, msg)
}

func (p *PLogger) logRev(msg string) {
	fmt.Printf("	%8s <- %-8s: %s\n", p.left, p.right, msg)
}

func (p *PLogger) Log(dir Direction, msg string) {
	if p.enabled == false {
		return
	}
	switch dir {
	case Fwd:
		p.logFwd(msg)
	case Rev:
		p.logRev(msg)
	default:
		panic("invalid direction")
	}
}
