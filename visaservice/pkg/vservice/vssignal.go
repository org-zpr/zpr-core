package vservice

type VSSignal interface {
	Type() VSSignalT
}

type VSSignalT int

const (
	VSSignalNOP  VSSignalT = iota // None, not used
	VSSignalExit                  // visa service exiting
)

type sig struct {
	t VSSignalT
}

func (s *sig) Type() VSSignalT {
	if s == nil {
		return VSSignalNOP
	}
	return s.t
}
