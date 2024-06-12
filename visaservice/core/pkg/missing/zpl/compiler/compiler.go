package compiler

import (
	"errors"

	"zpr.org/vs/pkg/missing/zpl/fs"

	"zpr.org/vsx/polio"
)

type CompileOpts struct {
	//Quiet              bool
	//Silent             bool
	//Werror             bool
	Verbose  bool
	Revision string // Revision is not optional
	//DynamicAsserts     bool
	//AbideAsserts       bool
	//TraceAsserts       string
	//DSDs               []*pp.DSDesc // passed to pp
	//SkipBootstrapVisas bool         // If TRUE does not generate bootstap visas
}

func Compile(main string, store fs.FileStore, opts *CompileOpts) (*polio.Policy, error) {
	return nil, errors.New("not implemented")
}
