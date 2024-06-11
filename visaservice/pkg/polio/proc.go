package polio

import (
	fmt "fmt"
	"strings"
)

// Pseudocode return the procedure in a human readable "pseudocode" format.
func (p *Proc) Pseudocode() string {
	var buf strings.Builder
	for i, instr := range p.GetProc() {
		buf.WriteString(fmt.Sprintf("%0.3d: ", i))
		writeInstruction(&buf, instr)
		buf.WriteString("\n")
	}
	return buf.String()
}

func (i *Instruction) Pseudocode() string {
	var buf strings.Builder
	writeInstruction(&buf, i)
	return buf.String()
}

func writeInstruction(buf *strings.Builder, instr *Instruction) {
	buf.WriteString(fmt.Sprintf("%v (", instr.GetOpcode()))
	for j, arg := range instr.GetArgs() {
		if j > 0 {
			buf.WriteString(", ")
		}
		switch av := arg.Arg.(type) {
		case *Argument_Ival:
			buf.WriteString(fmt.Sprintf("%v", av.Ival))
		case *Argument_Uival:
			buf.WriteString(fmt.Sprintf("%v", av.Uival))
		case *Argument_Strval:
			buf.WriteString(fmt.Sprintf("%v", av.Strval))
		case *Argument_Flagval:
			buf.WriteString(fmt.Sprintf("%v", av.Flagval))
		case *Argument_Svcval:
			buf.WriteString(fmt.Sprintf("%v", av.Svcval))
		case *Argument_Insval:
			// recurse!
			writeInstruction(buf, av.Insval)
		case *Argument_Spval:
			buf.WriteString(fmt.Sprintf("(%v, %v)", av.Spval.GetA(), av.Spval.GetB()))
		case *Argument_Bval:
			buf.WriteString(fmt.Sprintf("%v", av.Bval))
		default:
			buf.WriteString(fmt.Sprintf("%v", arg.Arg))
		}
	}
	buf.WriteString(")")
}
