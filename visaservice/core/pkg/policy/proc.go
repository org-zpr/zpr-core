package policy

import (
	fmt "fmt"
	"strings"

	"zpr.org/vsx/polio"
)

// Pseudocode return the procedure in a human readable "pseudocode" format.
func Pseudocode(p *polio.Proc) string {
	var buf strings.Builder
	for i, instr := range p.GetProc() {
		buf.WriteString(fmt.Sprintf("%0.3d: ", i))
		writeInstruction(&buf, instr)
		buf.WriteString("\n")
	}
	return buf.String()
}

func PseudocodeForInstruction(i *polio.Instruction) string {
	var buf strings.Builder
	writeInstruction(&buf, i)
	return buf.String()
}

func writeInstruction(buf *strings.Builder, instr *polio.Instruction) {
	buf.WriteString(fmt.Sprintf("%v (", instr.GetOpcode()))
	for j, arg := range instr.GetArgs() {
		if j > 0 {
			buf.WriteString(", ")
		}
		switch av := arg.Arg.(type) {
		case *polio.Argument_Ival:
			buf.WriteString(fmt.Sprintf("%v", av.Ival))
		case *polio.Argument_Uival:
			buf.WriteString(fmt.Sprintf("%v", av.Uival))
		case *polio.Argument_Strval:
			buf.WriteString(fmt.Sprintf("%v", av.Strval))
		case *polio.Argument_Flagval:
			buf.WriteString(fmt.Sprintf("%v", av.Flagval))
		case *polio.Argument_Svcval:
			buf.WriteString(fmt.Sprintf("%v", av.Svcval))
		case *polio.Argument_Insval:
			// recurse!
			writeInstruction(buf, av.Insval)
		case *polio.Argument_Spval:
			buf.WriteString(fmt.Sprintf("(%v, %v)", av.Spval.GetA(), av.Spval.GetB()))
		case *polio.Argument_Bval:
			buf.WriteString(fmt.Sprintf("%v", av.Bval))
		default:
			buf.WriteString(fmt.Sprintf("%v", arg.Arg))
		}
	}
	buf.WriteString(")")
}
