package compiler

import (
	"fmt"
	"sort"
	"strings"

	"zpr.org/vsx/polio"
	"zpr.org/vsx/zpl/defs"
)

// register_service(NAME, TYPE, ENDPOINTS_STRING)
func registerService(sname string, stype polio.SvcT, endpts string) *polio.Instruction {
	ins := &polio.Instruction{Opcode: polio.OpCodeT_OP_Register}
	ins.Args = append(ins.Args, &polio.Argument{
		Arg: &polio.Argument_Strval{sname},
	})
	ins.Args = append(ins.Args, &polio.Argument{
		Arg: &polio.Argument_Svcval{stype},
	})
	ins.Args = append(ins.Args, &polio.Argument{
		Arg: &polio.Argument_Strval{endpts},
	})
	return ins
}

func setFlag(ft polio.FlagT) *polio.Instruction {
	ins := &polio.Instruction{Opcode: polio.OpCodeT_OP_SetFlag}
	ins.Args = append(ins.Args, &polio.Argument{
		Arg: &polio.Argument_Flagval{ft},
	})
	return ins
}

func setCIDR(cidrstr string) *polio.Instruction {
	return setSetConfigVal(defs.ConfKeyCIDR, cidrstr)
}

func setSetConfigVal(name, value string) *polio.Instruction {
	ins := &polio.Instruction{Opcode: polio.OpCodeT_OP_SetCfg}
	ins.Args = append(ins.Args, &polio.Argument{
		Arg: &polio.Argument_Strval{name},
	})
	ins.Args = append(ins.Args, &polio.Argument{
		Arg: &polio.Argument_Strval{value},
	})
	return ins
}

// This could be more subtle: we just return true if the two procs have the
// same instructions, with the same args, in the same order.
func equivalentProcs(a, b *polio.Proc) bool {
	if len(a.GetProc()) != len(b.GetProc()) {
		return false
	}
	for i, ai := range a.GetProc() {
		bi := b.GetProc()[i]
		if !equivalentInstructions(ai, bi) {
			return false
		}
	}
	return true
}

func equivalentInstructions(a, b *polio.Instruction) bool {
	if a.GetOpcode() != b.GetOpcode() {
		return false
	}
	if len(a.GetArgs()) != len(b.GetArgs()) {
		return false
	}
	for i, aa := range a.GetArgs() {
		bb := b.GetArgs()[i]
		if !equivalentArgs(aa, bb) {
			return false
		}
	}
	return true
}

func equivalentArgs(a, b *polio.Argument) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	switch aa := a.GetArg().(type) {
	case *polio.Argument_Ival:
		if bv, ok := b.GetArg().(*polio.Argument_Ival); ok {
			return aa.Ival == bv.Ival
		}

	case *polio.Argument_Uival:
		if bv, ok := b.GetArg().(*polio.Argument_Uival); ok {
			return aa.Uival == bv.Uival
		}

	case *polio.Argument_Strval:
		if bv, ok := b.GetArg().(*polio.Argument_Strval); ok {
			return aa.Strval == bv.Strval
		}

	case *polio.Argument_Flagval:
		if bv, ok := b.GetArg().(*polio.Argument_Flagval); ok {
			return aa.Flagval == bv.Flagval
		}

	case *polio.Argument_Svcval:
		if bv, ok := b.GetArg().(*polio.Argument_Svcval); ok {
			return aa.Svcval == bv.Svcval
		}

	case *polio.Argument_Insval:
		if bv, ok := b.GetArg().(*polio.Argument_Insval); ok {
			return equivalentInstructions(aa.Insval, bv.Insval)
		}

	case *polio.Argument_Spval:
		if bv, ok := b.GetArg().(*polio.Argument_Spval); ok {
			return (aa.Spval.GetA() == bv.Spval.GetA()) && (aa.Spval.GetB() == bv.Spval.GetB())
		}

	case *polio.Argument_Bval:
		if bv, ok := b.GetArg().(*polio.Argument_Bval); ok {
			return aa.Bval == bv.Bval
		}

	default:
		panic(fmt.Sprintf("unhandled arg type: %#v", aa))
	}
	return false
}

func addProc(pp *polio.Proc, p *polio.Policy) uint32 {
	if len(pp.Proc) == 0 {
		return defs.NoProc
	}

	// Each PROC is an array of Instructions. We want the the instructions sorted by OPCODE.
	sort.Slice(pp.Proc, func(i, j int) bool {
		if pp.Proc[i].GetOpcode() == pp.Proc[j].GetOpcode() {
			// Just compare as strings.
			return strings.Compare(PseudocodeForInstruction(pp.Proc[i]), PseudocodeForInstruction(pp.Proc[j])) < 0
		}
		return pp.Proc[i].GetOpcode() < pp.Proc[j].GetOpcode()
	})

	idx := len(p.Procs)
	p.Procs = append(p.Procs, pp)
	return uint32(idx)
}

// copied from core/policy/proc.go
func Pseudocode(p *polio.Proc) string {
	var buf strings.Builder
	for i, instr := range p.GetProc() {
		buf.WriteString(fmt.Sprintf("%0.3d: ", i))
		writeInstruction(&buf, instr)
		buf.WriteString("\n")
	}
	return buf.String()
}

// copied from core/policy/proc.go
func PseudocodeForInstruction(i *polio.Instruction) string {
	var buf strings.Builder
	writeInstruction(&buf, i)
	return buf.String()
}

// copied from core/policy/proc.go
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
