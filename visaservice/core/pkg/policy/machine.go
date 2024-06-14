package policy

import (
	"fmt"
	"strings"

	"zpr.org/vsx/polio"
)

// Link/Connection related state.
type State interface {
	IsSelf() bool // TRUE if this state is for the invoking, local node.

	// Global -- only invoke if acting on self.
	SetConfig(key, value string) error

	// Link related:
	RegisterService(name string, stype polio.SvcT, endpoints []string) error // endpoint form is: "tcp/80"
	SetFlag(ft polio.FlagT) error
}

// ExecCProc runs the CONNECT proc on the state, which is probably modified.
func ExecCProc(proc *polio.Proc, state State) error {
	if proc == nil {
		return nil
	}
	for _, ins := range proc.GetProc() {
		switch ins.GetOpcode() {
		// In addition to running the instructions, the EXEC rotuine will error
		// out if there are unknown opcodes present.  So all OpCodeT values must
		// be handled.

		case polio.OpCodeT_OP_Nop:
			// NOP

		case polio.OpCodeT_OP_Register:
			// register a service.
			args := ins.GetArgs()
			eps := strings.Split(args[2].GetStrval(), ",")
			if err := state.RegisterService(args[0].GetStrval(), args[1].GetSvcval(), eps); err != nil {
				return err
			}

		case polio.OpCodeT_OP_SetFlag:
			if err := state.SetFlag(ins.GetArgs()[0].GetFlagval()); err != nil {
				return err
			}

		case polio.OpCodeT_OP_SetCfg:
			if state.IsSelf() {
				args := ins.GetArgs()
				if len(args) != 2 {
					return fmt.Errorf("syntax error: SetCfg requires two args")
				}
				if err := state.SetConfig(args[0].GetStrval(), args[1].GetStrval()); err != nil {
					return err
				}
			}

		default:
			// Unexpected opcode
			return fmt.Errorf("unknown proc instruction %v", ins.GetOpcode())

		}
	}
	return nil
}
