package tests

import (
	"fmt"

	"zpr.org/vst/pkg/plc"
	"zpr.org/vst/pkg/testfw"
)

type AuthorizeConnect struct{}

func init() {
	// testfw.Register(&AuthorizeConnect{}) // TODO: connect needs to use bootstrap
}

func (t *AuthorizeConnect) Name() string {
	return "AuthorizeConnect"
}

func (t *AuthorizeConnect) Order() testfw.Order {
	return testfw.OrderEarlier
}

func (t *AuthorizeConnect) Run(state *testfw.TestState) *testfw.RunResult {
	// If we don't have an API key in state, run the accept-valid-auth test.
	node, err := state.GetNode()
	if err != nil {
		return testfw.RunFailsFatal(err)
	}
	if !node.HasApiKey() {
		_, err := connectNodeAndGetApiKey(state)
		if err != nil {
			return testfw.Faile(err)
		}
		state.Pause()
	}
	if !node.HasApiKey() {
		return testfw.Fail("unable to get an API key from node")
	}

	policy, err := state.GetOrLoadPolicy(true)
	if err != nil {
		return testfw.Faile(err)
	}

	// Pick a non-node, non-provider to connect as.
	connects := plc.GetConnects(policy)
	if connects == nil {
		return testfw.Fail("cannot find any authorized connectors in policy")
	}

	var candidate *plc.ConnectRec
	var nodeCR *plc.ConnectRec
	for _, connect := range connects {
		if connect.IsNode() {
			if nodeCR != nil {
				panic("expecting only one node in policy")
			}
			nodeCR = connect
			continue
		}
		if len(connect.Provides) > 0 {
			continue
		}
		if !plc.ConnectRecHasSetAttr(connect, plc.KAttrCN) {
			// We cannot self-auth without this
			continue
		}
		if candidate == nil {
			candidate = connect
		}
	}
	if nodeCR == nil {
		panic("expecting a node in policy")
	}
	if candidate == nil {
		return testfw.Fail("cannot find any non-node, non-provider in policy")
	}

	actor, err := connectAdapter(node, candidate, nodeCR.Addr, state.GetNextAdapterAddr())
	if err != nil {
		return testfw.Fail(fmt.Sprintf("failed to connect adapter (CN='%v'): %v", candidate.CN, err))
	}

	// TODO: Check the actor.
	if actor == nil {
		return testfw.Fail("authorize-connect did not return an actor")
	}

	return testfw.Ok()
}
