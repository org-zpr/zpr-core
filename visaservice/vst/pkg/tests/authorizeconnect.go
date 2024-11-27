package tests

import (
	"zpr.org/vst/pkg/plc"
	"zpr.org/vst/pkg/testfw"
)

type AuthorizeConnect struct{}

func init() {
	testfw.Register(&AuthorizeConnect{})
}

func (t *AuthorizeConnect) Name() string {
	return "AuthorizeConnect"
}

func (t *AuthorizeConnect) Run(state *testfw.TestState, ctest *testfw.TestRun) error {
	// If we don't have an API key in state, run the accept-valid-auth test.
	node, err := state.GetNode()
	if err != nil {
		return err
	}
	if !node.HasApiKey() {
		_, err := connectNodeAndGetApiKey(state)
		if err != nil {
			ctest.Failed(err)
			return nil
		}
		state.Pause()
	}
	if !node.HasApiKey() {
		ctest.Failedm("unable to get an API key from node")
		return nil
	}

	policy, err := state.GetOrLoadPolicy(true)
	if err != nil {
		ctest.Failed(err)
		return nil
	}

	// Pick a non-node, non-provider to connect as.
	connects := plc.GetConnects(policy)
	if connects == nil {
		ctest.Failedm("cannot find any authorized connectors in policy")
		return nil
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
		if candidate == nil {
			candidate = connect
		}
	}
	if nodeCR == nil {
		panic("expecting a node in policy")
	}
	if candidate == nil {
		ctest.Failedm("cannot find any non-node, non-provider in policy")
		return nil
	}

	agent, err := connectAdapter(node, candidate, nodeCR.Addr, state.GetNextOctect())
	if err != nil {
		ctest.Failed(err)
		return nil
	}

	// TODO: Check the agent.
	if agent == nil {
		ctest.Failedm("authorize-connect did not return an agent")
		return nil
	}

	ctest.Passed()
	return nil
}
