package adb_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vs/pkg/agent"

	"zpr.org/vs/pkg/vservice/adb"
)

type DummyWatcher struct{}

func (d *DummyWatcher) HandleDBAgentAdded(_ *agent.Agent)   {}
func (d *DummyWatcher) HandleDBAgentRemoved(_ *agent.Agent) {}

func TestCloneNodesToBriefCopiesCounts(t *testing.T) {
	db := adb.NewAgentDB(&DummyWatcher{})

	naddr := netip.MustParseAddr("fd5a:5052:90de::7")

	claims := map[string]string{
		"foo": "bar",
	}
	agnt := agent.NewAgentFromUnsubstantiatedClaims(claims)

	db.AddNode(naddr, naddr, agnt, "foo", "127.0.0.1")

	{
		data := db.CloneNodesToBrief()
		require.Equal(t, 1, len(data))
		require.Equal(t, uint64(0), data[0].ConnectRequests)
		require.Equal(t, uint64(0), data[0].VisaRequests)
	}

	db.IncrNodeConnectReq(naddr)
	db.IncrNodeVisaReq(naddr)

	{
		data := db.CloneNodesToBrief()
		require.Equal(t, 1, len(data))
		require.Equal(t, uint64(1), data[0].ConnectRequests)
		require.Equal(t, uint64(1), data[0].VisaRequests)
	}

}
