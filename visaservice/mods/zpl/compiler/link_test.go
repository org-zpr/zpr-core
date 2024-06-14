package compiler_test

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vsx/zpl/compiler"
	"zpr.org/vsx/zpl/doc"
)

func zplString(s string) doc.ZplString {
	if zs, err := doc.NewZplString(s); err != nil {
		panic(err)
	} else {
		return zs
	}
}

func TestLinksSimple(t *testing.T) {

	nodes := map[string]*doc.Component{
		"n0": {
			Address: zplString("fc00:1001::1"),
			Interfaces: map[string]*doc.Interface{
				"n0i0": &doc.Interface{
					Netaddr: zplString("n0.spacelaser.net:5001"),
				},
			},
		},
		"n1": {
			Address: zplString("fc00:1001::2"),
			Interfaces: map[string]*doc.Interface{
				"n1i0": &doc.Interface{
					Netaddr: zplString("n1.spacelaser.net:5001"),
				},
			},
		},
	}

	topo := &doc.Topology{
		LANs: map[string]*doc.LANDesc{
			"lan0": {
				Nodes: []doc.ZplString{zplString("n0"), zplString("n1")}, // no need for interface names
			},
		},
	}

	d := &doc.Doc{
		Zpr: &doc.ZPR{
			Nodes:    nodes,
			Topology: topo,
		},
	}

	opts := compiler.CompileOpts{
		Verbose: true,
	}
	c := compiler.NewCompilation(d, &opts)
	err := c.SetLinks(d)
	require.Nil(t, err)

	pp := c.GetPolicy()
	links := pp.GetLinks()
	require.Len(t, links, 2) // n0->n1 and n1->n0

	require.False(t, bytes.Equal(links[0].GetSourceId(), links[1].GetSourceId()))

	addrs := []string{
		nodes["n0"].Address.String(),
		nodes["n1"].Address.String(),
	}
	require.Contains(t, addrs, net.IP(links[0].GetSourceId()).String())
	require.Contains(t, addrs, net.IP(links[1].GetSourceId()).String())
}

func TestLinksMultiface(t *testing.T) {

	nodes := map[string]*doc.Component{
		"n0": {
			Address: zplString("fc00:1001::1"),
			Interfaces: map[string]*doc.Interface{
				"n0i0": &doc.Interface{
					Netaddr: zplString("n0.spacelaser.net:5001"),
				},
				"n0i1": &doc.Interface{
					Netaddr: zplString("n0.altnet.net:5001"),
				},
			},
		},
		"n1": {
			Address: zplString("fc00:1001::2"),
			Interfaces: map[string]*doc.Interface{
				"n1i0": &doc.Interface{
					Netaddr: zplString("n1.spacelaser.net:5001"),
				},
				"n1i1": &doc.Interface{
					Netaddr: zplString("n1.altnet.net:5001"),
				},
			},
		},
	}

	topo := &doc.Topology{
		LANs: map[string]*doc.LANDesc{
			"lan0": {
				Nodes: []doc.ZplString{zplString("n0.n0i1"), zplString("n1.n1i0")},
			},
			"lan1": {
				Nodes: []doc.ZplString{zplString("n0.n0i0"), zplString("n1.n1i1")},
			},
		},
	}

	d := &doc.Doc{
		Zpr: &doc.ZPR{
			Nodes:    nodes,
			Topology: topo,
		},
	}

	opts := compiler.CompileOpts{
		Verbose: true,
	}
	c := compiler.NewCompilation(d, &opts)
	err := c.SetLinks(d)
	require.Nil(t, err)

	pp := c.GetPolicy()
	links := pp.GetLinks()
	require.Len(t, links, 4)

	require.False(t, bytes.Equal(links[0].GetSourceId(), links[1].GetSourceId()))

	addrs := []string{
		nodes["n0"].Address.String(),
		nodes["n1"].Address.String(),
	}
	require.Contains(t, addrs, net.IP(links[0].GetSourceId()).String())
	require.Contains(t, addrs, net.IP(links[1].GetSourceId()).String())
}

func TestLinksFailIfServiceMissing(t *testing.T) {
	nodes := map[string]*doc.Component{
		"n0": {
			Address: zplString("fc00:1001::1"),
			Interfaces: map[string]*doc.Interface{
				"n0i0": &doc.Interface{
					Netaddr: zplString("n0.spacelaser.net:5001"),
				},
			},
		},
		"n99": {
			Address: zplString("fc00:1001::2"),
			Interfaces: map[string]*doc.Interface{
				"n1i0": &doc.Interface{
					Netaddr: zplString("n1.spacelaser.net:5001"),
				},
			},
		},
	}

	topo := &doc.Topology{
		LANs: map[string]*doc.LANDesc{
			"lan0": {
				Nodes: []doc.ZplString{zplString("n0"), zplString("n1")},
			},
		},
	}
	d := &doc.Doc{
		Zpr: &doc.ZPR{
			Nodes:    nodes,
			Topology: topo,
		},
	}
	opts := compiler.CompileOpts{
		Verbose: true,
	}
	c := compiler.NewCompilation(d, &opts)
	err := c.SetLinks(d)
	require.NotNil(t, err)
	require.Regexp(t, "node n99 not on any LAN", err.Error())
}

func TestLinksFailIfLandRefMissing(t *testing.T) {
	nodes := map[string]*doc.Component{
		"n0": {
			Address: zplString("fc00:1001::1"),
			Interfaces: map[string]*doc.Interface{
				"n0i0": {
					Netaddr: zplString("n0.spacelaser.net:5001"),
				},
			},
		},
		"n1": {
			Address: zplString("fc00:1001::2"),
			Interfaces: map[string]*doc.Interface{
				"n1i0": {
					Netaddr: zplString("n1.spacelaser.net:5001"),
				},
			},
		},
	}

	topo := &doc.Topology{
		LANs: map[string]*doc.LANDesc{
			"lan0": {
				Nodes: []doc.ZplString{
					zplString("n0"),
					zplString("n1"),
					zplString("n99"),
				},
			},
		},
	}
	d := &doc.Doc{
		Zpr: &doc.ZPR{
			Nodes:    nodes,
			Topology: topo,
		},
	}
	opts := compiler.CompileOpts{
		Verbose: true,
	}
	c := compiler.NewCompilation(d, &opts)
	err := c.SetLinks(d)
	require.NotNil(t, err)
	require.Regexp(t, "topology node reference unknown", err.Error())
}

func TestLinksFailIfDupeNodesAddresses(t *testing.T) {
	nodes := map[string]*doc.Component{
		"n0": {
			Address: zplString("fc00:1001::1"),
			Interfaces: map[string]*doc.Interface{
				"n0i0": &doc.Interface{
					Netaddr: zplString("n0.spacelaser.net:5001"),
				},
			},
		},
		"n1": {
			Address: zplString("fc00:1001::1"),
			Interfaces: map[string]*doc.Interface{
				"n1i0": &doc.Interface{
					Netaddr: zplString("n1.spacelaser.net:5001"),
				},
			},
		},
	}

	topo := &doc.Topology{
		LANs: map[string]*doc.LANDesc{
			"lan0": {
				Nodes: []doc.ZplString{zplString("n0"), zplString("n1")},
			},
		},
	}
	d := &doc.Doc{
		Zpr: &doc.ZPR{
			Nodes:    nodes,
			Topology: topo,
		},
	}
	opts := compiler.CompileOpts{
		Verbose: true,
	}
	c := compiler.NewCompilation(d, &opts)
	err := c.SetLinks(d)
	require.NotNil(t, err)
	require.Regexp(t, "node n1 address already in use by n0", err.Error())
}

func TestLinksFailIfDupePOEs(t *testing.T) {
	nodes := map[string]*doc.Component{
		"n0": {
			Address: zplString("fc00:1001::1"),
			Interfaces: map[string]*doc.Interface{
				"n0i0": &doc.Interface{
					Netaddr: zplString("n0.spacelaser.net:5001"),
				},
			},
		},
		"n1": {
			Address: zplString("fc00:1001::2"),
			Interfaces: map[string]*doc.Interface{
				"n1i0": &doc.Interface{
					Netaddr: zplString("n0.spacelaser.net:5001"),
				},
			},
		},
	}

	topo := &doc.Topology{
		LANs: map[string]*doc.LANDesc{
			"lan0": {
				Nodes: []doc.ZplString{zplString("n0"), zplString("n1")},
			},
		},
	}
	d := &doc.Doc{
		Zpr: &doc.ZPR{
			Nodes:    nodes,
			Topology: topo,
		},
	}
	opts := compiler.CompileOpts{
		Verbose: true,
	}
	c := compiler.NewCompilation(d, &opts)
	err := c.SetLinks(d)
	require.NotNil(t, err)
	require.Regexp(t, "node n1 POE address already in use by n0", err.Error())
}

func TestLinksFailIfNodeNotOnLAN(t *testing.T) {
	nodes := map[string]*doc.Component{
		"n0": {
			Address: zplString("fc00:1001::1"),
			Interfaces: map[string]*doc.Interface{
				"n0i0": &doc.Interface{
					Netaddr: zplString("n0.spacelaser.net:5001"),
				},
			},
		},
		"n1": {
			Address: zplString("fc00:1001::2"),
			Interfaces: map[string]*doc.Interface{
				"n1i0": &doc.Interface{
					Netaddr: zplString("n1.spacelaser.net:5001"),
				},
			},
		},
	}

	topo := &doc.Topology{
		LANs: map[string]*doc.LANDesc{
			"lan0": {
				Nodes: []doc.ZplString{zplString("n0")},
			},
		},
	}
	d := &doc.Doc{
		Zpr: &doc.ZPR{
			Nodes:    nodes,
			Topology: topo,
		},
	}
	opts := compiler.CompileOpts{
		Verbose: true,
	}
	c := compiler.NewCompilation(d, &opts)
	err := c.SetLinks(d)
	require.NotNil(t, err)
	require.Regexp(t, "node n1 not on any LAN", err.Error())
}

func TestBasicBridge(t *testing.T) {
	nodes := map[string]*doc.Component{
		"n0": {
			Address: zplString("fc00:1001::1"),
			Interfaces: map[string]*doc.Interface{
				"n0i0": &doc.Interface{
					Netaddr: zplString("n0.spacelaser.net:5001"),
				},
			},
		},
		"n1": {
			Address: zplString("fc00:1001::2"),
			Interfaces: map[string]*doc.Interface{
				"n1i0": &doc.Interface{
					Netaddr: zplString("n1.spacelaser.net:5001"),
				},
			},
		},
		"n2": {
			Address: zplString("fc00:1001::3"),
			Interfaces: map[string]*doc.Interface{
				"n1i0": &doc.Interface{
					Netaddr: zplString("n2.spacelaser.net:5001"),
				},
			},
		},
	}

	topo := &doc.Topology{
		LANs: map[string]*doc.LANDesc{
			"lan0": {
				Nodes: []doc.ZplString{zplString("n0"), zplString("n1")},
			},
			"lan1": {
				Nodes: []doc.ZplString{zplString("n2")},
			},
		},
		Bridges: []*doc.Bridge{
			{
				Nodes: []doc.ZplString{zplString("n2"), zplString("n0")},
				Cost:  doc.MustNewZplUnsigned(1),
			},
		},
	}
	d := &doc.Doc{
		Zpr: &doc.ZPR{
			Nodes:    nodes,
			Topology: topo,
		},
	}
	opts := compiler.CompileOpts{
		Verbose: true,
	}
	c := compiler.NewCompilation(d, &opts)
	err := c.SetLinks(d)
	require.Nil(t, err)
	require.Len(t, c.GetPolicy().GetLinks(), 3)
}

func TestBridgeSpansLANs(t *testing.T) {
	nodes := map[string]*doc.Component{
		"n0": {
			Address: zplString("fc00:1001::1"),
			Interfaces: map[string]*doc.Interface{
				"n0i0": {
					Netaddr: zplString("n0.spacelaser.net:5001"),
				},
			},
		},
		"n1": {
			Address: zplString("fc00:1001::2"),
			Interfaces: map[string]*doc.Interface{
				"n1i0": {
					Netaddr: zplString("n1.spacelaser.net:5001"),
				},
			},
		},
		"n2": {
			Address: zplString("fc00:1001::3"),
			Interfaces: map[string]*doc.Interface{
				"n1i0": {
					Netaddr: zplString("n2.spacelaser.net:5001"),
				},
			},
		},
	}

	topo := &doc.Topology{
		LANs: map[string]*doc.LANDesc{
			"lan0": {
				Nodes: []doc.ZplString{zplString("n0"), zplString("n1")},
			},
			"lan1": {
				Nodes: []doc.ZplString{zplString("n2")},
			},
		},
		Bridges: []*doc.Bridge{
			{
				Nodes: []doc.ZplString{zplString("n1"), zplString("n0")}, // oops! In same LAN!
				Cost:  doc.MustNewZplUnsigned(1),
			},
		},
	}
	d := &doc.Doc{
		Zpr: &doc.ZPR{
			Nodes:    nodes,
			Topology: topo,
		},
	}
	opts := compiler.CompileOpts{
		Verbose: true,
	}
	c := compiler.NewCompilation(d, &opts)
	err := c.SetLinks(d)
	require.NotNil(t, err)
	require.Regexp(t, `invalid bridge \[n1 n0\]`, err.Error())
}

func TestNoRedundantBridges(t *testing.T) {
	nodes := map[string]*doc.Component{
		"n0": {
			Address: zplString("fc00:1001::1"),
			Interfaces: map[string]*doc.Interface{
				"n0i0": {
					Netaddr: zplString("n0.spacelaser.net:5001"),
				},
			},
		},
		"n1": {
			Address: zplString("fc00:1001::2"),
			Interfaces: map[string]*doc.Interface{
				"n1i0": {
					Netaddr: zplString("n1.spacelaser.net:5001"),
				},
			},
		},
		"n2": {
			Address: zplString("fc00:1001::3"),
			Interfaces: map[string]*doc.Interface{
				"n1i0": {
					Netaddr: zplString("n2.spacelaser.net:5001"),
				},
			},
		},
	}

	topo := &doc.Topology{
		LANs: map[string]*doc.LANDesc{
			"lan0": {
				Nodes: []doc.ZplString{zplString("n0"), zplString("n1")},
			},
			"lan1": {
				Nodes: []doc.ZplString{zplString("n2")},
			},
		},
		Bridges: []*doc.Bridge{
			{
				Nodes: []doc.ZplString{zplString("n2"), zplString("n0")},
				Cost:  doc.MustNewZplUnsigned(1),
			},
			{
				Nodes: []doc.ZplString{zplString("n0"), zplString("n2")},
				Cost:  doc.MustNewZplUnsigned(1),
			},
		},
	}
	d := &doc.Doc{
		Zpr: &doc.ZPR{
			Nodes:    nodes,
			Topology: topo,
		},
	}
	opts := compiler.CompileOpts{
		Verbose: true,
	}
	c := compiler.NewCompilation(d, &opts)
	err := c.SetLinks(d)
	require.Nil(t, err)
	require.Len(t, c.GetPolicy().GetLinks(), 3) // Still just three links
}
