package pp_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vsx/zpl/pp"
	yt "zpr.org/vsx/zpl/pp/yamltree"
)

// Returns true if a path corresponding to path expression pathExpr exists in
// the tree rooted by root. Panics if pathExpr is invalid.
func pathExists(root yt.Node, pathExpr string) bool {
	return len(yt.MatchingPaths(root, yt.NewPathPatternOk(pathExpr))) != 0
}

func TestBasicDefine(t *testing.T) {
	polyml := `
zpl_format: 2
network:
  topology:
    nodes:
communications:
  systems:
    system001:
      defines:
        foo: haha
        fee:
          scope:
            - tcp: 80
      services:
        service001:
          desc: $foo
          $fee:
          policies: ~
`
	root0, err := yt.ReadYamlFromString(polyml, "")
	require.NoError(t, err)

	root1, err := pp.ProcessDefines(root0)
	require.NoError(t, err)

	require.True(t, pathExists(root1, "communications.systems.system001.services.service001.desc$haha"))
	require.True(t, pathExists(root1, "communications.systems.system001.services.service001.scope[0].tcp$80"))
	require.False(t, pathExists(root1, "communications.systems.system001.defines"))
}

func TestBasicDefineWithHierarchy(t *testing.T) {
	polyml := `
zpl_format: 2
network:
  topology:
    nodes:
communications:
  hierarchy:
    - regions
    - divisions
  regions:
    region001:
      defines:
        foo: haha
        fee:
          scope:
            - tcp: 80
      services:
        service001:
          desc: $foo
          $fee:
          policies: ~
`
	root0, err := yt.ReadYamlFromString(polyml, "")
	require.NoError(t, err)

	root1, err := pp.ProcessDefines(root0)
	require.NoError(t, err)

	require.True(t, pathExists(root1, "communications.regions.region001.services.service001.desc$haha"))
	require.True(t, pathExists(root1, "communications.regions.region001.services.service001.scope[0].tcp$80"))
	require.False(t, pathExists(root1, "@@.defines"))
}

func TestProviderAttrs(t *testing.T) {
	polyml := `
zpl_format: 2
network:
  topology:
    nodes:
communications:
  systems:
    system001:
      defines:
        foo: haha
        fee:
          scope:
            - tcp: 80
        monitor.attrs:
          - [foo, fee]
          - [ha, ho]
      services:
        service001:
          desc: $foo
          provider:
            $monitor.attrs
          $fee:
          policies: ~
`
	root0, err := yt.ReadYamlFromString(polyml, "")
	require.NoError(t, err)

	root1, err := pp.ProcessDefines(root0)
	require.NoError(t, err)

	require.True(t, pathExists(root1, "communications.systems.system001.services.service001.desc$haha"))
	require.True(t, pathExists(root1, "communications.systems.system001.services.service001.provider[0][0]$foo"))
	require.True(t, pathExists(root1, "communications.systems.system001.services.service001.provider[0][1]$fee"))
	require.True(t, pathExists(root1, "communications.systems.system001.services.service001.provider[1][0]$ha"))
	require.True(t, pathExists(root1, "communications.systems.system001.services.service001.provider[1][1]$ho"))
}

func TestHostExpansionInNodes(t *testing.T) {
	polyml := `
zpl_format: 2
network:
  topology:
    nodes:
      n0:
        address: fc00:2000::1
communications:
  systems:
    system001:
      defines:
        foo: haha
        fee:
          scope:
            - tcp: 80
      services:
        service001:
          desc: $foo
          $fee:
          address: "fc00:2000::2"
          policies: ~
`
	root0, err := yt.ReadYamlFromString(polyml, "")
	require.NoError(t, err)

	root1, err := pp.ProcessDefines(root0)
	require.NoError(t, err)

	require.True(t, pathExists(root1, "network.topology.nodes.n0.address$"))
	require.True(t, pathExists(root1, "network.topology.nodes.n0.address$\"fc00:2000::1\""))
}

func TestHostExpansionInAttrs(t *testing.T) {
	polyml := `
zpl_format: 2
network:
  topology:
    nodes:
      n0:
        address: fc00:2000::3
communications:
  systems:
    system001:
      defines:
        foo: haha
        fee:
          scope:
            - tcp: 80
      services:
        service001:
          desc: $foo
          provider:
            - [zpr.addr, "fc00:2000::1"]
          $fee:
          address: fc00:2000::2
          policies: ~
`

	root0, err := yt.ReadYamlFromString(polyml, "")
	require.NoError(t, err)

	root1, err := pp.ProcessDefines(root0)
	require.NoError(t, err)

	require.True(t, pathExists(root1, "communications.systems.system001.services.service001.provider[0][1]$\"fc00:2000::1\""))
}

func TestKeyContextDefines(t *testing.T) {
	polyml := `
        zpl_format: 2
        communications:
          systems:
            system0:
              defines:
                a:
                  x: 1
                  y: 2
                b:
                  - 1
                  - 2
                c:
                  $a
                d:
                  $b
              services:
                service0:
                  p:
                    $a
                  q:
                    $b
                  r:
                    foo: 10
                    $c:
                    bar: 20
                  s:
                    $d:
        network:
          topology:
            nodes:
          addresses:
            hosts:
`
	root0, err := yt.ReadYamlFromString(polyml, "")
	require.NoError(t, err)

	root1, err := pp.ProcessDefines(root0)
	require.NoError(t, err)

	require.True(t, pathExists(root1, "communications.systems.system0.services.service0.p.x$1"))
	require.True(t, pathExists(root1, "communications.systems.system0.services.service0.p.y$2"))
	require.True(t, pathExists(root1, "communications.systems.system0.services.service0.q[0]$1"))
	require.True(t, pathExists(root1, "communications.systems.system0.services.service0.q[1]$2"))
	require.True(t, pathExists(root1, "communications.systems.system0.services.service0.r.foo$10"))
	require.True(t, pathExists(root1, "communications.systems.system0.services.service0.r.bar$20"))
	require.True(t, pathExists(root1, "communications.systems.system0.services.service0.r.x$1"))
	require.True(t, pathExists(root1, "communications.systems.system0.services.service0.r.y$2"))
	require.True(t, pathExists(root1, "communications.systems.system0.services.service0.s[0]$1"))
	require.True(t, pathExists(root1, "communications.systems.system0.services.service0.s[1]$2"))
}

func TestDefineScoping(t *testing.T) {
	polyml := `
        zpl_format: 2
        communications:
          hierarchy:
            - divisions
            - regions
            - branches
          divisions:
            division0:
              defines:
                a: one
                b:
                  x: foo
                  y: bar
                c: two
                d:
                  x: $a
                  y: foo
                e: $c
                f:
                  $d
                g:
                  - p: $a
                  - q: $c
              regions:
                region0:
                  branches:
                    branch0:
                      stuff:
                        more:
                          t: null
                          u: $a
                          v: $b
                          w: $e
                          $b:
                region1:
                  defines:
                    a: $c
                    b: $d
                    z: zzz
                  branches:
                    branch0:
                      stuff:
                        more:
                          u: $a
                          v: $b
                          w: $z
                    branch1:
                      stuff:
                        more:
                          u: $c
                          v: $d
                          w: $z
            division1:
              items:
                - defines:
                    one: 1
                    two: 2
                - $one
                - $two
                - stuff:
                    defines:
                      one: $two
                    more:
                      u: $one
                      v: $two
        network:
          topology:
            nodes:
          addresses:
            hosts:
    `

	root0, err := yt.ReadYamlFromString(polyml, "")
	require.NoError(t, err)

	root1, err := pp.ProcessDefines(root0)
	require.NoError(t, err)

	require.True(t, pathExists(root1, "communications.divisions.division0.regions.region0.branches.branch0.stuff.more.u$one"))
	require.True(t, pathExists(root1, "communications.divisions.division0.regions.region0.branches.branch0.stuff.more.v.x$foo"))
	require.True(t, pathExists(root1, "communications.divisions.division0.regions.region0.branches.branch0.stuff.more.v.y$bar"))
	require.True(t, pathExists(root1, "communications.divisions.division0.regions.region0.branches.branch0.stuff.more.w$two"))
	require.True(t, pathExists(root1, "communications.divisions.division0.regions.region0.branches.branch0.stuff.more.x$foo"))
	require.True(t, pathExists(root1, "communications.divisions.division0.regions.region0.branches.branch0.stuff.more.y$bar"))
	require.True(t, pathExists(root1, "communications.divisions.division0.regions.region1.branches.branch0.stuff.more.u$two"))
	require.True(t, pathExists(root1, "communications.divisions.division0.regions.region1.branches.branch0.stuff.more.v.x$one"))
	require.True(t, pathExists(root1, "communications.divisions.division0.regions.region1.branches.branch0.stuff.more.v.y$foo"))
	require.True(t, pathExists(root1, "communications.divisions.division0.regions.region1.branches.branch0.stuff.more.w$zzz"))
	require.True(t, pathExists(root1, "communications.divisions.division0.regions.region1.branches.branch1.stuff.more.u$two"))
	require.True(t, pathExists(root1, "communications.divisions.division0.regions.region1.branches.branch1.stuff.more.v.x$one"))
	require.True(t, pathExists(root1, "communications.divisions.division0.regions.region1.branches.branch1.stuff.more.v.y$foo"))
	require.True(t, pathExists(root1, "communications.divisions.division0.regions.region1.branches.branch1.stuff.more.w$zzz"))
	require.True(t, pathExists(root1, "communications.divisions.division1.items[0]$1")) // [0] because "defines" removed
	require.True(t, pathExists(root1, "communications.divisions.division1.items[1]$2"))
	require.True(t, pathExists(root1, "communications.divisions.division1.items[2].stuff.more.u$2"))
	require.True(t, pathExists(root1, "communications.divisions.division1.items[2].stuff.more.v$2"))
	require.False(t, pathExists(root1, "@@.defines"))

	lastNode := func(path []yt.Node) yt.Node {
		return path[len(path)-1]
	}

	tpath := yt.MatchingPaths(root1, yt.NewPathPatternOk("communications.divisions.division0.regions.region0.branches.branch0.stuff.more.t"))[0]
	require.Equal(t, 0, len(lastNode(tpath).Referrers()))

	upath := yt.MatchingPaths(root1, yt.NewPathPatternOk("communications.divisions.division0.regions.region0.branches.branch0.stuff.more.u"))[0]
	require.Equal(t, 1, len(lastNode(upath).Referrers()))

	wpath := yt.MatchingPaths(root1, yt.NewPathPatternOk("communications.divisions.division0.regions.region0.branches.branch0.stuff.more.w"))[0]
	require.Equal(t, 2, len(lastNode(wpath).Referrers()))

	xpath := yt.MatchingPaths(root1, yt.NewPathPatternOk("communications.divisions.division0.regions.region0.branches.branch0.stuff.more.x"))[0]
	require.Equal(t, 1, len(lastNode(xpath).Referrers()))
}

func TestLookupFailure(t *testing.T) {
	polyml1 := `
        zpl_format: 2
        communications:
          systems:
            system0:
              foo: $x
        network:
          topology:
            nodes:
          addresses:
            hosts:
    `

	polyml2 := `
        zpl_format: 2
        communications:
          systems:
            system0:
              defines:
                  foo: $x
        network:
          topology:
            nodes:
          addresses:
            hosts:
    `

	for i, yaml := range []string{polyml1, polyml2} {
		root0, err := yt.ReadYamlFromString(yaml, "")
		require.NoError(t, err, "i=%d", i)

		_, err = pp.ProcessDefines(root0)
		require.Error(t, err, "i=%d", i)
	}
}

func TestCyclicDependency(t *testing.T) {
	polyml1 := `
        zpl_format: 2
        communications:
          systems:
            system0:
              defines:
                  foo: $foo
        network:
          topology:
            nodes:
          addresses:
            hosts:
    `

	polyml2 := `
        zpl_format: 2
        communications:
          systems:
            system0:
              defines:
                  foo: $bar
                  bar: $foo
        network:
          topology:
            nodes:
          addresses:
            hosts:
    `

	polyml3 := `
        zpl_format: 2
        communications:
          systems:
            system0:
              defines:
                  foo:
                      a:
                          b: $bar
                  bar:
                      x:
                          y: $qux
                  qux: $foo
        network:
          topology:
            nodes:
          addresses:
            hosts:
    `

	for i, yaml := range []string{polyml1, polyml2, polyml3} {
		root0, err := yt.ReadYamlFromString(yaml, "")
		require.NoError(t, err, "i=%d", i)

		_, err = pp.ProcessDefines(root0)
		require.Error(t, err, "i=%d", i)
	}
}

func TestMultipleSequencesInKeyContext(t *testing.T) {
	polyml := `
        zpl_format: 2
        communications:
          defines:
            seq1:
              - a
            seq2:
              - c
              - d
            seq3:
              - b
          systems:
            system0:
              stuff:
                $seq1:
                $seq3:
                $seq2:
        network:
          topology:
            nodes:
          addresses:
            hosts:
    `

	root0, err := yt.ReadYamlFromString(polyml, "")
	require.NoError(t, err)

	root1, err := pp.ProcessDefines(root0)
	require.NoError(t, err)

	require.Equal(t, 4, len(yt.MatchingPaths(root1, yt.NewPathPatternOk("communications.systems.system0.stuff[*]$"))))
	require.True(t, pathExists(root1, "communications.systems.system0.stuff[0]$a"))
	require.True(t, pathExists(root1, "communications.systems.system0.stuff[1]$b"))
	require.True(t, pathExists(root1, "communications.systems.system0.stuff[2]$c"))
	require.True(t, pathExists(root1, "communications.systems.system0.stuff[3]$d"))

}

func TestSortSymbolDependencies(t *testing.T) {
	d0 := []pp.SymbolDependency{}
	s0, err := pp.SortSymbolDependencies(d0)
	require.NoError(t, err)
	require.Equal(t, []string{}, s0)

	d1 := []pp.SymbolDependency{
		pp.NewSymbolDependency("a", "b"),
	}
	s1, err := pp.SortSymbolDependencies(d1)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b"}, s1)

	d2 := []pp.SymbolDependency{
		pp.NewSymbolDependency("a", "b"),
		pp.NewSymbolDependency("b", "c"),
	}
	s2, err := pp.SortSymbolDependencies(d2)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "c"}, s2)

	d3 := []pp.SymbolDependency{
		pp.NewSymbolDependency("a", "b"),
		pp.NewSymbolDependency("a", "c"),
		pp.NewSymbolDependency("b", "c"),
	}
	s3, err := pp.SortSymbolDependencies(d3)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "c"}, s3)

	d4 := []pp.SymbolDependency{
		pp.NewSymbolDependency("b", "c"),
		pp.NewSymbolDependency("a", "c"),
		pp.NewSymbolDependency("a", "b"),
	}
	s4, err := pp.SortSymbolDependencies(d4)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "c"}, s4)

	index := func(ss []string, s string) int {
		for i, x := range ss {
			if x == s {
				return i
			}
		}
		return -1
	}

	before := func(ss []string, s1, s2 string) bool {
		return index(ss, s1) < index(ss, s2)
	}

	d5 := []pp.SymbolDependency{
		pp.NewSymbolDependency("a", "b"),
		pp.NewSymbolDependency("a", "c"),
		pp.NewSymbolDependency("b", "d"),
		pp.NewSymbolDependency("c", "d"),
	}
	s5, err := pp.SortSymbolDependencies(d5)
	require.NoError(t, err)
	require.Equal(t, 4, len(s5))
	require.True(t, before(s5, "a", "b"))
	require.True(t, before(s5, "a", "c"))
	require.True(t, before(s5, "b", "d"))
	require.True(t, before(s5, "c", "d"))

	d6 := []pp.SymbolDependency{
		pp.NewSymbolDependency("c", "b"),
		pp.NewSymbolDependency("d", "b"),
		pp.NewSymbolDependency("b", "a"),
		pp.NewSymbolDependency("g", "e"),
		pp.NewSymbolDependency("i", "h"),
		pp.NewSymbolDependency("i", "g"),
		pp.NewSymbolDependency("i", "f"),
	}
	s6, err := pp.SortSymbolDependencies(d6)
	require.NoError(t, err)
	require.Equal(t, 9, len(s6))
	require.True(t, before(s6, "c", "b"))
	require.True(t, before(s6, "d", "b"))
	require.True(t, before(s6, "b", "a"))
	require.True(t, before(s6, "i", "f"))
	require.True(t, before(s6, "i", "g"))
	require.True(t, before(s6, "i", "h"))
	require.True(t, before(s6, "g", "e"))

	d7 := []pp.SymbolDependency{
		pp.NewSymbolDependency("a", "b"),
		pp.NewSymbolDependency("a", "c"),
		pp.NewSymbolDependency("b", "c"),
		pp.NewSymbolDependency("a", "b"),
		pp.NewSymbolDependency("a", "c"),
		pp.NewSymbolDependency("b", "c"),
	}
	s7, err := pp.SortSymbolDependencies(d7)
	require.NoError(t, err)
	require.Equal(t, []string{"a", "b", "c"}, s7)

	d8 := []pp.SymbolDependency{
		pp.NewSymbolDependency("a", "b"),
		pp.NewSymbolDependency("b", "a"),
	}
	_, err = pp.SortSymbolDependencies(d8)
	require.Error(t, err)

	d9 := []pp.SymbolDependency{
		pp.NewSymbolDependency("e", "b"),
		pp.NewSymbolDependency("a", "b"),
		pp.NewSymbolDependency("b", "c"),
		pp.NewSymbolDependency("c", "d"),
		pp.NewSymbolDependency("c", "e"),
	}
	_, err = pp.SortSymbolDependencies(d9)
	require.Error(t, err)
}
