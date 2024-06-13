package yamltree_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	y "zpr.org/vsx/zpl/pp/yamltree"
)

func TestReadEmptyDocument(t *testing.T) {
	root, err := y.ReadYaml(bytes.NewReader([]byte{}), "testfile")
	require.Error(t, err)
	require.Nil(t, root)
}

func TestReadSingleScalarNode(t *testing.T) {
	root, err := y.ReadYaml(bytes.NewReader([]byte("foo")), "testfile")
	require.NoError(t, err)
	require.Equal(t, y.ScalarKind, root.Kind())
	require.IsType(t, "", root.Value())
	require.Equal(t, "foo", root.Value())
	require.Equal(t, y.NodeSource{"testfile", 1, 1}, root.Source())
}

func TestReadSingleSequence(t *testing.T) {
	root, err := y.ReadYaml(bytes.NewReader([]byte("- foo\n- bar")), "testfile")
	require.NoError(t, err)
	require.Equal(t, y.SequenceKind, root.Kind())
	require.IsType(t, []y.Node{}, root.Value())

	kids := root.Value().([]y.Node)
	require.Equal(t, len(kids), 2)
	require.Equal(t, y.ScalarKind, kids[0].Kind())
	require.Equal(t, y.NodeSource{"testfile", 1, 3}, kids[0].Source())
	require.Equal(t, "foo", kids[0].Value())
	require.Equal(t, y.NodeSource{"testfile", 2, 3}, kids[1].Source())
}

func TestReadSingleMapping(t *testing.T) {
	root, err := y.ReadYaml(bytes.NewReader([]byte("a: foo\nb: bar")), "testfile")
	require.NoError(t, err)
	require.Equal(t, y.MappingKind, root.Kind())
	require.IsType(t, map[string]y.Node{}, root.Value())

	kidmap := root.Value().(map[string]y.Node)
	require.Equal(t, len(kidmap), 2)
	require.Equal(t, y.ScalarKind, kidmap["a"].Kind())
	require.Equal(t, "foo", kidmap["a"].Value())
	require.Equal(t, y.ScalarKind, kidmap["b"].Kind())
	require.Equal(t, "bar", kidmap["b"].Value())
}

func TestReadNontrivialDocument(t *testing.T) {
	yaml := `---
        a: one
        b: two # comment
        c:
            x:
                - 1
                - 2
                - 3
            y:
                aa: !!float 1
                bb: [2, 3]
                cc: xyz
        d:
        last one: the end`

	root, err := y.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	require.Equal(t, y.MappingKind, root.Kind())

	m, _ := root.Value().(map[string]y.Node)
	require.Equal(t, 5, len(m))
	require.Equal(t, y.ScalarKind, m["a"].Kind())
	require.Equal(t, "one", m["a"].Value())
	require.Equal(t, y.ScalarKind, m["b"].Kind())
	require.Equal(t, "two", m["b"].Value())
	require.Equal(t, y.MappingKind, m["c"].Kind())

	mm, _ := m["c"].Value().(map[string]y.Node)
	require.Equal(t, 2, len(mm))
	require.Equal(t, y.SequenceKind, mm["x"].Kind())

	s, _ := mm["x"].Value().([]y.Node)
	require.Equal(t, 3, len(s))
	require.Equal(t, y.ScalarKind, s[0].Kind())
	require.Equal(t, "1", s[0].Value())
	require.Equal(t, y.ScalarKind, s[1].Kind())
	require.Equal(t, "2", s[1].Value())
	require.Equal(t, y.ScalarKind, s[2].Kind())
	require.Equal(t, "3", s[2].Value())
	require.Equal(t, y.MappingKind, mm["y"].Kind())

	mmm, _ := mm["y"].Value().(map[string]y.Node)
	require.Equal(t, 3, len(mmm))
	require.Equal(t, y.ScalarKind, mmm["aa"].Kind())
	require.Equal(t, "1", mmm["aa"].Value())
	require.Equal(t, y.SequenceKind, mmm["bb"].Kind())

	ss, _ := mmm["bb"].Value().([]y.Node)
	require.Equal(t, 2, len(ss))
	require.Equal(t, y.ScalarKind, ss[0].Kind())
	require.Equal(t, "2", ss[0].Value())
	require.Equal(t, y.ScalarKind, ss[1].Kind())
	require.Equal(t, "3", ss[1].Value())
	require.Equal(t, y.ScalarKind, m["d"].Kind())
	require.Equal(t, "", m["d"].Value())
	require.Equal(t, y.ScalarKind, m["last one"].Kind())
	require.Equal(t, "the end", m["last one"].Value())

	require.Equal(t, y.NodeSource{"testfile", 10, 21}, mmm["aa"].Source())
	require.Equal(t, y.NodeSource{"testfile", 14, 19}, m["last one"].Source())
}

func TestTagAndDecodeValue(t *testing.T) {
	yaml := `---
        a: ~
        b: true
        c: 1234
        d: 1234.5
        e: 1234x
        f:
            x: 0
            y: 1
        g:
            - 0
            - 1`

	root, err := y.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	require.Equal(t, y.MappingKind, root.Kind())

	m, _ := root.Value().(map[string]y.Node)
	require.NoError(t, err)

	require.Equal(t, "!!null", m["a"].Tag())
	a, err := m["a"].DecodedScalarValue()
	require.Exactly(t, nil, a)

	require.Equal(t, "!!bool", m["b"].Tag())
	b, err := m["b"].DecodedScalarValue()
	require.Exactly(t, true, b)

	require.Equal(t, "!!int", m["c"].Tag())
	c, err := m["c"].DecodedScalarValue()
	require.Exactly(t, int64(1234), c)

	require.Equal(t, "!!float", m["d"].Tag())
	d, err := m["d"].DecodedScalarValue()
	require.Exactly(t, float64(1234.5), d)

	require.Equal(t, "!!str", m["e"].Tag())
	e, err := m["e"].DecodedScalarValue()
	require.Exactly(t, "1234x", e)

	require.Equal(t, "!!map", m["f"].Tag())
	_, err = m["f"].DecodedScalarValue()
	require.Error(t, err)

	require.Equal(t, "!!seq", m["g"].Tag())
	_, err = m["g"].DecodedScalarValue()
	require.Error(t, err)
}

func TestReadSet(t *testing.T) {
	yaml := `---
        ? one
        ? two`

	root, err := y.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	require.Equal(t, y.MappingKind, root.Kind())

	m, _ := root.Value().(map[string]y.Node)
	require.Equal(t, 2, len(m))
	require.Equal(t, y.ScalarKind, m["one"].Kind())
	require.Equal(t, "", m["one"].Value())
	require.Equal(t, y.ScalarKind, m["two"].Kind())
	require.Equal(t, "", m["one"].Value())
}

func TestReadAnchorsAndAliases(t *testing.T) {
	yaml := `
        one: &ONE 1
        two: &TWO 2
        two2: *TWO
        a: &A
            x: *ONE
            y: *TWO
        b: *A
        c: &C [*ONE, *TWO]
        d:
            z: *C`

	root, err := y.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	require.Equal(t, y.MappingKind, root.Kind())

	m := root.Value().(map[string]y.Node)
	require.Equal(t, 7, len(m))
	require.Equal(t, "1", m["one"].Value())
	require.Equal(t, "2", m["two"].Value())
	require.Equal(t, "2", m["two2"].Value())
	require.Equal(t, y.MappingKind, m["a"].Kind())

	ma := m["a"].Value().(map[string]y.Node)
	require.Equal(t, 2, len(ma))
	require.Equal(t, "1", ma["x"].Value())
	require.Equal(t, "2", ma["y"].Value())
	require.Equal(t, y.MappingKind, m["b"].Kind())

	mb := m["a"].Value().(map[string]y.Node)
	require.Equal(t, 2, len(mb))
	require.Equal(t, "1", mb["x"].Value())
	require.Equal(t, "2", mb["y"].Value())
	require.Equal(t, y.SequenceKind, m["c"].Kind())

	sc := m["c"].Value().([]y.Node)
	require.Equal(t, 2, len(sc))
	require.Equal(t, "1", sc[0].Value())
	require.Equal(t, "2", sc[1].Value())
	require.Equal(t, y.MappingKind, m["d"].Kind())

	md := m["d"].Value().(map[string]y.Node)
	require.Equal(t, 1, len(md))
	require.Equal(t, y.SequenceKind, md["z"].Kind())

	sz := md["z"].Value().([]y.Node)
	require.Equal(t, 2, len(sz))
	require.Equal(t, "1", sz[0].Value())
	require.Equal(t, "2", sz[1].Value())

	require.Equal(t, y.NodeSource{"testfile", 2, 14}, m["one"].Source())
	require.Equal(t, y.NodeSource{"testfile", 2, 14}, sc[0].Source())
}

func TestReadCircularAlias(t *testing.T) {
	yaml := `
        a: &A
            b:
                c: *A`
	_, err := y.ReadYamlFromString(yaml, "testfile")
	require.Error(t, err)
}

func TestReadMergeKey(t *testing.T) {
	yaml := `
        - &A
            x: 1
            y: 2
        -
            <<: *A`
	_, err := y.ReadYamlFromString(yaml, "testfile")
	require.Error(t, err)
}

func TestReadEmptyFilename(t *testing.T) {
	root, err := y.ReadYamlFromString("- foo\n- bar", "")
	require.NoError(t, err)
	require.Equal(t, y.NodeSource{"", 2, 3}, root.Value().([]y.Node)[1].Source())
}

func TestWriteYaml(t *testing.T) {
	yaml1 := `---
        a: one
        b: two # comment
        c:
            x: &X
                - 1
                - 2
                - 3
            y:
                aa: !!float 1
                bb: [2, 3, {xx: 4, yy: 5}]
                cc: xyz
        d: *X`

	root1, err := y.ReadYamlFromString(yaml1, "testfile")
	require.NoError(t, err)

	yaml2 := y.WriteYamlToString(root1)

	root2, err := y.ReadYamlFromString(yaml2, "testfile")
	require.NoError(t, err)

	a1 := root1.Value().(map[string]y.Node)["a"].Value()
	a2 := root2.Value().(map[string]y.Node)["a"].Value()
	require.Equal(t, "one", a1)
	require.Equal(t, "one", a2)

	c1 := root1.Value().(map[string]y.Node)["c"].Value().(map[string]y.Node)["x"].Value().([]y.Node)[0].Value()
	c2 := root2.Value().(map[string]y.Node)["c"].Value().(map[string]y.Node)["x"].Value().([]y.Node)[0].Value()
	require.Equal(t, "1", c1)
	require.Equal(t, "1", c2)

	d1 := root1.Value().(map[string]y.Node)["d"].Value().([]y.Node)[0].Value()
	d2 := root2.Value().(map[string]y.Node)["d"].Value().([]y.Node)[0].Value()
	require.Equal(t, "1", d1)
	require.Equal(t, "1", d2)
}

func TestWriteYamlSourceOrder(t *testing.T) {
	yaml1 := `---
        z: one
        y: two # comment
        x:
            has whitespace: &Q q
            "has other \"weird\" stuff ∞":
                cc: !!float 1
                bb: [2, 3, {xx: 4, yy: 5}]
                aa: xyz
        w: *Q`

	root1, err := y.ReadYamlFromString(yaml1, "testfile")
	require.NoError(t, err)

	yaml2 := y.WriteYamlToString(root1)

	root2, err := y.ReadYamlFromString(yaml2, "testfile")
	require.NoError(t, err)

	z1 := root1.Value().(map[string]y.Node)["z"].Value()
	z2 := root2.Value().(map[string]y.Node)["z"].Value()
	require.Equal(t, "one", z1)
	require.Equal(t, "one", z2)

	h1 := root1.Value().(map[string]y.Node)["x"].Value().(map[string]y.Node)["has whitespace"].Value()
	h2 := root2.Value().(map[string]y.Node)["x"].Value().(map[string]y.Node)["has whitespace"].Value()
	require.Equal(t, "q", h1)
	require.Equal(t, "q", h2)

	o1 := root1.Value().(map[string]y.Node)["x"].Value().(map[string]y.Node)[`has other "weird" stuff ∞`].Value().(map[string]y.Node)["bb"].Value().([]y.Node)[1].Value()
	o2 := root2.Value().(map[string]y.Node)["x"].Value().(map[string]y.Node)[`has other "weird" stuff ∞`].Value().(map[string]y.Node)["bb"].Value().([]y.Node)[1].Value()
	require.Equal(t, "3", o1)
	require.Equal(t, "3", o2)

	w1 := root1.Value().(map[string]y.Node)["w"].Value()
	w2 := root2.Value().(map[string]y.Node)["w"].Value()
	require.Equal(t, "q", w1)
	require.Equal(t, "q", w2)
}

func TestPathFrom(t *testing.T) {
	yaml1 := `---
        this: one
        that:
            -
                a: 1
                b: 2
            -
                c: 3
                d: 4
        other: end`

	yaml2 := `---
        x: something else`

	root1, _ := y.ReadYamlFromString(yaml1, "file1")
	root2, _ := y.ReadYamlFromString(yaml2, "file1")

	this := root1.Value().(map[string]y.Node)["this"]
	that := root1.Value().(map[string]y.Node)["that"]
	other := root1.Value().(map[string]y.Node)["other"]
	that0 := that.Value().([]y.Node)[0]
	that1 := that.Value().([]y.Node)[1]
	a := that0.Value().(map[string]y.Node)["a"]
	d := that1.Value().(map[string]y.Node)["d"]

	x := root2.Value().(map[string]y.Node)["x"]

	require.Equal(t, []y.Node{root1}, y.PathFrom(root1, root1))
	require.Equal(t, []y.Node{root1, this}, y.PathFrom(root1, this))
	require.Equal(t, []y.Node{root1, that}, y.PathFrom(root1, that))
	require.Equal(t, []y.Node{root1, that, that0}, y.PathFrom(root1, that0))
	require.Equal(t, []y.Node{root1, that, that0, a}, y.PathFrom(root1, a))
	require.Equal(t, []y.Node{root1, that, that1, d}, y.PathFrom(root1, d))
	require.Equal(t, []y.Node{root1, other}, y.PathFrom(root1, other))
	require.Equal(t, []y.Node{that1, d}, y.PathFrom(that1, d))
	require.Nil(t, y.PathFrom(root1, x))
}

func TestReplaceNodeValue(t *testing.T) {
	yaml1 := `{a: 0}`
	yaml2 := `{b0: 1, b1: [1, 2], b2: {x: 1, y: 2}}`

	root1, _ := y.ReadYamlFromString(yaml1, "file1")
	root2, _ := y.ReadYamlFromString(yaml2, "file2")

	a := root1.Value().(map[string]y.Node)["a"]
	b0 := root2.Value().(map[string]y.Node)["b0"]
	b1 := root2.Value().(map[string]y.Node)["b1"]
	b2 := root2.Value().(map[string]y.Node)["b2"]

	a0, err := y.ReplaceNodeValue(a, b0.Value())
	require.NoError(t, err)
	require.Equal(t, y.ScalarKind, a0.Kind())
	require.Equal(t, a.Source(), a0.Source())
	require.Equal(t, b0.Value(), a0.Value())
	require.Equal(t, "!!str", a0.Tag())

	a1, err := y.ReplaceNodeValue(a, b1.Value())
	require.NoError(t, err)
	require.Equal(t, y.SequenceKind, a1.Kind())
	require.Equal(t, a.Source(), a1.Source())
	require.Equal(t, b1.Value(), a1.Value())
	require.Equal(t, "!!seq", a1.Tag())

	a2, err := y.ReplaceNodeValue(a, b2.Value())
	require.NoError(t, err)
	require.Equal(t, y.MappingKind, a2.Kind())
	require.Equal(t, a.Source(), a2.Source())
	require.Equal(t, b2.Value(), a2.Value())
	require.Equal(t, "!!map", a2.Tag())

	_, err = y.ReplaceNodeValue(a, []int{})
	require.Error(t, err)

	n, _ := y.ReadYamlFromString("dummy", "file3")

	n0, err := y.ReplaceNodeValue(n, nil)
	require.NoError(t, err)
	require.Equal(t, y.ScalarKind, n0.Kind())
	require.Equal(t, n.Source(), n0.Source())
	require.Equal(t, "", n0.Value())
	require.Equal(t, "!!null", n0.Tag())

	n1, err := y.ReplaceNodeValue(n, true)
	require.NoError(t, err)
	require.Equal(t, y.ScalarKind, n1.Kind())
	require.Equal(t, n.Source(), n1.Source())
	require.Equal(t, "true", n1.Value())
	require.Equal(t, "!!bool", n1.Tag())

	n2, err := y.ReplaceNodeValue(n, 1)
	require.NoError(t, err)
	require.Equal(t, y.ScalarKind, n2.Kind())
	require.Equal(t, n.Source(), n2.Source())
	require.Equal(t, "1", n2.Value())
	require.Equal(t, "!!int", n2.Tag())

	n3, err := y.ReplaceNodeValue(n, int8(1))
	require.NoError(t, err)
	require.Equal(t, y.ScalarKind, n3.Kind())
	require.Equal(t, n.Source(), n3.Source())
	require.Equal(t, "1", n3.Value())
	require.Equal(t, "!!int", n3.Tag())

	n4, err := y.ReplaceNodeValue(n, uint(1))
	require.NoError(t, err)
	require.Equal(t, y.ScalarKind, n4.Kind())
	require.Equal(t, n.Source(), n4.Source())
	require.Equal(t, "1", n4.Value())
	require.Equal(t, "!!int", n4.Tag())

	n5, err := y.ReplaceNodeValue(n, uint64(1))
	require.NoError(t, err)
	require.Equal(t, y.ScalarKind, n5.Kind())
	require.Equal(t, n.Source(), n5.Source())
	require.Equal(t, "1", n5.Value())
	require.Equal(t, "!!int", n5.Tag())

	n6, err := y.ReplaceNodeValue(n, float64(1.5))
	require.NoError(t, err)
	require.Equal(t, y.ScalarKind, n6.Kind())
	require.Equal(t, n.Source(), n6.Source())
	require.Equal(t, "1.5", n6.Value())
	require.Equal(t, "!!float", n6.Tag())
}

func TestReplaceNode(t *testing.T) {
	yaml1 := `---
        this: one
        that:
            -
                a: 1
                b: 2
            -
                c: 3
                d: 4
        other: end`

	yaml2 := `---
        e: another one
        f:
            - foo
            - bar`

	root1, _ := y.ReadYamlFromString(yaml1, "file1")
	this := root1.Value().(map[string]y.Node)["this"]
	that := root1.Value().(map[string]y.Node)["that"]
	that0 := that.Value().([]y.Node)[0]
	that1 := that.Value().([]y.Node)[1]

	root2, _ := y.ReadYamlFromString(yaml2, "file2")
	e := root2.Value().(map[string]y.Node)["e"]
	f := root2.Value().(map[string]y.Node)["f"]

	root10, err := y.ReplaceNode(root1, root1, root2, nil)
	require.NoError(t, err)
	root10map := root10.Value().(map[string]y.Node)
	require.Equal(t, 2, len(root10map))
	require.Equal(t, "another one", root10map["e"].Value())
	require.Equal(t, y.SequenceKind, root10map["f"].Kind())
	f10seq := root10map["f"].Value().([]y.Node)
	require.Equal(t, 2, len(f10seq))
	require.Equal(t, "foo", f10seq[0].Value())
	require.Equal(t, "bar", f10seq[1].Value())

	root11, err := y.ReplaceNode(root1, this, root2, nil)
	require.NoError(t, err)
	root11map := root11.Value().(map[string]y.Node)
	require.Equal(t, 3, len(root11map))
	require.Equal(t, y.MappingKind, root11map["this"].Kind())
	this11map := root11map["this"].Value().(map[string]y.Node)
	require.Equal(t, "another one", this11map["e"].Value())
	require.Equal(t, y.SequenceKind, this11map["f"].Kind())

	root12, err := y.ReplaceNode(root1, that0, e, nil)
	require.NoError(t, err)
	root12map := root12.Value().(map[string]y.Node)
	require.Equal(t, 3, len(root12map))
	require.Equal(t, y.ScalarKind, root12map["this"].Kind())
	require.Equal(t, "one", root12map["this"].Value())
	require.Equal(t, y.SequenceKind, root12map["that"].Kind())
	that12seq := root12map["that"].Value().([]y.Node)
	require.Equal(t, y.ScalarKind, that12seq[0].Kind())
	require.Equal(t, "another one", that12seq[0].Value())
	require.Equal(t, y.MappingKind, that12seq[1].Kind())

	root13, err := y.ReplaceNode(root1, that1, that0, nil)
	require.NoError(t, err)
	root13map := root13.Value().(map[string]y.Node)
	require.Equal(t, 3, len(root13map))
	require.Equal(t, y.ScalarKind, root13map["this"].Kind())
	require.Exactly(t, "one", root13map["this"].Value())
	require.Equal(t, y.SequenceKind, root13map["that"].Kind())
	that13seq := root13map["that"].Value().([]y.Node)
	require.Equal(t, 2, len(that13seq))
	that130map := that13seq[0].Value().(map[string]y.Node)
	that131map := that13seq[1].Value().(map[string]y.Node)
	require.Equal(t, 2, len(that130map))
	require.Equal(t, 2, len(that131map))
	require.Exactly(t, "1", that130map["a"].Value())
	require.Exactly(t, "2", that130map["b"].Value())
	require.Exactly(t, "1", that131map["a"].Value())
	require.Exactly(t, "2", that131map["b"].Value())
	require.Exactly(t, "end", root13map["other"].Value())

	_, err1 := y.ReplaceNode(root1, f, e, nil) // original (f) not in tree
	require.Error(t, err1)
}

func TestRemoveNode(t *testing.T) {
	yaml1 := `---
        this: one
        that:
            -
                a: 1
                b: 2
            -
                c: 3
        other:
            foo:
                bar: 0`

	root1, _ := y.ReadYamlFromString(yaml1, "file1")
	this := root1.Value().(map[string]y.Node)["this"]
	that := root1.Value().(map[string]y.Node)["that"]
	that0 := that.Value().([]y.Node)[0]
	that1 := that.Value().([]y.Node)[1]
	c := that1.Value().(map[string]y.Node)["c"]
	other := root1.Value().(map[string]y.Node)["other"]
	foo := other.Value().(map[string]y.Node)["foo"]
	bar := foo.Value().(map[string]y.Node)["bar"]

	root11, err := y.RemoveNode(root1, root1)
	require.Nil(t, root11)
	require.NoError(t, err)

	root12, err := y.RemoveNode(root1, this)
	require.NoError(t, err)
	root12map := root12.Value().(map[string]y.Node)
	require.Equal(t, 2, len(root12map))
	that2seq := root12map["that"].Value().([]y.Node)
	require.Equal(t, 2, len(that2seq))
	require.Equal(t, y.MappingKind, root12map["other"].Kind())

	root13, err := y.RemoveNode(root1, that)
	require.NoError(t, err)
	root13map := root13.Value().(map[string]y.Node)
	require.Equal(t, 2, len(root13map))
	require.Equal(t, "one", root13map["this"].Value())
	require.Equal(t, y.MappingKind, root12map["other"].Kind())

	root14, err := y.RemoveNode(root1, that0)
	require.NoError(t, err)
	root14map := root14.Value().(map[string]y.Node)
	require.Equal(t, 3, len(root14map))
	require.Equal(t, "one", root14map["this"].Value())
	that4seq := root14map["that"].Value().([]y.Node)
	require.Equal(t, 1, len(that4seq))
	that40map := that4seq[0].Value().(map[string]y.Node)
	require.Equal(t, 1, len(that40map))
	require.Equal(t, "3", that40map["c"].Value())
	require.Equal(t, y.MappingKind, root12map["other"].Kind())

	root15, err := y.RemoveNode(root1, c)
	require.NoError(t, err)
	root15map := root15.Value().(map[string]y.Node)
	require.Equal(t, 3, len(root15map))
	that5seq := root15map["that"].Value().([]y.Node)
	require.Equal(t, 1, len(that5seq))
	that50map := that5seq[0].Value().(map[string]y.Node)
	require.Equal(t, 2, len(that50map))
	require.Equal(t, "1", that50map["a"].Value())
	require.Equal(t, "2", that50map["b"].Value())

	root16, err := y.RemoveNode(root1, that0)
	root16, err = y.RemoveNode(root16, that1)
	require.NoError(t, err)
	root16map := root16.Value().(map[string]y.Node)
	require.Equal(t, 2, len(root16map))
	require.Equal(t, "one", root16map["this"].Value())
	require.Equal(t, y.MappingKind, root12map["other"].Kind())

	root17, err := y.RemoveNode(root1, bar)
	require.NoError(t, err)
	root17map := root17.Value().(map[string]y.Node)
	require.Equal(t, 2, len(root17map))
	require.Equal(t, "one", root16map["this"].Value())
	require.Equal(t, y.SequenceKind, root12map["that"].Kind())

	yaml2 := "x: y"

	root2, _ := y.ReadYamlFromString(yaml2, "file2")
	x := root2.Value().(map[string]y.Node)["x"]
	root21, err := y.RemoveNode(root1, x)
	require.Nil(t, root21)
	require.Error(t, err)
}

func TestAddNodesToMapping(t *testing.T) {
	yaml1 := `
        this: one
        that:
            -
                a: 1
                b: 2
            -
                c: 3
        other:
            foo:
                bar: 0`

	yaml2 := `
        u: [foo, bar]
        v: -1`

	root1, _ := y.ReadYamlFromString(yaml1, "file1")
	require.Equal(t, 3, len(root1.Value().(map[string]y.Node)))

	that := root1.Value().(map[string]y.Node)["that"]
	other := root1.Value().(map[string]y.Node)["other"]
	foo := other.Value().(map[string]y.Node)["foo"]
	c := that.Value().([]y.Node)[1].Value().(map[string]y.Node)["c"]

	root2, _ := y.ReadYamlFromString(yaml2, "file2")
	require.Equal(t, 2, len(root2.Value().(map[string]y.Node)))
	u := root2.Value().(map[string]y.Node)["u"]
	v := root2.Value().(map[string]y.Node)["v"]

	root11, err := y.AddNodesToMapping(root1, root2, map[string]y.Node{"new": u}, nil)
	require.Nil(t, root11)
	require.Error(t, err) // parent not in tree

	root12, err := y.AddNodesToMapping(root1, that, map[string]y.Node{"new": u}, nil)
	require.Nil(t, root12)
	require.Error(t, err) // parent not a mapping node

	root13, err := y.AddNodesToMapping(root1, root1, map[string]y.Node{"new": v}, nil)
	require.NotEmpty(t, root13)
	require.NoError(t, err)
	root13map := root13.Value().(map[string]y.Node)
	require.Equal(t, 4, len(root13map))
	require.Exactly(t, "one", root13map["this"].Value())
	require.Equal(t, y.SequenceKind, root13map["that"].Kind())
	require.Equal(t, y.MappingKind, root13map["other"].Kind())
	require.Exactly(t, "-1", root13map["new"].Value())

	root14, err := y.AddNodesToMapping(root1, foo, map[string]y.Node{"newu": u, "newv": v}, nil)
	require.NotEmpty(t, root14)
	require.NoError(t, err)
	root14map := root14.Value().(map[string]y.Node)
	require.Equal(t, 3, len(root14map))
	require.Exactly(t, "one", root14map["this"].Value())
	require.Equal(t, y.SequenceKind, root14map["that"].Kind())
	require.Equal(t, y.MappingKind, root14map["other"].Kind())
	other14map := root14map["other"].Value().(map[string]y.Node)
	foo14map := other14map["foo"].Value().(map[string]y.Node)
	require.Equal(t, 3, len(foo14map))
	require.Exactly(t, "0", foo14map["bar"].Value())
	require.Equal(t, y.SequenceKind, foo14map["newu"].Kind())
	new14seq := foo14map["newu"].Value().([]y.Node)
	require.Exactly(t, "foo", new14seq[0].Value())
	require.Exactly(t, "bar", new14seq[1].Value())
	require.Exactly(t, "-1", foo14map["newv"].Value())

	root15, err := y.AddNodesToMapping(root1, other, map[string]y.Node{"newc": c}, that)
	require.NotEmpty(t, root15)
	require.NoError(t, err)
	root15map := root15.Value().(map[string]y.Node)
	require.Equal(t, 3, len(root15map))
	require.Exactly(t, "one", root15map["this"].Value())
	require.Equal(t, y.SequenceKind, root15map["that"].Kind())
	require.Equal(t, y.MappingKind, root15map["other"].Kind())
	other15map := root15map["other"].Value().(map[string]y.Node)
	require.Equal(t, 2, len(other15map))
	foo15map := other15map["foo"].Value().(map[string]y.Node)
	require.Equal(t, 1, len(foo15map))
	require.Contains(t, other15map, "newc")
	newc := other15map["newc"]
	require.Exactly(t, "3", newc.Value())
	require.Equal(t, []y.NodeSource{that.Source()}, newc.Referrers())

	// TODO add more Referrers tests
}

func TestAddNodesToSequence(t *testing.T) {
	yaml1 := `
        this: one
        that:
            -
                a: 1
                b: 2
            -
                c: 3
        other:
            foo:
                bar: 0`

	yaml2 := `
        u: [foo, bar]
        v: -1`

	root1, _ := y.ReadYamlFromString(yaml1, "file1")
	require.Equal(t, 3, len(root1.Value().(map[string]y.Node)))

	this := root1.Value().(map[string]y.Node)["this"]
	that := root1.Value().(map[string]y.Node)["that"]
	that0 := that.Value().([]y.Node)[0]
	that1 := that.Value().([]y.Node)[1]

	root2, _ := y.ReadYamlFromString(yaml2, "file2")
	require.Equal(t, 2, len(root2.Value().(map[string]y.Node)))
	u := root2.Value().(map[string]y.Node)["u"]
	v := root2.Value().(map[string]y.Node)["v"]

	// TODO test non-nil referrer node
	root11, err := y.AddNodesToSequence(root1, u, []y.Node{v}, 0, nil)
	require.Nil(t, root11)
	require.Error(t, err) // parent not in tree

	root12, err := y.AddNodesToSequence(root1, this, []y.Node{u}, 0, nil)
	require.Nil(t, root12)
	require.Error(t, err) // parent not a sequence node

	root13, err := y.AddNodesToSequence(root1, that, []y.Node{v}, -1, nil)
	require.Nil(t, root13)
	require.Error(t, err) // index out of range

	root14, err := y.AddNodesToSequence(root1, that, []y.Node{v}, 3, nil)
	require.Nil(t, root14)
	require.Error(t, err) // index out of range

	root15, err := y.AddNodesToSequence(root1, that, []y.Node{v}, 0, nil)
	require.NotEmpty(t, root15)
	require.NoError(t, err)
	root15map := root15.Value().(map[string]y.Node)
	require.Equal(t, 3, len(root15map))
	require.Exactly(t, "one", root15map["this"].Value())
	require.Equal(t, y.SequenceKind, root15map["that"].Kind())
	require.Equal(t, y.MappingKind, root15map["other"].Kind())
	that15seq := root15map["that"].Value().([]y.Node)
	require.Equal(t, 3, len(that15seq))
	require.Exactly(t, "-1", that15seq[0].Value())
	require.Equal(t, that0, that15seq[1])
	require.Equal(t, that1, that15seq[2])

	root16, err := y.AddNodesToSequence(root1, that, []y.Node{v}, 1, nil)
	require.NotEmpty(t, root16)
	require.NoError(t, err)
	root16map := root16.Value().(map[string]y.Node)
	require.Equal(t, 3, len(root16map))
	require.Exactly(t, "one", root16map["this"].Value())
	require.Equal(t, y.SequenceKind, root16map["that"].Kind())
	require.Equal(t, y.MappingKind, root16map["other"].Kind())
	that16seq := root16map["that"].Value().([]y.Node)
	require.Equal(t, 3, len(that16seq))
	require.Equal(t, that0, that16seq[0])
	require.Exactly(t, "-1", that16seq[1].Value())
	require.Equal(t, that1, that16seq[2])

	root17, err := y.AddNodesToSequence(root1, that, []y.Node{v}, 2, nil)
	require.NotEmpty(t, root17)
	require.NoError(t, err)
	root17map := root17.Value().(map[string]y.Node)
	require.Equal(t, 3, len(root17map))
	require.Exactly(t, "one", root17map["this"].Value())
	require.Equal(t, y.SequenceKind, root17map["that"].Kind())
	require.Equal(t, y.MappingKind, root17map["other"].Kind())
	that17seq := root17map["that"].Value().([]y.Node)
	require.Equal(t, 3, len(that17seq))
	require.Equal(t, that0, that17seq[0])
	require.Equal(t, that1, that17seq[1])
	require.Exactly(t, "-1", that17seq[2].Value())

	root18, err := y.AddNodesToSequence(root1, that, []y.Node{u, v}, 1, nil)
	require.NotEmpty(t, root18)
	require.NoError(t, err)
	root18map := root18.Value().(map[string]y.Node)
	require.Equal(t, 3, len(root18map))
	require.Exactly(t, "one", root18map["this"].Value())
	require.Equal(t, y.SequenceKind, root18map["that"].Kind())
	require.Equal(t, y.MappingKind, root18map["other"].Kind())
	that18seq := root18map["that"].Value().([]y.Node)
	require.Equal(t, 4, len(that18seq))
	require.Equal(t, that0, that18seq[0])
	require.Equal(t, y.SequenceKind, that18seq[1].Kind())
	u18 := that18seq[1].Value().([]y.Node)
	require.Exactly(t, "foo", u18[0].Value())
	require.Exactly(t, "bar", u18[1].Value())
	require.Exactly(t, "-1", that18seq[2].Value())
	require.Equal(t, that1, that18seq[3])
}

func TestTreesEquivalent(t *testing.T) {
	yaml := `
        this: one
        that:
            -
                a: 1
                b: 2
            -
                c: 3
        other:
            foo:
                bar: 0`

	root1, _ := y.ReadYamlFromString(yaml, "file1")
	root2, _ := y.ReadYamlFromString("\n"+yaml, "file2")
	require.True(t, y.TreesEquivalent(root1, root2))
	root3, _ := y.ReadYamlFromString(strings.Replace(yaml, "3", "4", 1), "file3")
	require.False(t, y.TreesEquivalent(root1, root3))
	root4, _ := y.ReadYamlFromString(yaml+"\n        more: 0", "file3")
	require.False(t, y.TreesEquivalent(root1, root4))
}

func TestNativeTreeForSingleScalarNode(t *testing.T) {
	root, _ := y.ReadYamlFromString("foo", "testfile")
	n := y.NativeTree(root)
	require.IsType(t, "", n)
	require.Exactly(t, "foo", n)
}

func TestNativeTreeForSingleSequence(t *testing.T) {
	root, _ := y.ReadYamlFromString("- foo\n- bar", "testfile")
	n := y.NativeTree(root)
	require.IsType(t, []interface{}{}, n)
	s := n.([]interface{})
	require.Equal(t, 2, len(s))
	require.Exactly(t, "foo", s[0])
	require.Exactly(t, "bar", s[1])
}

func TestNativeTreeForSingleMapping(t *testing.T) {
	root, _ := y.ReadYamlFromString("a: foo\nb: bar", "testfile")
	n := y.NativeTree(root)
	require.IsType(t, map[string]interface{}{}, n)
	m := n.(map[string]interface{})
	require.Equal(t, 2, len(m))
	require.Exactly(t, "foo", m["a"])
	require.Exactly(t, "bar", m["b"])
}

func TestNativeTreeForNontrivialDocument(t *testing.T) {
	yaml := `---
        a: one
        b: two
        c:
            x:
                - 1
                - 2
                - 3
            y:
                aa: !!float 1
                bb: [2, 3]
                cc: xyz
        d: ~
        last one: the end`

	root, err := y.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	n := y.NativeTree(root)
	require.IsType(t, map[string]interface{}{}, n)
	m := n.(map[string]interface{})
	require.Equal(t, 5, len(m))
	require.Exactly(t, "one", m["a"])
	require.Exactly(t, "two", m["b"])
	require.Equal(t, 2, len(m["c"].(map[string]interface{})))
	require.Exactly(t, []interface{}{int64(1), int64(2), int64(3)}, m["c"].(map[string]interface{})["x"].([]interface{}))
	require.Exactly(t, float64(1.0), m["c"].(map[string]interface{})["y"].(map[string]interface{})["aa"])
	require.Exactly(t, []interface{}{int64(2), int64(3)}, m["c"].(map[string]interface{})["y"].(map[string]interface{})["bb"])
	require.Exactly(t, "xyz", m["c"].(map[string]interface{})["y"].(map[string]interface{})["cc"])
	require.Exactly(t, nil, m["d"])
	require.Exactly(t, "the end", m["last one"])
}

func TestMappingKeysInSourceOrder(t *testing.T) {
	yaml := `
        _: [&SIX 6, &FIVE 5, &FOUR 4, &THREE 3, &TWO 2, &ONE 1]
        a:
            one: 1
        b:
            one: *ONE
            two: *TWO
            three: *THREE
            four: *FOUR
            five: *FIVE
            six: *SIX
        c: {one: *ONE, two: *TWO, three: *THREE, four: *FOUR, five: *FIVE, six: *SIX}
        d: 0
        e: [0]`

	root, err := y.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	m := root.Value().(map[string]y.Node)
	require.Equal(t, []string{"one"}, y.MappingKeysInSourceOrder(m["a"]))
	require.Equal(t, []string{"one", "two", "three", "four", "five", "six"}, y.MappingKeysInSourceOrder(m["b"]))
	require.Equal(t, []string{"one", "two", "three", "four", "five", "six"}, y.MappingKeysInSourceOrder(m["c"]))
	require.Panics(t, func() { y.MappingKeysInSourceOrder(m["d"]) })
	require.Panics(t, func() { y.MappingKeysInSourceOrder(m["e"]) })
}
