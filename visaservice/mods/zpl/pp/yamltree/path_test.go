package yamltree_test

import (
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	y "zpr.org/vsx/zpl/pp/yamltree"
)

func TestNewPathPatternEmpty(t *testing.T) {
	pat, err := y.NewPathPattern("")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestPathRoot(t *testing.T) {
	pat, err := y.NewPathPattern(".")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTopLevelLiteralKey(t *testing.T) {
	pat, err := y.NewPathPattern(".foo")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTopLevelLiteralKeyInverted(t *testing.T) {
	pat, err := y.NewPathPattern(".!foo")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTopLevelRegexpKey(t *testing.T) {
	pat, err := y.NewPathPattern(".'foo'")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTopLevelRegexpKeyInverted(t *testing.T) {
	pat, err := y.NewPathPattern(".!'foo'")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTopLevelNoClosingSingleQuote(t *testing.T) {
	pat, err := y.NewPathPattern(`.'foo`)
	require.Error(t, err)
	require.Nil(t, pat)
}

func TestNewPathPatternTopLevelNoClosingDoubleQuote(t *testing.T) {
	pat, err := y.NewPathPattern(`."foo`)
	require.Error(t, err)
	require.Nil(t, pat)
}

func TestPathTopLevelRegexpKeyWithEscapedQuotes(t *testing.T) {
	pat, err := y.NewPathPattern(".'foo''bar'''")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTopLevelKeyWildcard(t *testing.T) {
	pat, err := y.NewPathPattern(".*")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTopLevelKeyWildcardNoDot(t *testing.T) {
	pat, err := y.NewPathPattern("*")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTopLevelIndex(t *testing.T) {
	pat, err := y.NewPathPattern(".[0]")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternIndexNoDot(t *testing.T) {
	pat, err := y.NewPathPattern("[0]")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternIndexNegative(t *testing.T) {
	pat, err := y.NewPathPattern("[-1]")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternIndexInverted(t *testing.T) {
	pat, err := y.NewPathPattern("[!0]")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTopLevelIndexWildcard(t *testing.T) {
	pat, err := y.NewPathPattern(".[*]")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTopLevelIndexWildcardNoDot(t *testing.T) {
	pat, err := y.NewPathPattern("[*]")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTopLevelAnyWildcard(t *testing.T) {
	pat, err := y.NewPathPattern(".@")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTopLevelAnyWildcardNoDot(t *testing.T) {
	pat, err := y.NewPathPattern("@@")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTopLevelAssertion1(t *testing.T) {
	pat, err := y.NewPathPattern("{foo}bar")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTopLevelAssertion2(t *testing.T) {
	pat, err := y.NewPathPattern("{foo}{bar}baz")
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTopLevelLiteralKeyPlusLiteralIndex(t *testing.T) {
	for _, expr := range []string{".foo.[0]", ".foo[0]", ".foo[+17]", ".foo[-1]", "foo[0]"} {
		pat, err := y.NewPathPattern(expr)
		require.NoError(t, err, expr)
		require.NotEmpty(t, pat, expr)
	}
}

func TestNewPathPatternTopLevelLiteralKeyPlusInvalidIndex(t *testing.T) {
	for _, expr := range []string{".foo.[bar]", ".foo[1bar]", ".foo[]", ".foo[1"} {
		pat, err := y.NewPathPattern(expr)
		require.Error(t, err, expr)
		require.Nil(t, pat, expr)
	}
}

func TestNewPathPatternTopLevelLiteralKeyPlusInvalidNegation(t *testing.T) {
	for _, expr := range []string{".foo.!", ".foo.!*", ".foo.!**", ".foo.!@", ".foo.!@@", ".foo[!]", ".foo[!*]", ".foo.[!**]"} {
		pat, err := y.NewPathPattern(expr)
		require.Error(t, err, expr)
		require.Nil(t, pat, expr)
	}
}

func TestNewPathPatternIndexTwoLevels(t *testing.T) {
	for _, expr := range []string{".a.[*].[0]", ".a.[*][0]", ".a[0][1]", "a[0].[1]"} {
		pat, err := y.NewPathPattern(expr)
		require.NoError(t, err, expr)
		require.NotEmpty(t, pat, expr)
	}
}

func TestNewPathPatternTwoLiteralKeys(t *testing.T) {
	for _, expr := range []string{".foo.bar", "foo.bar"} {
		pat, err := y.NewPathPattern(expr)
		require.NoError(t, err, expr)
		require.NotEmpty(t, pat, expr)
	}
}

func TestNewPathPatternMultipleComponents(t *testing.T) {
	for _, expr := range []string{`.foo.bar.baz`, `foo."bar.baz"`, `foo."bar \"baz\""`, `.foo.'[bB].*r'[0].baz`,
		`.foo.'[bB].*r'[0].*.baz`, `.foo[0].[1]`, `foo[0][1]`, `.[0][1].foo`, `[0][1].foo`} {
		pat, err := y.NewPathPattern(expr)
		require.NoError(t, err, expr)
		require.NotEmpty(t, pat, expr)
	}
}

func TestNewPathPatternMultipleDots(t *testing.T) {
	for _, expr := range []string{"..", "..foo", "foo..", "foo..bar"} {
		pat, err := y.NewPathPattern(expr)
		require.Error(t, err, expr)
		require.Nil(t, pat, expr)
	}
}

func TestNewPathPatternDescent(t *testing.T) {
	for _, op := range []string{"**", "[**]", "@@"} {
		for _, expr := range []string{"." + op, "." + op + ".foo", ".foo." + op + ".bar", "foo." + op} {
			pat, err := y.NewPathPattern(expr)
			require.NoError(t, err, expr)
			require.NotEmpty(t, pat, expr)
		}
	}
}

func TestNewPathPatternEndMatch(t *testing.T) {
	for _, expr := range []string{".$", "$", ".foo$", "foo$", "*[0]$"} {
		pat, err := y.NewPathPattern(expr)
		require.NoError(t, err, expr)
		require.NotEmpty(t, pat, expr)
	}
}

func TestNewPathPatternValueSelector(t *testing.T) {
	for _, expr := range []string{`.$foo`, `$*`, `foo$bar`, `foo$"bar.baz"`, `*[0]$'^$'`, `foo$!bar`, `foo$!"bar.baz"`, `*[0]$!'^$'`} {
		pat, err := y.NewPathPattern(expr)
		require.NoError(t, err, expr)
		require.NotEmpty(t, pat, expr)
	}
}

func TestNewPathPatternYikes(t *testing.T) {
	pat, err := y.NewPathPattern(`foo[*].**."bar.".'\w+{\d:\S}*😬?'.'.'."❗️"[!+3].**$!"√−1"`)
	require.NoError(t, err)
	require.NotEmpty(t, pat)
}

func TestNewPathPatternTrailingUnquotedWhitespace(t *testing.T) {
	pat, err := y.NewPathPattern(`foo.bar `)
	require.Error(t, err)
	require.Nil(t, pat)
}

func TestParsePathExpressionGood(t *testing.T) {
	type item struct {
		text   string
		length int
	}
	items := []item{{"", 0}, {"foo.bar[*]", 10}, {"foo.bar[*]$", 11}, {"foo.bar[*]=0", 10}, {"foo.bar[*] = 0", 10}}
	for _, i := range items {
		_, nbytes, err := y.ParsePathExpression(i.text)
		require.NoError(t, err, "%v", i)
		require.Equal(t, i.length, nbytes)
	}
}

func TestParsePathExpressionBad(t *testing.T) {
	exprs := []string{"foo.bar[*", "foo.'.*", "foo.'\\'"}
	for _, e := range exprs {
		_, _, err := y.ParsePathExpression(e)
		require.Error(t, err, e)
	}
}

func TestParsePathExpressionNonePresent(t *testing.T) {
	exprs := []string{"%nope", "$nada", ":zilch", " ", "+", "(etc.)"}
	for _, e := range exprs {
		_, n, err := y.ParsePathExpression(e)
		require.NoError(t, err, e)
		require.Equal(t, 0, n, e)
	}
}

func TestMatchingPathsRoot(t *testing.T) {
	for _, yaml := range []string{"foo", "- foo\n- bar", "foo: 1\nbar: 1"} {
		for _, expr := range []string{"", "."} {
			pat := y.NewPathPatternOk(expr)
			root, _ := y.ReadYamlFromString(yaml, "testfile")
			paths := y.MatchingPaths(root, pat)
			require.Equal(t, 1, len(paths), "%q %q", yaml, expr)
			require.Equal(t, 1, len(paths[0]), "%q %q", yaml, expr)
			require.Equal(t, root, paths[0][0], "%q %q", yaml, expr)
		}
	}
}

func TestMatchingPathsScalarRoot(t *testing.T) {
	root, _ := y.ReadYamlFromString("foo", "testfile")
	for _, expr := range []string{"", "."} {
		pat := y.NewPathPatternOk(expr)
		paths := y.MatchingPaths(root, pat)
		require.Equal(t, 1, len(paths), expr)
	}
}

func TestMatchingPathsScalarRootNoMatch(t *testing.T) {
	root, _ := y.ReadYamlFromString("foo", "testfile")
	for _, expr := range []string{".foo", ".*", "*"} {
		pat := y.NewPathPatternOk(expr)
		paths := y.MatchingPaths(root, pat)
		require.Equal(t, 0, len(paths), expr)
	}
}

func TestMatchingPathsMappingRoot(t *testing.T) {
	root, _ := y.ReadYamlFromString("foo: 1", "testfile")
	for _, expr := range []string{".foo", ".*", "foo", "*"} {
		pat := y.NewPathPatternOk(expr)
		paths := y.MatchingPaths(root, pat)
		require.Equal(t, 1, len(paths), expr)
		require.Equal(t, 2, len(paths[0]), expr)
		require.Equal(t, "1", paths[0][1].Value(), expr)
	}
}

func TestMatchingPathsNilRoot(t *testing.T) {
	pat := y.NewPathPatternOk("foo")
	paths := y.MatchingPaths(nil, pat)
	require.Equal(t, 0, len(paths))
}

func TestMatchingPathsSequenceRoot(t *testing.T) {
	root, _ := y.ReadYamlFromString("- foo", "testfile")
	for _, expr := range []string{".[0]", "[0]", ".[-1]", "[-1]", ".[*]", "[!2]"} {
		pat := y.NewPathPatternOk(expr)
		paths := y.MatchingPaths(root, pat)
		require.Equal(t, 1, len(paths), expr)
		require.Equal(t, 2, len(paths[0]), expr)
		require.Equal(t, "foo", paths[0][1].Value(), expr)
	}
}

func TestMatchingPathsEndAssertion(t *testing.T) {
	root, _ := y.ReadYamlFromString("foo: xyz\nbar: 123", "testfile")
	for _, expr := range []string{".foo$", "foo$"} {
		pat := y.NewPathPatternOk(expr)
		paths := y.MatchingPaths(root, pat)
		require.Equal(t, 1, len(paths), expr)
		require.Equal(t, 2, len(paths[0]), expr)
		require.Equal(t, "xyz", paths[0][1].Value(), expr)
	}
}

func TestMatchingPathsEndAssertionWithValueSelector(t *testing.T) {
	root, _ := y.ReadYamlFromString("foo: xyz\nbar: 123", "testfile")
	for _, expr := range []string{".foo$xyz", "foo$*y*", "foo$'z$'", "@@$x*"} {
		pat := y.NewPathPatternOk(expr)
		paths := y.MatchingPaths(root, pat)
		require.Equal(t, 1, len(paths), expr)
		require.Equal(t, 2, len(paths[0]), expr)
		require.Equal(t, "xyz", paths[0][1].Value(), expr)
	}
}

func TestMatchingPathsMultilevel(t *testing.T) {
	yaml := `
        k0: &a0 v0                      # n0
        k1:                             # n1
            k10: &a10                   # n10
                k100: v100              # n100
                k101: v101              # n101
            k11:                        # n11
                - v110                  # n110
                -                       # n111
                    k1110: v1110        # n1110
                    k1111:              # n1111
                        k11110: v11110  # n11110
        k2:                             # n2
            -                           # n20
                - v200                  # n200
                - v201                  # n201
            -                           # n21
                -                       # n210
                    k2100:              # n2100
                        - v21000        # n21000
                - *a0                   # n211 (n0)
        k3:                             # n3
            k30:                        # n30
                *a10                    # n300 (n100), n301 (n101)
    `

	root, err := y.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	require.Equal(t, y.MappingKind, root.Kind())

	asSeq := func(node y.Node) []y.Node {
		require.Equal(t, y.SequenceKind, node.Kind(), "not a sequence node: %#v", node)
		return node.Value().([]y.Node)
	}

	asMap := func(node y.Node) map[string]y.Node {
		require.Equal(t, y.MappingKind, node.Kind(), "not a mapping node: %#v", node)
		return node.Value().(map[string]y.Node)
	}

	n0 := asMap(root)["k0"] // scalar (leaf) node with value "v0"
	n1 := asMap(root)["k1"] // mapping node with keys "k10" and "k11"
	n2 := asMap(root)["k2"] // sequence node with two elements
	n3 := asMap(root)["k3"] // sequence node with one element
	n10 := asMap(n1)["k10"]
	n11 := asMap(n1)["k11"]
	n20 := asSeq(n2)[0]
	n21 := asSeq(n2)[1]
	n30 := asMap(n3)["k30"]
	n100 := asMap(n10)["k100"]
	n101 := asMap(n10)["k101"]
	n110 := asSeq(n11)[0]
	n111 := asSeq(n11)[1]
	n200 := asSeq(n20)[0]
	n201 := asSeq(n20)[1]
	n210 := asSeq(n21)[0]
	n211 := asSeq(n21)[1]
	n300 := asMap(n30)["k100"]
	n301 := asMap(n30)["k101"]
	n1110 := asMap(n111)["k1110"]
	n1111 := asMap(n111)["k1111"]
	n2100 := asMap(n210)["k2100"]
	n11110 := asMap(n1111)["k11110"]
	n21000 := asSeq(n2100)[0]

	var paths [][]y.Node

	path := func(ns ...y.Node) []y.Node {
		return ns
	}

	containsPath := func(paths [][]y.Node, path []y.Node) bool {
		for _, p := range paths {
			if reflect.DeepEqual(p, path) {
				return true
			}
		}
		return false
	}

	pathExprsSorted := func(paths [][]y.Node) []string {
		var exprs []string
		for _, p := range paths {
			exprs = append(exprs, y.PathExpressionOk(p))
		}
		sort.Strings(exprs)
		return exprs
	}

	paths = y.MatchingPaths(root, y.NewPathPatternOk("."))
	require.Equal(t, 1, len(paths))
	require.Equal(t, 1, len(paths[0]))
	require.Equal(t, path(root), paths[0])
	require.Equal(t, ".", y.PathExpressionOk(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k0"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n0), paths[0])
	require.Equal(t, "k0", y.PathExpressionOk(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k0$"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n0), paths[0])
	require.Equal(t, "k0", y.PathExpressionOk(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k0$v0"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n0), paths[0])
	require.Equal(t, "k0", y.PathExpressionOk(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k1"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n1), paths[0])
	require.Equal(t, "k1", y.PathExpressionOk(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k1$"))
	require.Equal(t, 0, len(paths))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k2"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n2), paths[0])
	require.Equal(t, "k2", y.PathExpressionOk(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k3"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n3), paths[0])
	require.Equal(t, "k3", y.PathExpressionOk(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("*"))
	require.Equal(t, 4, len(paths))
	require.True(t, containsPath(paths, path(root, n0)))
	require.True(t, containsPath(paths, path(root, n1)))
	require.True(t, containsPath(paths, path(root, n2)))
	require.True(t, containsPath(paths, path(root, n3)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("*"))
	require.Equal(t, 4, len(paths))
	require.True(t, containsPath(paths, path(root, n0)))
	require.True(t, containsPath(paths, path(root, n1)))
	require.True(t, containsPath(paths, path(root, n2)))
	require.True(t, containsPath(paths, path(root, n3)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("'^k\\d'"))
	require.Equal(t, 4, len(paths))
	require.True(t, containsPath(paths, path(root, n0)))
	require.True(t, containsPath(paths, path(root, n1)))
	require.True(t, containsPath(paths, path(root, n2)))
	require.True(t, containsPath(paths, path(root, n3)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k1.k10"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n1, n10), paths[0])

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k1.k10.k101"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n1, n10, n101), paths[0])
	require.Equal(t, "k1.k10.k101", y.PathExpressionOk(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k1.k10.x"))
	require.Equal(t, 0, len(paths))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k2.[-1]"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n2, n21), paths[0])
	require.Equal(t, "k2[1]", y.PathExpressionOk(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k2[-1][0]"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n2, n21, n210), paths[0])
	require.Equal(t, "k2[1][0]", y.PathExpressionOk(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k2[-1][0].k2100[0]"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n2, n21, n210, n2100, n21000), paths[0])

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k2[-1][1]"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n2, n21, n211), paths[0])

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k2[-1][1]$"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n2, n21, n211), paths[0])

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k2[-1][1]$*0"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n2, n21, n211), paths[0])

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k2[-1]$"))
	require.Equal(t, 0, len(paths))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k3.k30"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n3, n30), paths[0])

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k3.k30.k100"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n3, n30, n300), paths[0])

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k3.k30.*"))
	require.Equal(t, 2, len(paths))
	require.True(t, containsPath(paths, path(root, n3, n30, n300)))
	require.True(t, containsPath(paths, path(root, n3, n30, n301)))
	require.Equal(t, []string{"k3.k30.k100", "k3.k30.k101"}, pathExprsSorted(paths))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("*.k10.*101"))
	require.Equal(t, 1, len(paths))
	require.Equal(t, path(root, n1, n10, n101), paths[0])

	paths = y.MatchingPaths(root, y.NewPathPatternOk("*.'^.\\d0'.*"))
	require.Equal(t, 4, len(paths))
	require.True(t, containsPath(paths, path(root, n1, n10, n100)))
	require.True(t, containsPath(paths, path(root, n1, n10, n101)))
	require.True(t, containsPath(paths, path(root, n3, n30, n300)))
	require.True(t, containsPath(paths, path(root, n3, n30, n301)))
	require.Equal(t, []string{"k1.k10.k100", "k1.k10.k101", "k3.k30.k100", "k3.k30.k101"}, pathExprsSorted(paths))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k2[0][*]$"))
	require.Equal(t, 2, len(paths))
	require.True(t, containsPath(paths, path(root, n2, n20, n200)))
	require.True(t, containsPath(paths, path(root, n2, n20, n201)))
	require.Equal(t, []string{"k2[0][0]", "k2[0][1]"}, pathExprsSorted(paths))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("*[*][*]"))
	require.Equal(t, 4, len(paths))
	require.True(t, containsPath(paths, path(root, n2, n20, n200)))
	require.True(t, containsPath(paths, path(root, n2, n20, n201)))
	require.True(t, containsPath(paths, path(root, n2, n21, n210)))
	require.True(t, containsPath(paths, path(root, n2, n21, n211)))
	require.Equal(t, []string{"k2[0][0]", "k2[0][1]", "k2[1][0]", "k2[1][1]"}, pathExprsSorted(paths))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("**.k0"))
	require.Equal(t, path(root, n0), paths[0])

	paths = y.MatchingPaths(root, y.NewPathPatternOk("**.k10"))
	require.Equal(t, path(root, n1, n10), paths[0])

	paths = y.MatchingPaths(root, y.NewPathPatternOk("**.k101"))
	require.Equal(t, 2, len(paths))
	require.True(t, containsPath(paths, path(root, n1, n10, n101)))
	require.True(t, containsPath(paths, path(root, n3, n30, n301)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("**.k*.**.k101"))
	require.Equal(t, 2, len(paths))
	require.True(t, containsPath(paths, path(root, n1, n10, n101)))
	require.True(t, containsPath(paths, path(root, n3, n30, n301)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("**.k11.[**]"))
	require.Equal(t, 2, len(paths))
	require.True(t, containsPath(paths, path(root, n1, n11, n110)))
	require.True(t, containsPath(paths, path(root, n1, n11, n111)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("@@.k11.[**]"))
	require.Equal(t, 2, len(paths))
	require.True(t, containsPath(paths, path(root, n1, n11, n110)))
	require.True(t, containsPath(paths, path(root, n1, n11, n111)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k2[**]$"))
	require.Equal(t, 3, len(paths))
	require.True(t, containsPath(paths, path(root, n2, n20, n200)))
	require.True(t, containsPath(paths, path(root, n2, n20, n201)))
	require.True(t, containsPath(paths, path(root, n2, n21, n211)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("k2[**]$v20*"))
	require.Equal(t, 2, len(paths))
	require.True(t, containsPath(paths, path(root, n2, n20, n200)))
	require.True(t, containsPath(paths, path(root, n2, n20, n201)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("@@.k1110$"))
	require.Equal(t, 1, len(paths))
	require.True(t, containsPath(paths, path(root, n1, n11, n111, n1110)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("**.k11.@@"))
	require.Equal(t, 5, len(paths))
	require.True(t, containsPath(paths, path(root, n1, n11, n110)))
	require.True(t, containsPath(paths, path(root, n1, n11, n111)))
	require.True(t, containsPath(paths, path(root, n1, n11, n111, n1110)))
	require.True(t, containsPath(paths, path(root, n1, n11, n111, n1111)))
	require.True(t, containsPath(paths, path(root, n1, n11, n111, n1111, n11110)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("**.k11.@@$"))
	require.Equal(t, 3, len(paths))
	require.True(t, containsPath(paths, path(root, n1, n11, n110)))
	require.True(t, containsPath(paths, path(root, n1, n11, n111, n1110)))
	require.True(t, containsPath(paths, path(root, n1, n11, n111, n1111, n11110)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("*[*][*]$"))
	require.Equal(t, 3, len(paths))
	require.True(t, containsPath(paths, path(root, n2, n20, n200)))
	require.True(t, containsPath(paths, path(root, n2, n20, n201)))
	require.True(t, containsPath(paths, path(root, n2, n21, n211)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("*.@@.[*]$"))
	require.Equal(t, 5, len(paths))
	require.True(t, containsPath(paths, path(root, n1, n11, n110)))
	require.True(t, containsPath(paths, path(root, n2, n20, n200)))
	require.True(t, containsPath(paths, path(root, n2, n20, n201)))
	require.True(t, containsPath(paths, path(root, n2, n21, n210, n2100, n21000)))
	require.True(t, containsPath(paths, path(root, n2, n21, n211)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("@@"))
	require.Equal(t, 24, len(paths))
	require.True(t, containsPath(paths, path(root, n0)))
	require.True(t, containsPath(paths, path(root, n1)))
	require.True(t, containsPath(paths, path(root, n1, n10)))
	require.True(t, containsPath(paths, path(root, n1, n10, n100)))
	require.True(t, containsPath(paths, path(root, n1, n10, n101)))
	require.True(t, containsPath(paths, path(root, n1, n11)))
	require.True(t, containsPath(paths, path(root, n1, n11, n110)))
	require.True(t, containsPath(paths, path(root, n1, n11, n111)))
	require.True(t, containsPath(paths, path(root, n1, n11, n111, n1110)))
	require.True(t, containsPath(paths, path(root, n1, n11, n111, n1111)))
	require.True(t, containsPath(paths, path(root, n1, n11, n111, n1111, n11110)))
	require.True(t, containsPath(paths, path(root, n2)))
	require.True(t, containsPath(paths, path(root, n2, n20)))
	require.True(t, containsPath(paths, path(root, n2, n20, n200)))
	require.True(t, containsPath(paths, path(root, n2, n20, n201)))
	require.True(t, containsPath(paths, path(root, n2, n21)))
	require.True(t, containsPath(paths, path(root, n2, n21, n210)))
	require.True(t, containsPath(paths, path(root, n2, n21, n210, n2100)))
	require.True(t, containsPath(paths, path(root, n2, n21, n210, n2100, n21000)))
	require.True(t, containsPath(paths, path(root, n2, n21, n211)))
	require.True(t, containsPath(paths, path(root, n3)))
	require.True(t, containsPath(paths, path(root, n3, n30)))
	require.True(t, containsPath(paths, path(root, n3, n30, n300)))
	require.True(t, containsPath(paths, path(root, n3, n30, n301)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("@@$"))
	require.Equal(t, 12, len(paths))
	require.True(t, containsPath(paths, path(root, n0)))
	require.True(t, containsPath(paths, path(root, n1, n10, n100)))
	require.True(t, containsPath(paths, path(root, n1, n10, n101)))
	require.True(t, containsPath(paths, path(root, n1, n11, n110)))
	require.True(t, containsPath(paths, path(root, n1, n11, n111, n1110)))
	require.True(t, containsPath(paths, path(root, n1, n11, n111, n1111, n11110)))
	require.True(t, containsPath(paths, path(root, n2, n20, n200)))
	require.True(t, containsPath(paths, path(root, n2, n20, n201)))
	require.True(t, containsPath(paths, path(root, n2, n21, n210, n2100, n21000)))
	require.True(t, containsPath(paths, path(root, n2, n21, n211)))
	require.True(t, containsPath(paths, path(root, n3, n30, n300)))
	require.True(t, containsPath(paths, path(root, n3, n30, n301)))

	paths = y.MatchingPaths(root, y.NewPathPatternOk("@@$'^v1{2,3}0'"))
	require.Equal(t, 2, len(paths))
	require.True(t, containsPath(paths, path(root, n1, n11, n110)))
	require.True(t, containsPath(paths, path(root, n1, n11, n111, n1110)))

	// Squeeze in a couple PathError/PathErrorf/PathSources tests while everything is set up.
	pe1 := y.PathErrorf(path(root, n1, n10, n100), "test")
	require.IsType(t, &y.PathError{}, pe1)
	require.Equal(t, 1, len(y.PathSources(pe1.(*y.PathError).Path)))
	require.Equal(t, "k1.k10.k100", y.PathExpressionOk(pe1.(*y.PathError).Path))
	pe2 := y.PathErrorf(path(root, n3, n30, n301), "test")
	require.IsType(t, &y.PathError{}, pe2)
	require.Equal(t, 2, len(y.PathSources(pe2.(*y.PathError).Path)))
	require.Equal(t, "k3.k30.k101", y.PathExpressionOk(pe2.(*y.PathError).Path))
}

func TestMatchingPathsNegation(t *testing.T) {
	yaml := `
        one:
            red: 123
            blue: 234
            green: 345
        two:
            - - low 0
              - low 1
            - - medium 0
              - medium 1
            - - high 0
              - high 1
        three: the end
    `

	sortedPathExprs := func(root y.Node, pathExpr string) []string {
		exprs := []string{}
		for _, path := range y.MatchingPaths(root, y.NewPathPatternOk(pathExpr)) {
			exprs = append(exprs, y.PathExpressionOk(path))
		}
		sort.Strings(exprs)
		return exprs
	}

	root, err := y.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	require.Equal(t, y.MappingKind, root.Kind())

	require.Equal(t, []string{"one", "two"}, sortedPathExprs(root, `!three`))
	require.Equal(t, []string{"one.blue", "one.green"}, sortedPathExprs(root, `one.!red`))
	require.Equal(t, []string{"one.blue"}, sortedPathExprs(root, `one.!*r*`))
	require.Equal(t, []string{"one.blue"}, sortedPathExprs(root, `one.!'r'`))
	require.Equal(t, []string{"one.blue"}, sortedPathExprs(root, `one.!'r'`))
	require.Equal(t, []string{}, sortedPathExprs(root, `one.!'e'`))
	require.Equal(t, []string{"one.green", "one.red"}, sortedPathExprs(root, `one.*$!234`))
	require.Equal(t, []string{"one.red"}, sortedPathExprs(root, `one.*$!'4'`))
	require.Equal(t, []string{}, sortedPathExprs(root, `one.*$!'3'`))
	require.Equal(t, []string{"two[1]", "two[2]"}, sortedPathExprs(root, `two.[!0]`))
	require.Equal(t, []string{"two[1]", "two[2]"}, sortedPathExprs(root, `two[!0]`))
	require.Equal(t, []string{"two[0]", "two[1]"}, sortedPathExprs(root, `two[!-1]`))
}

func TestMatchingPathsAssertion(t *testing.T) {
	yaml := `
        one:
            red: 123
            blue: 234
            green: 345
        two:
            - - low 0
              - low 1
            - - medium 0
              - medium 1
            - - high 0
              - high 1
        three: the end
    `

	sortedPathExprs := func(root y.Node, pathExpr string) []string {
		exprs := []string{}
		for _, path := range y.MatchingPaths(root, y.NewPathPatternOk(pathExpr)) {
			exprs = append(exprs, y.PathExpressionOk(path))
		}
		sort.Strings(exprs)
		return exprs
	}

	root, err := y.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	require.Equal(t, y.MappingKind, root.Kind())

	require.Equal(t, []string{"one"}, sortedPathExprs(root, `{two}one`))
	require.Equal(t, []string{"one"}, sortedPathExprs(root, `{three}one`))
	require.Equal(t, []string{}, sortedPathExprs(root, `{four}one`))
	require.Equal(t, []string{"one"}, sortedPathExprs(root, `{three$the*}one`))
	require.Equal(t, []string{}, sortedPathExprs(root, `{three$other}one`))
	require.Equal(t, []string{"one"}, sortedPathExprs(root, `{two[0]}one`))
	require.Equal(t, []string{}, sortedPathExprs(root, `{two[3]}one`))
	require.Equal(t, []string{"two"}, sortedPathExprs(root, `{two[1][0]$'edi'}two`))
	require.Equal(t, []string{}, sortedPathExprs(root, `{two[1][0]$"xyz"}two`))
	require.Equal(t, []string{"one.red"}, sortedPathExprs(root, `one.{blue}red`))
	require.Equal(t, []string{"one.red"}, sortedPathExprs(root, `one.{blue$234}red`))
	require.Equal(t, []string{}, sortedPathExprs(root, `one.{blue$235}red`))
	require.Equal(t, []string{"one.red"}, sortedPathExprs(root, `one.{blue}{green}red`))
	require.Equal(t, []string{}, sortedPathExprs(root, `one.{blue}{yellow}red`))
	require.Equal(t, []string{"one.red"}, sortedPathExprs(root, `one.{blue}!{yellow}red`))
	require.Equal(t, []string{}, sortedPathExprs(root, `one.!{blue}!{yellow}red`))
	require.Equal(t, []string{"one.red"}, sortedPathExprs(root, `one.!{magenta}!{yellow}red`))
	require.Equal(t, []string{"two[0][0]"}, sortedPathExprs(root, `two.{[1][1]$*1}[0][0]$*0`))
	require.Equal(t, []string{"two[0][0]"}, sortedPathExprs(root, `two{[1][1]$*1}[0][0]$*0`))
	require.Equal(t, []string{}, sortedPathExprs(root, `two{[1][2]$*1}[0][0]$*0`))
	require.Equal(t, []string{"two[0][0]"}, sortedPathExprs(root, `two.!{[1][2]$*1}[0][0]$*0`))
	require.Equal(t, []string{"two[0][0]"}, sortedPathExprs(root, `two!{[1][2]$*1}[0][0]$*0`))
	require.Equal(t, []string{"two[0][0]"}, sortedPathExprs(root, `two{[**]$high*}[0][0]$*0`))
	require.Equal(t, []string{}, sortedPathExprs(root, `two{[**]$higher*}[0][0]$*0`))
}

func TestMatchingPathsNightmare(t *testing.T) {
	yaml := `
       one: {"foo bar": {"[0]": {foo.bar: {"*": {"foo$": {bar$}}}}}}
       "два": [{"👍": [{"😺": 👍}], "👎": [{"🙀": 👎}]}, [👍, 👎]]
       "三": {"3": {"fjórir": [{4: 4}], "πέντε": [[{5: 5}]], "шесть": [[[6: 6]]]}}
       "2 \"plus\" \\2": [["?"]]
    `

	root, err := y.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)

	var paths [][]y.Node

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`one.**."foo bar"`))
	require.Equal(t, 1, len(paths))
	require.Equal(t, 3, len(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`one.**.'[0]'`))
	require.Equal(t, 1, len(paths))
	require.Equal(t, 4, len(paths[0]))
	require.Equal(t, `one."foo bar"."[0]"`, y.PathExpressionOk(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`one.**."foo.bar"`))
	require.Equal(t, 1, len(paths))
	require.Equal(t, 5, len(paths[0]))
	require.Equal(t, `one."foo bar"."[0]"."foo.bar"`, y.PathExpressionOk(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`one.**.'\*'`))
	require.Equal(t, 1, len(paths))
	require.Equal(t, 6, len(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`one.**."foo$"`))
	require.Equal(t, 1, len(paths))
	require.Equal(t, 7, len(paths[0]))
	require.Equal(t, `one."foo bar"."[0]"."foo.bar"."*"."foo$"`, y.PathExpressionOk(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`one.**$`))
	require.Equal(t, 1, len(paths))
	require.Equal(t, 8, len(paths[0]))
	require.Equal(t, "", paths[0][len(paths[0])-1].Value())

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`one.**`))
	require.Equal(t, 6, len(paths))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`one.**.foo*`))
	require.Equal(t, 3, len(paths))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`"два".@@."👍"`))
	require.Equal(t, 1, len(paths))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`"два".@@."👍".@@."😺"`))
	require.Equal(t, 1, len(paths))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`"два".@@."👍".@@."🙀"`))
	require.Equal(t, 0, len(paths))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`"два".@@$`))
	require.Equal(t, 4, len(paths))
	var nup, ndn int
	for _, p := range paths {
		if p[len(p)-1].Value() == "👍" {
			nup++
		}
		if p[len(p)-1].Value() == "👎" {
			ndn++
		}
	}
	require.Equal(t, 2, nup)
	require.Equal(t, 2, ndn)

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`**.3.@@.4`))
	require.Equal(t, 1, len(paths))
	require.Equal(t, 6, len(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`**.3.@@.5`))
	require.Equal(t, 1, len(paths))
	require.Equal(t, 7, len(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`**.3.@@.6`))
	require.Equal(t, 1, len(paths))
	require.Equal(t, 8, len(paths[0]))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`**."三".@@.'[4-6]'$`))
	require.Equal(t, 3, len(paths))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`"三".@@`))
	require.Equal(t, 13, len(paths))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`"三".@@$`))
	require.Equal(t, 3, len(paths))

	paths = y.MatchingPaths(root, y.NewPathPatternOk(`2*.@@$`))
	require.Equal(t, 1, len(paths))
	require.Equal(t, 4, len(paths[0]))
	require.Equal(t, `"2 \"plus\" \\2"[0][0]`, y.PathExpressionOk(paths[0]))
}

func TestQuoteKeyMeta(t *testing.T) {
	require.Equal(t, `foo`, y.QuoteKeyMeta(`foo`))
	require.Equal(t, `"foo "`, y.QuoteKeyMeta(`foo `))
	require.Equal(t, `"fo*o"`, y.QuoteKeyMeta(`fo*o`))
	require.Equal(t, `"fo\"o"`, y.QuoteKeyMeta(`fo"o`))
	require.Equal(t, `"fo\\o"`, y.QuoteKeyMeta(`fo\o`))
}

func TestQuoteKeyRegexMeta(t *testing.T) {
	require.Equal(t, `foo`, y.QuoteKeyRegexMeta(`foo`))
	require.Equal(t, `\.foo`, y.QuoteKeyRegexMeta(`.foo`))
	require.Equal(t, `foo\*`, y.QuoteKeyRegexMeta(`foo*`))
	require.Equal(t, `fo''o`, y.QuoteKeyRegexMeta(`fo'o`))
}
