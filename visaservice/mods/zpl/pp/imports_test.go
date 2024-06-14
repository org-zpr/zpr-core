package pp_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vsx/zpl/fs"
	"zpr.org/vsx/zpl/pp"
	yt "zpr.org/vsx/zpl/pp/yamltree"
)

func TestValueScopeImports(t *testing.T) {
	main := `
        communications:
            systems:
                foo: $import[sub1.yaml]
                bar: $import[sub2.yaml]
                qux: $import[sub3]`
	sub1 := `[0, 1]`
	sub2 := `{a: 0, b: 1}`
	sub3 := `01`

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/main.yaml", []byte(main))
	fst.AddFile("/sub1.yaml", []byte(sub1))
	fst.AddFile("/sub2.yaml", []byte(sub2))
	fst.AddFile("/sub3", []byte(sub3))

	root, err := pp.LoadYamlTree("/main.yaml", fst)
	require.NoError(t, err)

	root, err = pp.ProcessImports(root, fst)
	require.NoError(t, err)

	require.Equal(t, 2, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.foo[*]"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.foo[0]$0"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.foo[1]$1"))))
	require.Equal(t, 2, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.bar.*"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.bar.a$0"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.bar.b$1"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.qux$01"))))
}

func TestKeyScopeImports(t *testing.T) {
	main := `
        communications:
            systems:
                foo:
                    $import: sub1.yaml
                bar:
                    $import: sub1.yaml
                    $import[sub2.yaml]:
                    other: stuff
                qux:
                    $import[sub3.yaml]:
                    $import[sub4.yaml]:
                    $import[sub5.yaml]:`
	sub1 := `{a: 0, b: 1}`
	sub2 := `{c: 2, d: 3}`
	sub3 := `[0, 1]`
	sub4 := `[2, 3]`
	sub5 := `[4, 5]`

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/main.yaml", []byte(main))
	fst.AddFile("/sub1.yaml", []byte(sub1))
	fst.AddFile("/sub2.yaml", []byte(sub2))
	fst.AddFile("/sub3.yaml", []byte(sub3))
	fst.AddFile("/sub4.yaml", []byte(sub4))
	fst.AddFile("/sub5.yaml", []byte(sub5))

	root, err := pp.LoadYamlTree("/main.yaml", fst)
	require.NoError(t, err)

	root, err = pp.ProcessImports(root, fst)
	require.NoError(t, err)

	require.Equal(t, 2, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.foo.*"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.foo.a$0"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.foo.b$1"))))
	require.Equal(t, 5, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.bar.*"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.bar.a$0"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.bar.b$1"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.bar.c$2"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.bar.d$3"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.bar.other$stuff"))))
	require.Equal(t, 6, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.qux[*]"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.qux[0]$0"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.qux[1]$1"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.qux[2]$2"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.qux[3]$3"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.qux[4]$4"))))
	require.Equal(t, 1, len(yt.MatchingPaths(root, yt.NewPathPatternOk("communications.systems.qux[5]$5"))))
}

func TestNestedImports(t *testing.T) {
	root := `
        communications:
            systems:
              - $import: /blah.yaml`
	blah := `
        name: some system
        services:
            - name: service 1
              policies:
                - name: s1p1
                - $import: /s1p2.yaml`

	s1p2 := `
        name: s1p2
        id: $import[s1p2id.txt]`

	s1p2id := "s1p2_id_xx"

	fst, _ := fs.NewMemoryFileStore()
	fst.AddFile("/root.yaml", []byte(root))
	fst.AddFile("/blah.yaml", []byte(blah))
	fst.AddFile("/s1p2.yaml", []byte(s1p2))
	fst.AddFile("/s1p2id.txt", []byte(s1p2id))

	root0, err := pp.LoadYamlTree("/root.yaml", fst)
	require.NoError(t, err)

	root1, err := pp.ProcessImports(root0, fst)
	require.NoError(t, err)

	require.Equal(t, 1, len(yt.MatchingPaths(root1, yt.NewPathPatternOk("communications.systems[0].services[0].policies[1].id$s1p2_id_xx"))))
}
