package compiler_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"zpr.org/vsx/zpl/compiler"
	"zpr.org/vsx/zpl/doc"
)

func makeAttrExpr(key, op, val string) *doc.AttrExpr {
	zs := func(s string) doc.ZplString {
		if zs, err := doc.NewZplString(s); err != nil {
			panic(err)
		} else {
			return zs
		}
	}
	return &doc.AttrExpr{nil, zs(key), zs(op), zs(val)}
}

func TestGetProvides(t *testing.T) {
	as := &compiler.AttrExprSet{
		Provides: []*compiler.PSvc{
			&compiler.PSvc{
				Path:      "/foo",
				ServiceID: "service.foo",
				Type:      compiler.PSvcTDef,
				Endpoints: []string{"tcp/100"},
			},
			&compiler.PSvc{
				Path:      "/fee",
				ServiceID: "service.fee",
				Type:      compiler.PSvcTDef,
				Endpoints: []string{"tcp/200"},
			},
		},
	}

	pset := as.GetProvides()
	pslist := func() []string {
		var res []string
		for _, s := range strings.Split(pset, ",") {
			res = append(res, strings.TrimSpace(s))
		}
		return res
	}()
	require.Contains(t, pslist, "/foo")
	require.Contains(t, pslist, "/fee")
	require.Len(t, pslist, 2)
}

func TestGenerateIDOnEmpty(t *testing.T) {
	as := &compiler.AttrExprSet{}
	as.GenerateID()
	require.NotEmpty(t, as.ID)
	require.NotEmpty(t, as.Hash)
}

func TestGenerateIDSameAttrs(t *testing.T) {
	as1 := &compiler.AttrExprSet{
		AttrExprs: []*doc.AttrExpr{
			makeAttrExpr("foo", "ne", "fee"),
		},
	}
	as2 := &compiler.AttrExprSet{
		AttrExprs: []*doc.AttrExpr{
			makeAttrExpr("foo", "ne", "fee"),
		},
	}
	as1.GenerateID()
	as2.GenerateID()
	require.Equal(t, as1.ID, as2.ID)
	require.Equal(t, as1.Hash, as2.Hash)

	as3 := &compiler.AttrExprSet{
		AttrExprs: []*doc.AttrExpr{
			makeAttrExpr("foo", "ne", "fie"),
		},
	}
	as3.GenerateID()
	require.NotEqual(t, as1.ID, as3.ID)
	require.NotEqual(t, as1.Hash, as3.Hash)
}

func TestGenerateIDOrderNotMatter(t *testing.T) {
	ps1 := &compiler.PSvc{
		Path:      "/foo",
		ServiceID: "service.foo",
		Type:      compiler.PSvcTDef,
		Endpoints: []string{"tcp/100"},
	}
	ps2 := &compiler.PSvc{
		Path:      "/fee",
		ServiceID: "service.fee",
		Type:      compiler.PSvcTDef,
		Endpoints: []string{"tcp/200"},
	}

	as1 := &compiler.AttrExprSet{
		AttrExprs: []*doc.AttrExpr{
			makeAttrExpr("foo", "eq", "fee"),
			makeAttrExpr("okey", "eq", "dokey"),
		},
		Provider: true,
		Provides: []*compiler.PSvc{ps1, ps2},
	}
	as2 := &compiler.AttrExprSet{
		AttrExprs: []*doc.AttrExpr{
			makeAttrExpr("okey", "eq", "dokey"),
			makeAttrExpr("foo", "eq", "fee"),
		},
		Provider: true,
		Provides: []*compiler.PSvc{ps2, ps1},
	}
	as1.GenerateID()
	as2.GenerateID()
	require.Equal(t, as1.ID, as2.ID)
	require.Equal(t, as1.Hash, as2.Hash)
}

func TestGenerateIDNoticeNode(t *testing.T) {
	as1 := &compiler.AttrExprSet{
		AttrExprs: []*doc.AttrExpr{
			makeAttrExpr("foo", "eq", "fee"),
		},
		Node: true,
	}
	as2 := &compiler.AttrExprSet{
		AttrExprs: []*doc.AttrExpr{
			makeAttrExpr("foo", "eq", "fee"),
		},
		Node: false,
	}
	as1.GenerateID()
	as2.GenerateID()
	require.NotEqual(t, as1.ID, as2.ID)
	require.Equal(t, as1.Hash, as2.Hash) // AttrExprs are still the same
}

func TestGenerateIDIgnoresProviderFlag(t *testing.T) {
	as1 := &compiler.AttrExprSet{
		AttrExprs: []*doc.AttrExpr{
			makeAttrExpr("foo", "eq", "fee"),
		},
		Provider: true,
	}
	as2 := &compiler.AttrExprSet{
		AttrExprs: []*doc.AttrExpr{
			makeAttrExpr("foo", "eq", "fee"),
		},
		Provider: false,
	}
	as1.GenerateID()
	as2.GenerateID()
	require.Equal(t, as1.ID, as2.ID)
	require.Equal(t, as1.Hash, as2.Hash)
}
