package doc_test

import (
	"testing"

	"github.com/stretchr/testify/require"
  "zpr.org/vsx/zpl/doc"
)

func zplString(s string) doc.ZplString {
	if z, err := doc.NewZplString(s); err != nil {
		panic(err)
	} else {
		return z
	}
}

func TestScopingString(t *testing.T) {
	require.Equal(t, "TCP/80", (&doc.Scoping{TCP: zplString("80")}).String())
	require.Equal(t, "UDP/31337", (&doc.Scoping{UDP: zplString("31337")}).String())
	{
		s := doc.Scoping{
			ICMP: &doc.ScopeICMP{
				Type:      zplString("foo"),
				TypeCodes: zplString("128"),
			},
		}
		require.Equal(t, "ICMP/128", s.String())
	}
	require.Equal(t, "TCP/5000-5008", (&doc.Scoping{TCP: zplString("5000-5008")}).String())
	require.Equal(t, "UDP/5000-5008", (&doc.Scoping{UDP: zplString("5000-5008")}).String())
	require.Equal(t, "TCP/80,443", (&doc.Scoping{TCP: zplString("80,443")}).String())
}

func TestGetEmptyIDs(t *testing.T) {
	c := &doc.Condition{}
	require.Empty(t, c.GetID())
}

func TestGetIDs(t *testing.T) {
	c := &doc.Condition{
		Desc: zplString("That which is"),
	}
	require.Equal(t, "That-which-is", c.GetID())
	c.ID = zplString("that.which.is")
	require.Equal(t, "that.which.is", c.GetID())

	p := &doc.Policy{
		Desc: zplString("my own policy"),
	}
	require.Equal(t, "my-own-policy", p.GetID())
	p.ID = zplString("foo.foo")
	require.Equal(t, "foo.foo", p.GetID())

	s := &doc.System{
		ID:   zplString("hello-world"),
		Desc: zplString("hello world"),
	}
	require.Equal(t, "hello-world", s.GetID())
	s.ID = zplString("eek.eek")
	require.Equal(t, "eek.eek", s.GetID())
}

func TestGetProvides(t *testing.T) {
	s := &doc.Component{
		Desc: zplString("my service"),
		ID:   zplString("svc.mine"),
	}
	require.Equal(t, "svc.mine", s.GetProvides())
}
