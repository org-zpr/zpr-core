package yamltree_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	y "zpr.org/vsx/zpl/pp/yamltree"
)

func TestParseSingleQuoteString0(t *testing.T) {
	s, n, err := y.ParseSingleQuoteString(``, 0)
	require.NoError(t, err)
	require.Equal(t, ``, s)
	require.Equal(t, 0, n)
}

func TestParseSingleQuoteString1(t *testing.T) {
	s, n, err := y.ParseSingleQuoteString(`''`, 0)
	require.NoError(t, err)
	require.Equal(t, ``, s)
	require.Equal(t, 2, n)
}

func TestParseSingleQuoteString2(t *testing.T) {
	s, n, err := y.ParseSingleQuoteString(`'x'`, 0)
	require.NoError(t, err)
	require.Equal(t, `x`, s)
	require.Equal(t, 3, n)
}

func TestParseSingleQuoteString3(t *testing.T) {
	s, n, err := y.ParseSingleQuoteString(`--'x ''y'' z'--`, 2)
	require.NoError(t, err)
	require.Equal(t, `x 'y' z`, s)
	require.Equal(t, 11, n)
}

func TestParseSingleQuoteString4(t *testing.T) {
	_, _, err := y.ParseSingleQuoteString(`'xyz`, 0)
	require.Error(t, err)
}

func TestParseDoubleQuoteString0(t *testing.T) {
	s, n, err := y.ParseDoubleQuoteString(``, 0)
	require.NoError(t, err)
	require.Equal(t, ``, s)
	require.Equal(t, 0, n)
}

func TestParseDoubleQuoteString1(t *testing.T) {
	s, n, err := y.ParseDoubleQuoteString(`""`, 0)
	require.NoError(t, err)
	require.Equal(t, ``, s)
	require.Equal(t, 2, n)
}

func TestParseDoubleQuoteString2(t *testing.T) {
	s, n, err := y.ParseDoubleQuoteString(`"x"`, 0)
	require.NoError(t, err)
	require.Equal(t, `x`, s)
	require.Equal(t, 3, n)
}

func TestParseDoubleQuoteString3(t *testing.T) {
	s, n, err := y.ParseDoubleQuoteString(`--"x \"y\" \\\:z"--`, 2)
	require.NoError(t, err)
	require.Equal(t, `x "y" \:z`, s)
	require.Equal(t, 15, n)
}

func TestParseDoubleQuoteString4(t *testing.T) {
	_, _, err := y.ParseDoubleQuoteString(`"xyz`, 0)
	require.Error(t, err)
}

func TestParseDoubleQuoteString5(t *testing.T) {
	_, _, err := y.ParseDoubleQuoteString(`"xyz\`, 0)
	require.Error(t, err)
}

func TestSnippet0(t *testing.T) {
	require.Equal(t, "", y.Snippet("", 0, 5))
}

func TestSnippet1(t *testing.T) {
	require.Equal(t, "abc", y.Snippet("abc", 0, 5))
}

func TestSnippet2(t *testing.T) {
	require.Equal(t, "ab...", y.Snippet("abcdef", 0, 5))
}

func TestSnippet3(t *testing.T) {
	require.Equal(t, "...def", y.Snippet("abcdef", 3, 10))
}

func TestSnippet4(t *testing.T) {
	require.Equal(t, "...defg...", y.Snippet("abcdefghijkl", 3, 10))
}
