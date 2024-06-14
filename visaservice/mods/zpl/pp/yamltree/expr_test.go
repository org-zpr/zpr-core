package yamltree_test

import (
	"math"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	y "zpr.org/vsx/zpl/pp/yamltree"
)

func TestNewExpressionParseEmpty(t *testing.T) {
	expr, err := y.NewExpression(``)
	require.Error(t, err)
	require.Nil(t, expr)
}

func TestNewExpressionParseNull(t *testing.T) {
	expr, err := y.NewExpression(`null`)
	require.NoError(t, err)
	require.NotEmpty(t, expr)
}

func TestNewExpressionParseBool(t *testing.T) {
	for _, text := range []string{"true", "false", " true", "\t false"} {
		expr, err := y.NewExpression(text)
		require.NoError(t, err, text)
		require.NotEmpty(t, expr, text)
	}
}

func TestNewExpressionParseNumber(t *testing.T) {
	for _, text := range []string{"0", "-1", " +1.5 ", "2.", " 3_628_800e0 ", "\t1.602e-19"} {
		expr, err := y.NewExpression(text)
		require.NoError(t, err, text)
		require.NotEmpty(t, expr, text)
	}
}

func TestNewExpressionParseDoubleQuotes(t *testing.T) {
	for _, text := range []string{`""`, `"x"`, `  "x y" `, ` "x \"y\" \\z" `} {
		expr, err := y.NewExpression(text)
		require.NoError(t, err, text)
		require.NotEmpty(t, expr, text)
	}
}

func TestNewExpressionParseSingleQuotes(t *testing.T) {
	for _, text := range []string{`"a" =~ ''`, `"a" =~ 'x'`, `"a" =~   'x y' `, `"a" =~ 'x ''y'' z' `} {
		expr, err := y.NewExpression(text)
		require.NoError(t, err, text)
		require.NotEmpty(t, expr, text)
	}
}

func TestNewExpressionParsePathExpression(t *testing.T) {
	for _, text := range []string{`.`, `foo`, ` .* `, `foo.bar`, ` .foo."bar.baz" `, ` foo.@@$*z `} {
		expr, err := y.NewExpression(text)
		require.NoError(t, err, text)
		require.NotEmpty(t, expr, text)
	}
}

func TestNewExpressionParseRelop(t *testing.T) {
	for _, text := range []string{`0==1`, ` 0 == 1 `, `0!=1`, ` 0 < 1 `, `0 <= 1`, `0 > 1`, `0>=1`} {
		expr, err := y.NewExpression(text)
		require.NoError(t, err, text)
		require.NotEmpty(t, expr, text)
	}
}

func TestNewExpressionParseComposites(t *testing.T) {
	for _, text := range []string{
		`foo.bar == 1`,
		`a + b + c + d * e - f - g`,
		`all(foo.@@.bar > 0) and not any(bar.foo[**]$<17)`,
		`-(@@$'^foo.*' + 1)/5 - 2^3^4//17`,
		`(foo(bar) + $x)^(abc(def) - $y) / (1 + 2/(3%4))`,
		`foo.{bar}baz =~ 'x(.*)z' and $1 == "y" or foo.!{bar}baz !~ '1.*2'`,
		`0 <= $x == $y < 1`,
		`[a + b + c + d * e - f - g for a in [1, 2] for bbbb in foo.* for c in [0]]`,
		`count([all($x.a.b > 0) and any($y[*] == "abc") for x in foo.bar[*] for y in qux.*])`,
		`true ? 1 : 0`,
		`foo ? 1 : bar ? 2 : 3`,
		`let x = 1 in $x`,
		`let x = 1 in let y = $x + 1 in $y * 2`,
	} {
		expr, err := y.NewExpression(text)
		require.NoError(t, err, text)
		require.NotEmpty(t, expr, text)
	}
}

func TestNewExpressionUnparsable(t *testing.T) {
	for _, text := range []string{
		`== 1`,
		`1 +`,
		`"x" =~`,
		`"`,
		`'`,
		`not`,
		`2 + (`,
		`()`,
		`(,)`,
		`all(+)`,
		`x for`,
		`x for y`,
		`x for y in`,
		`x ?`,
		`x ? 1`,
		`x ? 1 :`,
		`let`,
		`let x`,
		`let x =`,
		`let x = 1`,
		`let x = 1 in`,
	} {
		_, err := y.NewExpression(text)
		require.Error(t, err, text)
	}
}

func TestExpressionSymbols(t *testing.T) {
	type item struct {
		expr  string
		value []string
	}
	for _, item := range []item{
		{`one.two == 1`, []string{}},
		{`$one + two == 1`, []string{"one"}},
		{"f($one + 2) + $two == 1", []string{"one", "two"}},
		{"$one + $two * $one - num($three =~ '(.*)(.)e' ? f($2) : f(0) + g($1)) == 1", []string{"1", "2", "one", "three", "two"}},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		require.Equal(t, item.value, expr.Symbols(), item.expr)
	}
}

func TestExpressionFunctions(t *testing.T) {
	type item struct {
		expr  string
		value []string
	}
	for _, item := range []item{
		{`one.two == 1`, []string{}},
		{"f($one + 2) + $two == 1", []string{"f"}},
		{"$one + $two * f($one - num($three =~ '(.*)(.)e' ? f($2) : f(0) + g($1))) == 1", []string{"f", "g", "num"}},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		require.Equal(t, item.value, expr.Functions(), item.expr)
	}
}

func TestEvalScalarLiteral(t *testing.T) {
	type item struct {
		expr  string
		value interface{}
	}
	for _, item := range []item{
		{"null", nil},
		{"true", true},
		{"1", 1.},
		{`"abc"`, "abc"},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalVectorLiteral(t *testing.T) {
	type item struct {
		expr  string
		value []interface{}
	}
	for _, item := range []item{
		{`[]`, []interface{}{}},
		{`[1, 2]`, []interface{}{1., 2.}},
		{`["x", 0.5, "y"]`, []interface{}{"x", 0.5, "y"}},
		{`[1, [2, 3], [4, [5, 6]]]`, []interface{}{1., 2., 3., 4., 5., 6.}},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalTopLevelInvalid(t *testing.T) {
	for _, e := range []string{"", "'.*'", "0, 1"} {
		_, err := y.NewExpression(e)
		require.Error(t, err, e)
	}
}

func TestEvalScalarAddSub(t *testing.T) {
	type item struct {
		expr  string
		value interface{}
	}
	for _, item := range []item{
		{"1+2", 3.},
		{"-1+2", 1.},
		{"1+-2", -1.},
		{"-1--2", 1.},
		{"-1 - -2", 1.},
		{"1 + -(2.5 + 3) - ((4))", -8.5},
		{`""+"x"`, "x"},
		{`"abc" + "123"`, "abc123"},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalVectorAddSub(t *testing.T) {
	type item struct {
		expr  string
		value []interface{}
	}
	for _, item := range []item{
		{"[1, 2] + [3, 4]", []interface{}{4., 6.}},
		{"[1, 2] - 3", []interface{}{-2., -1.}},
		{"1 + [2, 3]", []interface{}{3., 4.}},
		{"1 + [-1]", []interface{}{0.}},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalScalarMulDiv(t *testing.T) {
	type item struct {
		expr  string
		value interface{}
	}
	for _, item := range []item{
		{"2*3", 6.},
		{"-2*+3", -6.},
		{"2*3*-4", -24.},
		{"3/2", 1.5},
		{"3/2*2", 3.},
		{"24/(2*3)*4/8", 2.},
		{"9//2", 4.},
		{"9//-2", -5.},
		{"3*3//2", 4.},
		{"3*3//2", 4.},
		{"10.1//3.3", 3.},
		{"2.3//1", 2.},
		{"9%2", 1.},
		{"9%-2", -1.},
		{"25%2.5", 0.},
		{"21%2.5", 1.},
		{"3/0", math.Inf(1)},
		{"-3/0", math.Inf(-1)},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalVectorMulDiv(t *testing.T) {
	type item struct {
		expr  string
		value []interface{}
	}
	for _, item := range []item{
		{"[1, 2] * [3, 4]", []interface{}{3., 8.}},
		{"[1, 3] / -2", []interface{}{-0.5, -1.5}},
		{"5 * [2, 3]/[1, 2]", []interface{}{10., 7.5}},
		{"0 * [-1]", []interface{}{0.}},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalScalarPow(t *testing.T) {
	type item struct {
		expr  string
		value interface{}
	}
	for _, item := range []item{
		{"2^3", 8.},
		{"-2^+8", 256.},
		{"-2^-3", -0.125},
		{"2^3^4", math.Pow(2, math.Pow(3, 4))},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalVectorPow(t *testing.T) {
	type item struct {
		expr  string
		value []interface{}
	}
	for _, item := range []item{
		{"[2, 3]^[4, 2]", []interface{}{16., 9.}},
		{"([2, 3]^[4, 2])^0.5", []interface{}{4., 3.}},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalScalarRelop(t *testing.T) {
	type item struct {
		expr  string
		value interface{}
	}
	for _, item := range []item{
		{`2 == 2`, true},
		{`2 == 3`, false},
		{`2 != 2`, false},
		{`2 != 3`, true},
		{`"ab" == "ab"`, true},
		{`"ab" == "ac"`, false},
		{`"ab" != "ab"`, false},
		{`"ab" != "ac"`, true},
		{`false == false`, true},
		{`false == true`, false},
		{`false != false`, false},
		{`false != true`, true},
		{`2 < 2`, false},
		{`2 < 3`, true},
		{`3 < 2`, false},
		{`"ab" < "ab"`, false},
		{`"ab" < "ac"`, true},
		{`"ac" < "ab"`, false},
		{`2 <= 3`, true},
		{`3 <= 2`, false},
		{`3 <= 3`, true},
		{`"ab" <= "ab"`, true},
		{`"ab" <= "ac"`, true},
		{`"ac" <= "ab"`, false},
		{`2 > 3`, false},
		{`3 > 2`, true},
		{`3 > 3`, false},
		{`"ab" > "ab"`, false},
		{`"ab" > "ac"`, false},
		{`"ac" > "ab"`, true},
		{`2 >= 3`, false},
		{`3 >= 2`, true},
		{`3 >= 3`, true},
		{`"ab" >= "ab"`, true},
		{`"ab" >= "ac"`, false},
		{`"ac" >= "ab"`, true},
		{`2 == 2 < 3`, true},
		{`2 < 2 < 3`, false},
		{`2 < 3 == 3`, true},
		{`2 < 3 == 3 <= 4 > 0`, true},
		{`2 < 3 == 3 <= 2 > 0`, false},
		{`"abc" >= "abb" > "ab" == "ab" < "aba"`, true},
		{`"abc" >= "abb" > "ab" != "ab" < "aba"`, false},
		{`null == null`, true},
		{`null == 0`, false},
		{`null != null`, false},
		{`null != 0`, true},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalScalarRelopInvalid(t *testing.T) {
	for _, s := range []string{
		`"x" < 0`,
		`true == 1`,
		`'.*' == ".*"`,
		`'.*' == '.*'`,
		`0 < true`,
		`0 <= true`,
		`"x" > 1`,
		`"x" >= 1`,
		`null < 0`,
		`null < null`,
		`null >= null`,
	} {
		expr, err := y.NewExpression(s)
		require.NoError(t, err, s)
		_, err = expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.Error(t, err, s)
	}
}

func TestEvalMatchingOps(t *testing.T) {
	type item struct {
		expr  string
		value interface{}
	}
	for _, item := range []item{
		{`"abc" =~ '.b.'`, true},
		{`"abc" !~ '.b.'`, false},
		{`"one fish two fish" =~ '(\w+) fish (\w+) fish' and $1 + " " + $2 == "one two"`, true},
		{`"one fish two fish" =~ '(\w+) fish (\w+) fish' and "xyz" =~ '(.).(.)' and $1 + " " + $2 == "x z"`, true},
		{`"one" =~ 'o(.)e' and "two" !~ 't(.)x' and $1 == "n"`, true},
		{`"one" =~ 'o(.)e' and not ("two" !~ 't(.)o') and $1 == "w"`, true},
		{`["one", "two", "three"] =~ ['o', 'o', 'o']`, []interface{}{true, true, false}},
		{`all(["one", "two"] =~ ['o(.)e', 't(.)x'] == [true, false]) and $1 == "n"`, true},
		{`all(["one", "two"] =~ ['o(.)e', 't(.)o'] == [true, true]) and $1 == "w"`, true},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalBooleanOps(t *testing.T) {
	type item struct {
		expr  string
		value interface{}
	}
	for _, item := range []item{
		{`true or false`, true},
		{`true and false`, false},
		{`2 < 3 and 3 < 4`, true},
		{`2 < 1 and 3 < 4 or 3 < 4`, true},
		{`not true`, false},
		{`not false`, true},
		{`not not true`, true},
		{`not not not false`, true},
		{`not (2 < 3)`, false},
		{`not (3 < 2)`, true},
		{`(not true and not false) == not(true or false)`, true},
		{`false and "not-a-number" == 0`, false},
		{`true or "not-a-number" == 0`, true},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalTernaryOp(t *testing.T) {
	type item struct {
		expr  string
		value interface{}
	}
	for _, item := range []item{
		{`false ? 1 : 0`, 0.},
		{`true ? 1 : 0`, 1.},
		{`1 < 2 ? "yes" : "no"`, "yes"},
		{`1 > 2 ? "yes" : "no"`, "no"},
		{`1 < 2 and 3 < 4 ? 5 + 6 : 7 < 8 or 9 < 10 ? 11 + 12 : null`, 11.},
		{`1 < 2 and 3 > 4 ? 5 + 6 : 7 < 8 or 9 < 10 ? 11 + 12 : null`, 23.},
		{`1 < 2 and 3 > 4 ? 5 + 6 : 7 > 8 or 9 > 10 ? 11 + 12 : null`, nil},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalLetExpression(t *testing.T) {
	type item struct {
		expr  string
		value interface{}
	}
	for _, item := range []item{
		{`let x = 1 in $x`, 1.},
		{`1 + (let x = 1 in $x)`, 2.},
		{`(let x = 1 in $x) + 1`, 2.},
		{`let x = 3 in (let y = 2 * $x in $y + 1)`, 7.},
		{`let x = 3 in let y = 2 * $x in $y + 1`, 7.},
		{`let x = [3, 1, 4] in sum($x)`, 8.},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalBuiltins(t *testing.T) {
	type item struct {
		expr  string
		value interface{}
	}
	for _, item := range []item{
		{`any()`, false},
		{`any(false)`, false},
		{`any(true)`, true},
		{`any(false, false)`, false},
		{`any([false, false])`, false},
		{`any(true, false, false)`, true},
		{`any(false, false, true)`, true},
		{`any(false, false, true)`, true},
		{`any([false, false, true])`, true},
		{`all()`, true},
		{`all(false)`, false},
		{`all(true)`, true},
		{`all(false, false)`, false},
		{`all(true, false, true)`, false},
		{`all([true, false, true])`, false},
		{`all(true, true, true)`, true},
		{`all([true, true, true])`, true},
		{`count(false)`, 0.},
		{`count(true)`, 1.},
		{`count([])`, 0.},
		{`count([false])`, 0.},
		{`count([false, false])`, 0.},
		{`count([false, true, false])`, 1.},
		{`count([false, true, true])`, 2.},
		{`len()`, 0.},
		{`len(3)`, 1.},
		{`len(0, 0, 0)`, 3.},
		{`len([0, 0, 0])`, 3.},
		{`len(n[*])`, 4.},
		{`len(["x", "x", "x"])`, 3.},
		{`min(3)`, 3.},
		{`min(2, 7, 1, 8, 2, 8)`, 1.},
		{`min([2, 7, 1, 8, 2, 8])`, 1.},
		{`min(n[*])`, 0.},
		{`max(3)`, 3.},
		{`max(2, 7, 1, 8, 2, 8)`, 8.},
		{`max([2, 7, 1, 8, 2, 8])`, 8.},
		{`max(n[*])`, 3.},
		{`sum()`, 0.},
		{`sum(3)`, 3.},
		{`sum(3, 1, 4)`, 8.},
		{`sum([3, 1, 4])`, 8.},
		{`sum(n[*])`, 6.},
		{`exists()`, false},
		{`exists("x")`, true},
		{`exists("x", "x")`, true},
		{`exists(["x", "x"])`, true},
		{`exists(n[*])`, true},
		{`split(" ", "")`, []interface{}{""}},
		{`split(" ", "one")`, []interface{}{"one"}},
		{`split(" ", "one two red blue")`, []interface{}{"one", "two", "red", "blue"}},
		{`split(" ", "one two red blue", -1)`, []interface{}{"one", "two", "red", "blue"}},
		{`split(" ", "one two red blue", 3)`, []interface{}{"one", "two", "red blue"}},
		{`split('n', "")`, []interface{}{""}},
		{`split('n', "one")`, []interface{}{"o", "e"}},
		{`split('e..', "one two red blue")`, []interface{}{"on", "wo r", "blue"}},
		{`split('e..', "one two red blue", -1)`, []interface{}{"on", "wo r", "blue"}},
		{`split('e..', "one two red blue", 2)`, []interface{}{"on", "wo red blue"}},
		{`join(" ")`, ""},
		{`join(" ", "x")`, "x"},
		{`join(" ", "1", 2, 1+2)`, "1 2 3"},
		{`join(" ", [])`, ""},
		{`join("--", ["a", "b", "c"])`, "a--b--c"},
		{`sort()`, []interface{}{}},
		{`sort(2, 7, 1, 8, 2, 8)`, []interface{}{1., 2., 2., 7., 8., 8.}},
		{`sort([2, 7, 1, 8, 2, 8])`, []interface{}{1., 2., 2., 7., 8., 8.}},
		{`sort(null, null)`, []interface{}{nil, nil}},
		{`sort([true, false, true, false])`, []interface{}{false, false, true, true}},
		{`sort(["one", "two", "red", "blue"])`, []interface{}{"blue", "one", "red", "two"}},
		{`sort(["foo", 29, "bar", n[2], true, null, n[1], false, 17, 29, "foo"])`, []interface{}{nil, false, true, 1., 2., 17., 29., 29., "bar", "foo", "foo"}},
		{`uniq()`, []interface{}{}},
		{`uniq(2, 7, 1, 8, 2, 8)`, []interface{}{1., 2., 7., 8.}},
		{`uniq([2, 7, 1, 8, 2, 8])`, []interface{}{1., 2., 7., 8.}},
		{`uniq(null, null)`, []interface{}{nil}},
		{`uniq([true, false, true, false])`, []interface{}{false, true}},
		{`uniq(["one", "two", "red", "blue"])`, []interface{}{"blue", "one", "red", "two"}},
		{`uniq(["foo", 29, "bar", n[2], true, null, n[1], false, 17, 29, "foo"])`, []interface{}{nil, false, true, 1., 2., 17., 29., "bar", "foo"}},
		{`str(1)`, "1"},
		{`str(1.5)`, "1.5"},
		{`str(1, 2, 3)`, []interface{}{"1", "2", "3"}},
		{`str([1, 2, 3])`, []interface{}{"1", "2", "3"}},
		{`str(n[*])`, []interface{}{"0", "1", "2", "3"}},
		{`num("1")`, 1.},
		{`num("1", "2", "3")`, []interface{}{1., 2., 3.}},
		{`num(["1", "2", "3"])`, []interface{}{1., 2., 3.}},
		{`num(n[*])`, []interface{}{0., 1., 2., 3.}},
		{`abs(2)`, 2.},
		{`abs(-2)`, 2.},
		{`abs([1, -2, 3, -4])`, []interface{}{1., 2., 3., 4.}},
		{`int(1.5)`, 2.},
		{`int(2.5, -2.5)`, []interface{}{3., -3.}},
		{`int([2.5, -2.5])`, []interface{}{3., -3.}},
		{`int(n[*])`, []interface{}{0., 1., 2., 3.}},
		{`value(3)`, 3.},
		{`value([3, 1, 4])`, []interface{}{3., 1., 4.}},
		{`value(n[*])`, []interface{}{0., 1., 2., 3.}},
	} {
		root, _ := y.ReadYamlFromString("n: [0, 1, 2, 3]", "")
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(y.NewBasicContextOk(root, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalBuiltinsInvalid(t *testing.T) {
	for _, s := range []string{
		`any(0)`,
		`any("x")`,
		`all(0)`,
		`all("x")`,
		`min()`,
		`min("x")`,
		`max("x")`,
		`sum("x")`,
		`num("x")`,
		`int(true)`,
		`key(0)`,
		`source(0)`,
		`str()`,
		`split()`,
		`split(",")`,
		`split(",", "a,b", "x")`,
		`join()`,
	} {
		expr, err := y.NewExpression(s)
		require.NoError(t, err, s)
		_, err = expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.Error(t, err, s)
	}
}

func TestEvalSetOps(t *testing.T) {
	type item struct {
		expr  string
		value interface{}
	}
	for _, item := range []item{
		{`[] union []`, []interface{}{}},
		{`[0] union [0]`, []interface{}{0.}},
		{`[0, 1] union [1, 2, 3]`, []interface{}{0., 1., 2., 3.}},
		{`["one", "fish"] union ["two", "fish"]`, []interface{}{"fish", "one", "two"}},
		{`[1, "fish"] union [2, "fish"]`, []interface{}{1., 2., "fish"}},
		{`[1, "fish"] union [2, "fish"]`, []interface{}{1., 2., "fish"}},
		{`[] intersect []`, []interface{}{}},
		{`[0] intersect [0]`, []interface{}{0.}},
		{`[0, 1] intersect [1, 2, 3]`, []interface{}{1.}},
		{`["one", "fish"] intersect ["two", "fish"]`, []interface{}{"fish"}},
		{`[1, "fish", 2, "red", "blue"] intersect ["black", "blue", "fish", 2, 3]`, []interface{}{2., "blue", "fish"}},
		{`[] minus []`, []interface{}{}},
		{`[0] minus [0]`, []interface{}{}},
		{`[0, 1] minus [1, 2, 3]`, []interface{}{0.}},
		{`["one", "fish", "two"] minus ["one", "two"]`, []interface{}{"fish"}},
		{`[1, "fish", 2, "red", "blue"] minus ["blue", 2, 3]`, []interface{}{1., "fish", "red"}},
		{`[] equals []`, true},
		{`[0] equals [0]`, true},
		{`[0, 1] equals [0]`, false},
		{`[0, 1] equals [1, 0]`, true},
		{`[0, 1] equals [0, 2]`, false},
		{`[0, 1, 2, 3] equals [3, 1, 0, 2]`, true},
		{`[] contains []`, true},
		{`[0] contains [0]`, true},
		{`[0, 1] contains [0]`, true},
		{`[0, 1] contains [1]`, true},
		{`[0, 1] contains [1, 2]`, false},
		{`[0, 1, 2, 3] contains [3, 1]`, true},
		{`["one", "fish", "two", "fish"] contains ["one", "two"]`, true},
		{`[1, "fish", 2, "red", "blue"] contains ["red", 1]`, true},
		{`["a", "b", "c", "d"] union ["c", "d", "e"] intersect ["d", "e", "f"] minus "c"`, []interface{}{"a", "b", "d", "e"}},
		{`["a", "b", "c", "d"] union ["c", "d", "e"] intersect ["d", "e", "f"] minus "c" union "d"`, []interface{}{"a", "b", "e"}},
		{`["a", "b", "c", "d"] union ["c", "d", "e"] intersect ["d", "e", "f"] minus "c" union "d" contains ["a", "b"]`, true},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(y.NewBasicContextOk(nil, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalExternalSymbols(t *testing.T) {
	root, _ := y.ReadYamlFromString("{s: 17., m: {x: 17}}", "")
	scalarNode := y.MatchingPaths(root, y.NewPathPatternOk("s"))[0][1]
	mappingNode := y.MatchingPaths(root, y.NewPathPatternOk("m"))[0][1]
	symtab := map[string]interface{}{"zip": nil, "foo": 1., "bar": "text", "scalar_node": scalarNode, "mapping_node": mappingNode}
	expr, err := y.NewExpression("[0, $zip, $foo, $bar, $scalar_node, $mapping_node]")
	require.NoError(t, err)
	val, err := expr.Evaluate(y.NewBasicContextOk(root, &y.BasicContextOptions{Symbols: symtab}))
	require.NoError(t, err)
	require.Exactly(t, []interface{}{0., nil, 1., "text", scalarNode, mappingNode}, val)
}

func TestEvalExternalSymbolsInvalid(t *testing.T) {
	for _, s := range []string{"", "0", "0foo", "foo.bar"} {
		expr, _ := y.NewExpression("true")
		_, err := expr.Evaluate(y.NewBasicContextOk(nil, &y.BasicContextOptions{Symbols: map[string]interface{}{s: 0.}}))
		require.Error(t, err, s)
	}
}

func TestEvalExternalFunctions(t *testing.T) {
	addemup := func(ctx y.EvaluationContext, arg interface{}) (interface{}, error) {
		sum := 0.
		for _, a := range arg.([]interface{}) {
			sum += a.(float64)
		}
		return sum, nil
	}
	functab := map[string]interface{}{"addemup": y.GeneralFunction(addemup)}
	expr, err := y.NewExpression("addemup(3, 1, 4, 1, 5, 9)")
	require.NoError(t, err)
	val, err := expr.Evaluate(y.NewBasicContextOk(nil, &y.BasicContextOptions{Functions: functab}))
	require.NoError(t, err)
	require.Exactly(t, 23., val)
}

func TestEvalExternalFunctionsInvalid(t *testing.T) {
	dummyFunc := func(y.EvaluationContext, interface{}) (interface{}, error) { return 0., nil }
	for _, f := range []string{"", "0", "0foo", "foo.bar"} {
		expr, _ := y.NewExpression("true")
		_, err := expr.Evaluate(y.NewBasicContextOk(nil, &y.BasicContextOptions{Functions: map[string]interface{}{f: y.GeneralFunction(dummyFunc)}}))
		require.Error(t, err, f)
	}
}

func TestEvalPathPatterns(t *testing.T) {
	yaml := `
        one:
            red:
                - r0
                - r1
                - r2
            green: ~
        two:
            - - 100
              - 101
            - - 110
              - 111
            - - 120
              - 121
    `

	root, err := y.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	require.Equal(t, y.MappingKind, root.Kind())

	lastNode := func(path []y.Node) y.Node { return path[len(path)-1] }

	red := lastNode(y.MatchingPaths(root, y.NewPathPatternOk("one.red"))[0])
	green := lastNode(y.MatchingPaths(root, y.NewPathPatternOk("one.green"))[0])

	ctx := y.NewBasicContextOk(root, nil)

	type item struct {
		expr  string
		value interface{}
	}

	for _, item := range []item{
		{`one.red`, []interface{}{red}},
		{`len(.*)`, 2.},
		{`one.green`, []interface{}{green}},
		{`value(one.green)`, []interface{}{nil}},
		{`value(one.red[*])`, []interface{}{"r0", "r1", "r2"}},
		{`one.red[*] + "x"`, []interface{}{"r0x", "r1x", "r2x"}},
		{`two.@@$ - 100 `, []interface{}{0., 1., 10., 11., 20., 21.}},
		{`-two[2][*]`, []interface{}{-120., -121.}},
		{`two[2][*] + 10`, []interface{}{130., 131.}},
		{`[two[2][*] - two[0][*]]^2`, []interface{}{400., 400.}},
		{`three.*`, []interface{}{}},
		{`value([one.red[*], two[0][*]])`, []interface{}{"r0", "r1", "r2", 100., 101.}},
		{`key(one.red)`, []interface{}{"red"}},
		{`key(one.red[0])`, []interface{}{nil}},
		{`split("0", two[0][1])`, []interface{}{"1", "1"}},
		{`join(",", one.red[*])`, "r0,r1,r2"},
		{`let x = one.red[*] in join(",", $x)`, "r0,r1,r2"},
		{`sort([key($n) for n in one.*])`, []interface{}{"green", "red"}},
		{`source(one.red)`, []interface{}{"testfile:4:17"}},
		{`sort([source($n) for n in one.red[*]])`, []interface{}{"testfile:4:19", "testfile:5:19", "testfile:6:19"}},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(ctx)
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}

	two := lastNode(y.MatchingPaths(root, y.NewPathPatternOk("two"))[0])
	ctx = y.NewBasicContextOk(root, &y.BasicContextOptions{YamlRef: two})

	for _, item := range []item{
		{`num(@@$)`, []interface{}{100., 101., 110., 111., 120., 121.}},
		{`num(.[*][*])`, []interface{}{100., 101., 110., 111., 120., 121.}},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		result, err := expr.Evaluate(ctx)
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestEvalFor(t *testing.T) {
	yaml := `
        one:
            red: [r0, r1, r2]
            green: ~
        two:
            - [100, 101]
            - [110, 111]
        three:
            - x: [200, 201]
              y: [210, 211]
            - x: [300, 301]
              y: [320, 321]
    `

	root, err := y.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	require.Equal(t, y.MappingKind, root.Kind())

	type item struct {
		expr  string
		value interface{}
	}

	for _, item := range []item{
		{`[$x for x in [1]]`, []interface{}{1.}},
		{`[$x for x in [1, 2, 3, 4]]`, []interface{}{1., 2., 3., 4.}},
		{`[$x for x in [1, 2, 3, 4] if $x%2 == 1]`, []interface{}{1., 3.}},
		{`[$x + $y for x in [1] for y in [2]]`, []interface{}{3.}},
		{`[$x + $y for x in [1, 2] for y in [5, 10] if $x * $y < 20]`, []interface{}{6., 11., 7.}},
		{`[$x + $y for x in [1, 2] if $x%2 == 0 for y in [5, 10] if $x * $y < 20]`, []interface{}{7.}},
		{`[value($x) for x in one.red.@@$]`, []interface{}{"r0", "r1", "r2"}},
		{`[value($x) for x in one.green]`, []interface{}{nil}},
		{`sum([$x for x in two[**]$])`, 422.},
		{`[value($x[0]) for x in two[*]]`, []interface{}{100., 110.}},
		{`[$x + "-" + str($y[1]) for x in one.red[*] for y in two[*]]`,
			[]interface{}{"r0-101", "r0-111", "r1-101", "r1-111", "r2-101", "r2-111"}},
		{`[$x + "-" + str($y[1]) for x in one.red[*] if $x =~ 'r[12]' for y in two[*] if $y[1] < 110]`,
			[]interface{}{"r1-101", "r2-101"}},
		{`[all($x[*] == ["r0", "r1", "r2"]) for x in one.red]`, []interface{}{true}},
		{`[len($x[*]) for x in two[*]]`, []interface{}{2., 2.}},
		{`any([len($x[*]) == 2 and all($x[*]%100 == [10, 11]) for x in two[*]])`, true},
		{`[$y - 100 for x in two[*] for y in $x[1]]`, []interface{}{1., 11.}},
		{`[$w[*] - $v[*] for u in three[*] for v in $u.x for w in $u.y]`, []interface{}{10., 10., 20., 20.}},
		{`[$w[*] - $v[*] for u in three[*] for v in $u.x if $v[0] >= 300 for w in $u.y]`, []interface{}{20., 20.}},
		{`[value($w) for u in three[*] for v in [$u.x, $u.y] for w in $v[*]]`,
			[]interface{}{200., 201., 210., 211., 300., 301., 320., 321.}},
		{`[$1 for x in ["one" =~ 'o(.)e']]`, []interface{}{"n"}},
	} {
		expr, err := y.NewExpression(item.expr)
		require.NoError(t, err, item)
		// expr.Dump(os.Stdout)
		result, err := expr.Evaluate(y.NewBasicContextOk(root, nil))
		require.NoError(t, err, item)
		require.Exactly(t, item.value, result, item)
	}
}

func TestNodeAccessLogging(t *testing.T) {
	yaml := `{foo: [12, 34]}`

	root, err := y.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	require.Equal(t, y.MappingKind, root.Kind())

	paths := y.MatchingPaths(root, y.NewPathPatternOk("foo[*]"))

	log := y.AppendingNodeAccessLogger{}
	ctx := y.NewBasicContextOk(root, &y.BasicContextOptions{NodeLogger: &log})

	expr, err := y.NewExpression("sum(foo[*])")
	require.NoError(t, err)

	_, err = expr.Evaluate(ctx)
	require.NoError(t, err)
	require.Equal(t, 2, len(log.Records))
	require.Equal(t, paths[0], log.Records[0].Path)
	require.Equal(t, paths[1], log.Records[1].Path)
}

func TestEvalTracing(t *testing.T) {
	yaml := `{foo: [12, 34]}`

	root, err := y.ReadYamlFromString(yaml, "testfile")
	require.NoError(t, err)
	require.Equal(t, y.MappingKind, root.Kind())

	tracer := strings.Builder{}
	ctx := y.NewBasicContextOk(root, &y.BasicContextOptions{EvalTracer: &tracer})

	expr, err := y.NewExpression("sum(foo[*])")
	require.NoError(t, err)

	_, err = expr.Evaluate(ctx)
	require.NoError(t, err)
	require.Regexp(t, `(?s)foo\[\*\].*sum`, tracer.String())
}
