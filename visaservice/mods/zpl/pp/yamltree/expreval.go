package yamltree

import (
	"fmt"
	"io"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"unicode/utf8"
)

// An exprValue represents the value of a (sub)expression.
type exprValue interface {
	// Returns the content of this value.
	content() interface{}

	// Returns the scalar content of this exprValue if it has one. Returns
	// nil and an error otherwise.
	asScalarValue() (*scalarValue, error)

	fmt.Stringer
}

// An exprValue implementation that represents a scalar value, which can be
// nil, bool, float64, string, or *regexp.Regexp.
type scalarValue struct {
	scalar interface{}
}

func (v *scalarValue) content() interface{} {
	return v.scalar
}

func (v *scalarValue) asScalarValue() (*scalarValue, error) {
	return v, nil
}

func (v *scalarValue) String() string {
	return fmt.Sprintf("scalarValue(%v)", v.scalar)
}

// Returns a brief text representation of a scalarValue's content and type.
func (v *scalarValue) summary() string {
	switch s := v.scalar.(type) {
	case nil:
		return "null"
	case bool:
		return fmt.Sprintf("%v (boolean)", s)
	case float64:
		return fmt.Sprintf("%v (number)", s)
	case string:
		return fmt.Sprintf("%q (string)", snippet(s, 0, 20))
	case *regexp.Regexp:
		return fmt.Sprintf("%q (regular expression)", snippet(s.String(), 0, 20))
	default:
		return fmt.Sprintf("%v (%T)", s, s) // "can't happen"
	}
}

// An exprValue implementation that represents a vector value.
type vectorValue struct {
	vector []exprValue
}

func (v *vectorValue) content() interface{} {
	return v.vector
}

func (v *vectorValue) asScalarValue() (*scalarValue, error) {
	return nil, fmt.Errorf("not a scalar: vector")
}

func (v *vectorValue) String() string {
	return fmt.Sprintf("vectorValue(%v)", v.vector)
}

func (v *vectorValue) appendToCopy(xs ...exprValue) *vectorValue {
	newVec := make([]exprValue, len(v.vector), len(v.vector)+len(xs))
	copy(newVec, v.vector)
	newVec = append(newVec, xs...)
	return &vectorValue{newVec}
}

// An exprValue implementation that represents a YAML tree node.
// Records entire path from tree root for full context.
type nodeValue struct {
	path []Node
}

func (v *nodeValue) node() Node {
	return v.path[len(v.path)-1]
}

func (v *nodeValue) content() interface{} {
	return v.node()
}

func (v *nodeValue) asScalarValue() (*scalarValue, error) {
	if v.node().Kind() != ScalarKind {
		return nil, PathErrorf(v.path, "non-scalar (%s) YAML node", v.node().Kind())
	} else if s, err := v.node().DecodedScalarValue(); err != nil {
		return nil, PathErrorf(v.path, "%w", err)
	} else {
		if intValue, isInt := s.(int64); isInt {
			s = float64(intValue)
		}
		return &scalarValue{s}, nil
	}
}

func (v *nodeValue) String() string {
	return fmt.Sprintf("nodeValue(%v)", v.node())
}

// Built-in functions for use in expressions.
var builtinFunctions = map[string]interface{}{
	"any":    GeneralFunction(anyFunc),
	"all":    GeneralFunction(allFunc),
	"count":  GeneralFunction(countFunc),
	"len":    GeneralFunction(lenFunc),
	"min":    GeneralFunction(minFunc),
	"max":    GeneralFunction(maxFunc),
	"sum":    GeneralFunction(sumFunc),
	"exists": GeneralFunction(existsFunc),
	"str":    ScalarFunction(strFunc),
	"num":    ScalarFunction(numFunc),
	"abs":    ScalarFunction(absFunc),
	"value":  ScalarFunction(valueFunc),
	"int":    ScalarFunction(intFunc),
	"split":  GeneralFunction(splitFunc),
	"join":   GeneralFunction(joinFunc),
	"sort":   GeneralFunction(sortFunc),
	"uniq":   GeneralFunction(uniqFunc),
	"key":    GeneralFunction(keyFunc),
	"source": GeneralFunction(sourceFunc),
}

// An internal wrapper around an EvaluationContext that adds a special regex
// submatch table and formatting evaluation tracer.
type evalContext struct {
	wrapped    EvaluationContext // the wrapped context
	submatches []string          // [0] = value of $1, etc.
	tracer     *evalTracer       // formatting tracer; not nil
}

// Creates a evalContext that wraps a copy of the specified EvaluationContext.
func newEvalContext(ctx EvaluationContext) *evalContext {
	var tracer *evalTracer
	if ctx.EvalTracer() != nil {
		tracer = &evalTracer{ctx.EvalTracer(), "    "}
	}
	return &evalContext{ctx.Copy(), nil, tracer}
}

// Returns a copy of ctx with new symbols added to its symbol table. Any symbol
// name conflicts are resolved in favor of new symbols.
func (ctx *evalContext) addSymbols(newSymbols map[string]interface{}) *evalContext {
	if newWrapped, err := ctx.wrapped.AddSymbols(newSymbols); err != nil {
		panic(fmt.Errorf("failed to add symbol(s) to wrapped context: %w", err))
	} else {
		ctxCopy := *ctx
		ctxCopy.wrapped = newWrapped
		return &ctxCopy
	}
}

// Returns a copy of ctx with new functions added to its function table. Any
// function name conflicts are resolved in favor of new functions.
func (ctx *evalContext) addFunctions(newFunctions map[string]interface{}) *evalContext {
	if newWrapped, err := ctx.wrapped.AddFunctions(newFunctions); err != nil {
		panic(fmt.Errorf("failed to add function(s) to wrapped context: %w", err))
	} else {
		ctxCopy := *ctx
		ctxCopy.wrapped = newWrapped
		return &ctxCopy
	}
}

// Internal formatting evaluation tracer.
type evalTracer struct {
	writer io.Writer // destination for tracing text
	indent string    // one level of indentation (e.g., n spaces)
}

// Prints formatted output through the tracer. First argument is the number
// of indents to print first (0 = no indentation). Remaining arguments are as
// for fmt.Printf.
func (t *evalTracer) printf(indentLevel int, format string, args ...interface{}) {
	for i := 0; i < indentLevel; i++ {
		fmt.Fprintf(t.writer, t.indent)
	}
	fmt.Fprintf(t.writer, format, args...)
}

// Prints an expression to an evaluation tracer. The output displays the
// expression followed by a "ruler" indicating byte offsets.
func (t *evalTracer) printExpr(expr string) {
	prefix := "expression: "
	indent := "            "
	t.printf(0, "%s%s\n%s", prefix, expr, indent)
	// Print the ruler with markers and byte offset labels. Take a stab at
	// accounting for multi-byte UTF-8 code points (e.g., in quoted strings)
	// by shifting the markers and labels. This isn't hard for single-width
	// characters, but there doesn't seem to be a convenient go analog to
	// wcwidth(3) that makes it possible to determine which characters are
	// double-width. So the ruler will slip in the presence of double-width
	// characters.
	for i, w := 0, 0; i < len(expr); i += w {
		_, w = utf8.DecodeRuneInString(expr[i:])
		if i%10 == 0 {
			t.printf(0, "^")
		} else if i%5 == 0 {
			t.printf(0, "+")
		} else {
			t.printf(0, "-")
		}
	}
	t.printf(0, "\n%s", indent)
	for i, w, skip := 0, 0, 0; i < len(expr); i += w {
		_, w = utf8.DecodeRuneInString(expr[i:])
		if i%10 == 0 {
			pos := fmt.Sprintf("%d", i)
			t.printf(0, "%s", pos)
			skip += len(pos) - 1
		} else {
			if skip == 0 {
				t.printf(0, " ")
			} else {
				skip--
			}
		}
	}
	t.printf(0, "\n")
}

// Prints an exprValue to a tracer. Prints the heading line first at the given
// indentation level, then prints the value indented one level more. Prints
// multiple value lines for a vector value.
func (t *evalTracer) printExprValue(indentLevel int, heading string, value exprValue) {
	t.printf(indentLevel, "%s\n", heading)
	switch v := value.(type) {
	case nil:
		t.printf(indentLevel+1, "null\n")
	case *scalarValue:
		t.printScalarValue(indentLevel+1, -1, v)
	case *nodeValue:
		t.printNodeValue(indentLevel+1, -1, v)
	case *vectorValue:
		t.printVectorValue(indentLevel+1, v)
	}
}

// Prints a scalarValue to a tracer.
func (t *evalTracer) printScalarValue(indentLevel int, valueIndex int, value *scalarValue) {
	t.printValueIndent(indentLevel, valueIndex)
	switch s := value.scalar.(type) {
	case nil:
		t.printf(0, "null\n")
	case string:
		t.printf(0, "%q\n", s)
	case *regexp.Regexp:
		t.printf(0, "regexp(%s)\n", s)
	default:
		t.printf(0, "%v\n", s)
	}
}

// Prints a nodeValue to a tracer.
func (t *evalTracer) printNodeValue(indentLevel int, valueIndex int, value *nodeValue) {
	t.printValueIndent(indentLevel, valueIndex)
	path := value.path
	node := path[len(path)-1]

	switch node.Kind() {
	case ScalarKind:
		t.printf(0, "scalar node -> ")
		if s, err := node.DecodedScalarValue(); err != nil {
			t.printf(0, "[%q, undecodable]\n", node.Value().(string))
		} else {
			switch ss := s.(type) {
			case nil:
				t.printf(0, "null\n")
			case string:
				t.printf(0, "%q\n", ss)
			default:
				t.printf(0, "%v\n", ss)
			}
		}
	case SequenceKind:
		t.printf(0, "sequence node with %d children\n", len(node.Value().([]Node)))
	case MappingKind:
		t.printf(0, "mapping node with %d children\n", len(node.Value().(map[string]Node)))
	}

	t.printf(indentLevel, "path: ")
	if pathExpr, err := PathExpression(value.path); err != nil {
		t.printf(0, "[%s]\n", err.Error())
	} else {
		t.printf(0, "%s\n", pathExpr)
	}

	for _, src := range PathSources(path) {
		file := src.File
		if file == "" {
			file = "?"
		}
		t.printf(indentLevel, "from: %s:%d:%d\n", file, src.Line, src.Column)
	}
}

// Prints a vectorValue to a tracer. Prints one element per line with indices.
func (t *evalTracer) printVectorValue(indentLevel int, value *vectorValue) {
	for i, v := range value.vector {
		switch vv := v.(type) {
		case nil:
			t.printf(indentLevel, "null\n")
		case *scalarValue:
			t.printScalarValue(indentLevel, i, vv)
		case *nodeValue:
			t.printNodeValue(indentLevel, i, vv)
		default:
			t.printValueIndent(indentLevel, i)
			t.printf(0, "%#v\n", vv) // "can't happen"
		}
	}
}

// Prints initial indentation for a value. Prints valueIndex to the left of the
// value position if it is nonnegative.
func (t *evalTracer) printValueIndent(indentLevel int, valueIndex int) {
	if valueIndex < 0 {
		t.printf(indentLevel, "")
	} else {
		indexWidth := fmt.Sprintf("%d", len(t.indent)-1)
		t.printf(indentLevel-1, "%"+indexWidth+"d ", valueIndex)
	}
}

// Evaluates an expression. See Expression for documentation.
func evaluateExpression(expr *exprImpl, context EvaluationContext) (interface{}, error) {
	// Make sure the caller hasn't specified any illegally named symbols or
	// functions in the context.
	for symName, _ := range context.Symbols() {
		if ss := identRe.FindStringSubmatch(symName); len(ss) == 0 || len(ss[1]) != len(symName) {
			return nil, EvaluationErrorf(expr.text, 0, "invalid symbol name in context: %q", symName)
		}
	}
	for funcName, _ := range context.Functions() {
		if ss := identRe.FindStringSubmatch(funcName); len(ss) == 0 || len(ss[1]) != len(funcName) {
			return nil, EvaluationErrorf(expr.text, 0, "invalid function name in context: %q", funcName)
		}
	}

	// Create an internal context wrapper.
	ctx := newEvalContext(context)

	// Install the built-in functions in the context. First make sure the caller
	// hasn't tried to override any of them.
	for funcName, _ := range context.Functions() {
		if _, exists := builtinFunctions[funcName]; exists {
			return nil, EvaluationErrorf(expr.text, 0, "cannot redefine built-in function %q", funcName)
		}
	}
	ctx = ctx.addFunctions(builtinFunctions)

	// Evaluate the expression using the AST and the context.
	if ctx.tracer != nil {
		ctx.tracer.printExpr(expr.text)
	}
	if val, err := evalAst(expr.astRoot, ctx); err != nil {
		offset := err.(*tokenError).token.Offset()
		return nil, EvaluationErrorf(expr.text, offset, "%w: %q", err, snippet(expr.text, offset, 40))
	} else {
		// Unwrap results from internal data structures for return to caller.
		switch v := val.(type) {
		case *scalarValue, *nodeValue:
			return val.content(), nil
		case *vectorValue:
			results := make([]interface{}, len(v.vector))
			for i, elemVal := range v.vector {
				switch elemVal.(type) {
				case *scalarValue, *nodeValue:
					results[i] = elemVal.content()
				default:
					// This used to be possible. Is it still?
					return nil, EvaluationErrorf(expr.text, 0, "nested vector structure not supported in expression values")
				}
			}
			return results, nil
		default:
			return nil, EvaluationErrorf(expr.text, 0, "expression value is not of scalar or vector type")
		}
	}
}

// Evaluates an expression's abstract syntax tree. Returns the expression's
// value on success, an error containing a *tokenError on failure. Writes an
// evaluation trace to tracer if non-nil.
func evalAst(ast *astNode, ctx *evalContext) (exprValue, error) {
	if ast == nil {
		return nil, nil
	}
	switch t := ast.token.(type) {
	case *nullToken:
		return &scalarValue{nil}, nil
	case *boolToken:
		return &scalarValue{t.value}, nil
	case *numberToken:
		return &scalarValue{t.value}, nil
	case *singleQuoteToken:
		return &scalarValue{t.re}, nil
	case *doubleQuoteToken:
		return &scalarValue{t.content}, nil
	case *bracketToken:
		result, err := evalVector(ast, ctx)
		if err != nil {
			return nil, err
		}
		return result, nil
	case *letBindingToken:
		symName := t.name
		if leftVal, err := evalAst(ast.left, ctx); err != nil {
			return nil, err
		} else {
			var symVal interface{}
			switch lv := leftVal.(type) {
			case *vectorValue:
				elems := make([]interface{}, len(lv.vector))
				for i, e := range lv.vector {
					elems[i] = e.content()
				}
				symVal = elems
			default:
				symVal = lv.content()
			}
			if rightVal, err := evalAst(ast.right, ctx.addSymbols(map[string]interface{}{symName: symVal})); err != nil {
				return nil, err
			} else {
				return rightVal, nil
			}
		}
	case *operatorToken:
		switch t.op {
		case operComma:
			return evalCommaExpr(ast, ctx)
		case operQuestion:
			return evalTernaryExpr(ast, ctx)
		case operNot:
			return evalUnop(ast, notImpl, ctx)
		case operPlus:
			if ast.right == nil {
				return evalUnop(ast, unaryPlusImpl, ctx)
			} else {
				return evalStdBinop(ast, addImpl, ctx)
			}
		case operMinus:
			if ast.right == nil {
				return evalUnop(ast, unaryMinusImpl, ctx)
			} else {
				return evalStdBinop(ast, subImpl, ctx)
			}
		case operMul:
			return evalStdBinop(ast, mulImpl, ctx)
		case operDiv:
			return evalStdBinop(ast, divImpl, ctx)
		case operIntDiv:
			return evalStdBinop(ast, intDivImpl, ctx)
		case operMod:
			return evalStdBinop(ast, modImpl, ctx)
		case operPow:
			return evalStdBinop(ast, powImpl, ctx)
		case operEq:
			return evalRelop(ast, eqImpl, ctx)
		case operNe:
			return evalRelop(ast, neImpl, ctx)
		case operLt:
			return evalRelop(ast, ltImpl, ctx)
		case operLe:
			return evalRelop(ast, leImpl, ctx)
		case operGt:
			return evalRelop(ast, gtImpl, ctx)
		case operGe:
			return evalRelop(ast, geImpl, ctx)
		case operAnd:
			return evalStdBinop(ast, andImpl, ctx)
		case operOr:
			return evalStdBinop(ast, orImpl, ctx)
		case operLike:
			return evalStdBinop(ast, likeImpl, ctx)
		case operUnlike:
			return evalStdBinop(ast, unlikeImpl, ctx)
		case operEquals:
			return evalSetBinop(ast, equalsImpl, ctx)
		case operContains:
			return evalSetBinop(ast, containsImpl, ctx)
		case operSetMinus:
			return evalSetBinop(ast, minusImpl, ctx)
		case operUnion:
			return evalSetBinop(ast, unionImpl, ctx)
		case operIntersect:
			return evalSetBinop(ast, intersectImpl, ctx)
		default:
			return nil, tokenErrorf(t, `unimplemented operator: %q`, t.text) // "can't happen"
		}
	case *symbolToken:
		if ctx.tracer != nil {
			ctx.tracer.printf(0, "evaluating symbol reference at offset %d: %s\n", t.Offset(), t.Text())
		}
		var symDefined bool
		var symVal interface{}
		if !allDigitsRe.MatchString(t.name) {
			// regular symbol
			if val, ok := ctx.wrapped.Symbols()[t.name]; ok {
				symDefined = true
				symVal = val
			}
		} else {
			// $0, $1, etc.
			symNum, _ := strconv.Atoi(t.name)
			if symNum > 0 {
				if len(ctx.submatches) >= symNum {
					symDefined = true
					symVal = ctx.submatches[symNum-1]
				}
			}
		}
		if !symDefined {
			return nil, tokenErrorf(t, `undefined symbol: %s`, t.text)
		}
		var result exprValue
		switch v := symVal.(type) {
		case nil, bool, float64, string:
			result = &scalarValue{v}
		case Node:
			if path := PathFrom(ctx.wrapped.YamlRoot(), v); path == nil {
				return nil, tokenErrorf(t, `value of symbol %q is a Node that is not in the context YAML tree: %v`, t.Text(), v)
			} else {
				result = &nodeValue{path}
				ctx.wrapped.NodeLogger().Log(path)
			}
		case []interface{}:
			elems := make([]exprValue, len(v))
			for i, elemVal := range v {
				switch vv := elemVal.(type) {
				case nil, bool, float64, string:
					elems[i] = &scalarValue{vv}
				case Node:
					if path := PathFrom(ctx.wrapped.YamlRoot(), vv); path == nil {
						return nil, tokenErrorf(t, `element %d of value of symbol %q is a Node that is not in the context YAML tree: %v`, i, t.Text(), vv)
					} else {
						elems[i] = &nodeValue{path}
						ctx.wrapped.NodeLogger().Log(path)
					}
				default:
					return nil, tokenErrorf(t, `unsupported value type for element %d of value of symbol %q: %T`, i, t.Text(), vv)
				}
			}
			result = &vectorValue{elems}
		default:
			return nil, tokenErrorf(t, `unsupported value type for symbol %q: %T`, t.Text(), v)
		}
		if ctx.tracer != nil {
			ctx.tracer.printExprValue(1, "result:", result)
		}
		return result, nil
	case *functionToken:
		return evalFunctionCall(ast, ctx)
	case *pathPatternToken:
		if ctx.tracer != nil {
			ctx.tracer.printf(0, "evaluating path expression at offset %d: %s\n", t.Offset(), t.Text())
		}
		yamlRef := ctx.wrapped.YamlRef()
		if yamlRef == nil {
			yamlRef = ctx.wrapped.YamlRoot()
		}
		if yamlRef != nil {
			paths := MatchingPaths(yamlRef, t.pattern)
			if len(paths) > 0 {
				nodeValues := make([]exprValue, len(paths))
				for i, p := range paths {
					fullPath := append(PathFrom(ctx.wrapped.YamlRoot(), yamlRef), p[1:]...)
					nodeValues[i] = &nodeValue{fullPath}
					ctx.wrapped.NodeLogger().Log(fullPath)
				}
				result := &vectorValue{nodeValues}
				if ctx.tracer != nil {
					ctx.tracer.printExprValue(1, "result:", result)
				}
				return result, nil
			}
		}
		if ctx.tracer != nil {
			ctx.tracer.printf(1, "(no matches)\n")
		}
		return &vectorValue{nil}, nil
	case *pathPatternSymbolToken:
		if ctx.tracer != nil {
			ctx.tracer.printf(0, "evaluating indirect path expression at offset %d: %s\n", t.Offset(), t.Text())
		}
		if v, ok := ctx.wrapped.Symbols()[t.name]; !ok {
			return nil, tokenErrorf(t, `undefined symbol: %s`, t.name)
		} else {
			if subroot, ok := v.(Node); !ok {
				return nil, tokenErrorf(t, `symbol %q not bound to a YAML node`, t.Text())
			} else {
				pathToSubroot := PathFrom(ctx.wrapped.YamlRoot(), subroot)
				if ctx.tracer != nil {
					ctx.tracer.printExprValue(1, fmt.Sprintf("value of $%s:", t.name), &nodeValue{pathToSubroot})
				}
				paths := MatchingPaths(subroot, t.pattern)
				if len(paths) > 0 {
					nodeValues := make([]exprValue, len(paths))
					for i, p := range paths {
						fullPath := AppendToPathCopy(pathToSubroot, p[1:]...)
						nodeValues[i] = &nodeValue{fullPath}
						ctx.wrapped.NodeLogger().Log(fullPath)
					}
					result := &vectorValue{nodeValues}
					if ctx.tracer != nil {
						ctx.tracer.printExprValue(1, "result:", result)
					}
					return result, nil
				}
			}
		}
		if ctx.tracer != nil {
			ctx.tracer.printf(1, "(no matches)\n")
		}
		return &vectorValue{nil}, nil
	}
	return nil, tokenErrorf(ast.token, `unhandled token type: %T (%q)`, ast.token, ast.token.Text()) // "can't happen"
}

// Evaluates a function. Assumes ast is rooted by the function call token.
func evalFunctionCall(ast *astNode, ctx *evalContext) (exprValue, error) {
	funcToken := ast.token.(*functionToken)
	// Look up the function in the context.
	funcValue, ok := ctx.wrapped.Functions()[funcToken.name]
	if !ok {
		return nil, tokenErrorf(funcToken, `undefined function: %q`, funcToken.text)
	}

	// Evaluate the argument(s). If there are multiple arguments, they will be
	// combined into a vector.
	argsValue, err := evalAst(ast.left, ctx)
	if err != nil {
		return nil, err
	}

	if ctx.tracer != nil {
		ctx.tracer.printf(0, "evaluating function call at offset %d: %q\n", funcToken.Offset(), funcToken.name)
		ctx.tracer.printExprValue(1, "argument(s):", argsValue)
	}

	// Call the function with the arguments unwrapped from their internal form
	// in a manner appropriate to the function's type. Save the results in raw
	// (unwrapped) form for now.
	var rawResult interface{}
	switch function := funcValue.(type) {
	case ScalarFunction:
		// Need to invoke function on scalars only. Convert Node values to
		// scalars if needed, and invoke function elementwise on vector args.
		// For convenience, force args into a vector shape for evaluation.
		realArgIsVector := false
		var argsAsVector *vectorValue
		switch arg := argsValue.(type) {
		case nil:
			return nil, tokenErrorf(funcToken, `scalar function %q cannot be invoked without an argument`, funcToken.name)
		case *scalarValue:
			if _, isRe := arg.scalar.(*regexp.Regexp); isRe {
				return nil, tokenErrorf(funcToken, `scalar function %q cannot be invoked with a regular expression argument`, funcToken.name)
			}
			argsAsVector = &vectorValue{[]exprValue{arg}}
		case *nodeValue:
			argsAsVector = &vectorValue{[]exprValue{arg}}
		case *vectorValue:
			realArgIsVector = true
			argsAsVector = arg
		}

		// Call the function elementwise on the (unwrapped) vector elements.
		retVals := make([]interface{}, len(argsAsVector.vector))
		for i, arg := range argsAsVector.vector {
			var err error
			switch a := arg.(type) {
			case *scalarValue:
				retVals[i], err = function(a.scalar)
			case *nodeValue:
				var s *scalarValue
				s, err = a.asScalarValue()
				if err == nil {
					retVals[i], err = function(s.scalar)
				}
			default:
				err = fmt.Errorf(`nested vector argument`) // "can't happen"?
			}
			if err != nil {
				return nil, tokenErrorf(funcToken, `function %q evaluation failure: %w`, funcToken.name, err)
			}
		}

		// Save returned value(s) a scalar or vector argument as appropriate.
		if realArgIsVector {
			rawResult = retVals
		} else {
			rawResult = retVals[0]
		}
	case GeneralFunction:
		// Invoke function with an (unwrapped) scalar, Node, or vector argument.
		var rawArg interface{}
		switch a := argsValue.(type) {
		case nil:
			rawArg = nil
		case *scalarValue, *nodeValue:
			rawArg = argsValue.content()
		case *vectorValue:
			rawArgSlice := make([]interface{}, len(a.vector))
			for i, v := range a.vector {
				switch v.(type) {
				case *scalarValue, *nodeValue:
					rawArgSlice[i] = v.content()
				case *vectorValue:
					return nil, tokenErrorf(funcToken, `function %q evaluation failure: nested vector argument`, funcToken.name)
				}
			}
			rawArg = rawArgSlice
		}
		retVal, err := function(ctx.wrapped.Copy(), rawArg)
		if err != nil {
			return nil, tokenErrorf(funcToken, `function %q evaluation failure: %w`, funcToken.name, err)
		} else {
			rawResult = retVal
		}
	}

	// Wrap the function's return value and return the result.
	var resultValue exprValue
	switch r := rawResult.(type) {
	case nil, bool, float64, string:
		resultValue = &scalarValue{r}
	case []interface{}:
		values := make([]exprValue, len(r))
		for i, v := range r {
			switch vv := v.(type) {
			case nil, bool, float64, string:
				values[i] = &scalarValue{vv}
			case Node:
				if path := PathFrom(ctx.wrapped.YamlRoot(), vv); path == nil {
					return nil, tokenErrorf(funcToken, `Node returned by %q not found in YAML tree: %v`, funcToken.name, vv)
				} else {
					values[i] = &nodeValue{path}
				}
			default:
				return nil, tokenErrorf(funcToken, `unsupported element type in function %q return value: %T`, funcToken.name, v)
			}
		}
		resultValue = &vectorValue{values}
	default:
		return nil, tokenErrorf(funcToken, `unsupported type in function %q return value: %T`, funcToken.name, r)
	}

	if ctx.tracer != nil {
		ctx.tracer.printExprValue(1, "result:", resultValue)
	}
	return resultValue, nil
}

// Evaluates a comma expression. Assumes ast is rooted by a comma operator
// token. Returns results in a *vectorValue. For example, "<e1>, <e2>, <e3>"
// produces a three-element vector containing the values of <e1>, <e2>, and
// <e3>. The elements of any vector-valued list elements are copied
// ("flattened") into the returned vector.
func evalCommaExpr(ast *astNode, ctx *evalContext) (exprValue, error) {
	lhsValue, err := evalAst(ast.left, ctx)
	if err != nil {
		return nil, err
	}
	rhsValue, err := evalAst(ast.right, ctx)
	if err != nil {
		return nil, err
	}
	switch lhs := lhsValue.(type) {
	case *scalarValue, *nodeValue:
		switch rhs := rhsValue.(type) {
		case *scalarValue, *nodeValue:
			return &vectorValue{[]exprValue{lhs, rhs}}, nil
		case *vectorValue:
			return &vectorValue{append([]exprValue{lhs}, rhs.vector...)}, nil
		}
	case *vectorValue:
		switch rhs := rhsValue.(type) {
		case *scalarValue, *nodeValue:
			return lhs.appendToCopy(rhs), nil
		case *vectorValue:
			return lhs.appendToCopy(rhs.vector...), nil
		}
	}
	return nil, tokenErrorf(ast.token, "unexpected: %T %q %T", lhsValue, ast.token.Text(), rhsValue) // "can't happen"
}

// Evaluates a ternary conditional expression. Assumes ast is rooted by a "?"
// operator token with the left child equal to the (presumably boolean-valued)
// conditional expression and the right child rooted by a ":" token with the
// "true" and "false" alternative expressions as its left and right children.
func evalTernaryExpr(ast *astNode, ctx *evalContext) (exprValue, error) {
	quesToken := ast.token

	predVal, err := evalAst(ast.left, ctx)
	if err != nil {
		return nil, err
	}

	if ctx.tracer != nil {
		ctx.tracer.printf(0, "evaluating ternary operator at offset %d: %q\n", quesToken.Offset(), quesToken.Text())
		ctx.tracer.printExprValue(1, "predicate operand:", predVal)
	}

	var scalarPredVal *scalarValue
	switch v := predVal.(type) {
	case *scalarValue:
		scalarPredVal = v
	case *vectorValue:
		if len(v.vector) == 1 {
			switch p := v.vector[0].(type) {
			case *scalarValue:
				scalarPredVal = p
			}
		}
	}
	if scalarPredVal == nil {
		return nil, tokenErrorf(quesToken, `expression before %q does not evaluate to a single boolean value`, quesToken.Text())
	} else if pred, isBool := scalarPredVal.content().(bool); !isBool {
		return nil, tokenErrorf(quesToken, `non-boolean expression before %q: %s`, quesToken.Text(), scalarPredVal.summary())
	} else {
		var resultVal exprValue
		if pred {
			resultVal, err = evalAst(ast.right.left, ctx)
		} else {
			resultVal, err = evalAst(ast.right.right, ctx)
		}
		if err != nil {
			return nil, err
		}
		return resultVal, nil
	}
}

// Evaluates a unary operator. Assumes ast is rooted by the operator token.
func evalUnop(ast *astNode, unopImpl func(token, *scalarValue) (*scalarValue, error), ctx *evalContext) (exprValue, error) {
	opToken := ast.token.(*operatorToken)

	// Get the op's argument (always the left-hand child for unary ops).
	lhsValue, err := evalAst(ast.left, ctx)
	if err != nil {
		return nil, err
	}

	// Translate the arg to scalar or vector-of-scalar.
	lhsValue, err = scalarOrVectorOfScalars(lhsValue)
	if err != nil {
		return nil, tokenErrorf(opToken, "invalid operand for unary %q: %w", opToken.Text(), err)
	}

	if ctx.tracer != nil {
		ctx.tracer.printf(0, "evaluating unary operator at offset %d: %q\n", opToken.Offset(), opToken.Text())
		ctx.tracer.printExprValue(1, "operand:", lhsValue)
	}

	var result exprValue

	// If the arg is a scalar, just apply the op implementation to it. If the
	// arg is a vector, apply the op elementwise to its elements. Note that
	// path expression evaluation always produces a vector.
	switch lhs := lhsValue.(type) {
	case *scalarValue:
		result, err = unopImpl(opToken, lhs)
		if err != nil {
			return nil, err
		}
	case *vectorValue:
		elems := make([]exprValue, len(lhs.vector))
		for i, e := range lhs.vector {
			if v, err := unopImpl(opToken, e.(*scalarValue)); err != nil {
				return nil, err
			} else {
				elems[i] = v
			}
		}
		result = &vectorValue{elems}
	default:
		return nil, tokenErrorf(opToken, "unexpected: unary %q %T", opToken.Text(), lhsValue) // "can't happen"
	}

	if ctx.tracer != nil {
		ctx.tracer.printExprValue(1, "result:", result)
	}
	return result, nil
}

// Evaluates a standard binary operator. Performs broadcasting if necessary to
// make the left and right operands have the same "shape". Normally evaluates
// both operands, but short-circuits boolean operators when the left operand
// is a scalar boolean or a unit-length boolean vector. On success returns the
// result of applying the operator. On failure returns nil and a non-nil error.
func evalStdBinop(ast *astNode, binopImpl func(token, *scalarValue, *scalarValue, *evalContext) (*scalarValue, error), ctx *evalContext) (exprValue, error) {
	// Evaluate the left-hand-side operand.
	opToken := ast.token.(*operatorToken)
	lhsValue, err := evalAst(ast.left, ctx)
	if err != nil {
		return nil, err
	}

	// Translate the lhs arg to scalar or vector-of-scalar.
	lhsValue, err = scalarOrVectorOfScalars(lhsValue)
	if err != nil {
		return nil, tokenErrorf(opToken, "invalid left operand for %q: %w", opToken.Text(), err)
	}

	var result exprValue

	// Handle special-case short circuiting for "and" and "or" binops.
	// Leave result nil iff there is no short circuit.
	if opToken.op == operAnd || opToken.op == operOr {
		switch v := lhsValue.(type) {
		case *scalarValue:
			if b, isBool := v.scalar.(bool); isBool && b == (opToken.op == operOr) {
				result = &scalarValue{b}
			}
		case *vectorValue:
			if len(v.vector) == 1 {
				switch vv := v.vector[0].(type) {
				case *scalarValue:
					if b, isBool := vv.scalar.(bool); isBool && b == (opToken.op == operOr) {
						result = &scalarValue{b}
					}
				}
			}
		}
	}

	var rhsValue exprValue

	if result == nil {
		// Evaluate the right-hand-side operand.
		rhsValue, err = evalAst(ast.right, ctx)
		if err != nil {
			return nil, err
		}

		// Translate the rhs arg to scalar or vector-of-scalar.
		rhsValue, err = scalarOrVectorOfScalars(rhsValue)
		if err != nil {
			return nil, tokenErrorf(opToken, "invalid right operand for %q: %w", opToken.Text(), err)
		}
	}

	if ctx.tracer != nil {
		ctx.tracer.printf(0, "evaluating binary operator at offset %d: %q\n", opToken.Offset(), opToken.Text())
		ctx.tracer.printExprValue(1, "left operand:", lhsValue)
		if result != nil {
			ctx.tracer.printExprValue(1, "result (short circuit):", result)
		} else {
			ctx.tracer.printExprValue(1, "right operand:", rhsValue)
		}
	}

	if result != nil { // short circuit
		return result, nil
	}

	// Determine whether or not both operands are scalars. If so, the result
	// needs to be a scalar also.
	bothScalars := false
	switch lhsValue.(type) {
	case *scalarValue:
		switch rhsValue.(type) {
		case *scalarValue:
			bothScalars = true
		}
	}

	// If necessary, translate the operands into two equal-length "vectors"
	// (just slices here) of scalar values.
	var lvec, rvec []*scalarValue
	lvec, rvec, err = broadcastForScalarOp(lhsValue, rhsValue)
	if err != nil {
		return nil, tokenErrorf(opToken, "operator %q unsupported for operands: %w", opToken.Text(), err)
	}

	// Apply the operator elementwise.
	resultValues := make([]exprValue, len(lvec))
	for i, _ := range lvec {
		lhs := lvec[i]
		rhs := rvec[i]
		resultValues[i], err = binopImpl(opToken, lhs, rhs, ctx)
		if err != nil {
			return nil, tokenErrorf(opToken, "failed to apply operator %q: %w", opToken.Text(), err)
		}
	}

	if bothScalars {
		result = resultValues[0]
	} else {
		result = &vectorValue{resultValues}
	}

	if ctx.tracer != nil {
		ctx.tracer.printExprValue(1, "result:", result)
	}

	return result, nil
}

// Evaluates a set binary operator.
func evalSetBinop(ast *astNode, binopImpl func(token, *vectorValue, *vectorValue, *evalContext) (exprValue, error), ctx *evalContext) (exprValue, error) {
	opToken := ast.token.(*operatorToken)

	// Evaluate the left operand, translate to vector of scalars.
	lhsValue, err := evalAst(ast.left, ctx)
	if err != nil {
		return nil, err
	}
	lhsValue, err = scalarOrVectorOfScalars(lhsValue)
	if err != nil {
		return nil, tokenErrorf(opToken, "invalid left operand for %q: %w", opToken.Text(), err)
	}
	if _, isScalar := lhsValue.(*scalarValue); isScalar {
		lhsValue = &vectorValue{[]exprValue{lhsValue}}
	}

	// Evaluate the right operand, translate to vector of scalars.
	rhsValue, err := evalAst(ast.right, ctx)
	if err != nil {
		return nil, err
	}
	rhsValue, err = scalarOrVectorOfScalars(rhsValue)
	if err != nil {
		return nil, tokenErrorf(opToken, "invalid left operand for %q: %w", opToken.Text(), err)
	}
	if _, isScalar := rhsValue.(*scalarValue); isScalar {
		rhsValue = &vectorValue{[]exprValue{rhsValue}}
	}

	if ctx.tracer != nil {
		ctx.tracer.printf(0, "evaluating binary operator at offset %d: %q\n", opToken.Offset(), opToken.Text())
		ctx.tracer.printExprValue(1, "left operand:", lhsValue)
		ctx.tracer.printExprValue(1, "right operand:", rhsValue)
	}

	// Apply the operator implementation.
	resultValue, err := binopImpl(opToken, lhsValue.(*vectorValue), rhsValue.(*vectorValue), ctx)
	if err != nil {
		return nil, tokenErrorf(opToken, "failed to apply operator %q: %w", opToken.Text(), err)
	}

	if ctx.tracer != nil {
		ctx.tracer.printExprValue(1, "result:", resultValue)
	}

	return resultValue, nil
}

// Evaluates a relational operator. Performs broadcasting if necessary to make
// the left and right operands have the same "shape". Implements chaining;
// e.g., "a < b == c <= d" is equivalent to "a == b and b == c and c <= d".
func evalRelop(ast *astNode, relopImpl func(token, *scalarValue, *scalarValue) (*scalarValue, error), ctx *evalContext) (exprValue, error) {
	opToken := ast.token.(*operatorToken)
	// If this relop is the second or subsequent op of a relop chain (e.g.,
	// 0 < x == y < 1), then its left subtree is headed by the preceding
	// relop, and the lhs for this relop is not the value of the left subtree
	// but rather the value of the left subtree's right subtree, and we need
	// to AND this relop's value with its left subtree's value.
	var prevValue, lhsValue, rhsValue exprValue
	var err error
	if tokenIsOperator(ast.left.token, operEq, operNe, operLt, operLe, operGt, operGe) {
		// We end up evaluating the left subtree's right subtree twice. With a
		// little effort we could eliminate the extra evaluation. Maybe later.
		lhsValue, err = evalAst(ast.left.right, ctx)
		if err != nil {
			return nil, err
		}
		prevValue, err = evalAst(ast.left, ctx)
		if err != nil {
			return nil, err
		}
	} else {
		lhsValue, err = evalAst(ast.left, ctx)
		if err != nil {
			return nil, err
		}
		prevValue = &scalarValue{true}
	}
	rhsValue, err = evalAst(ast.right, ctx)
	if err != nil {
		return nil, err
	}

	if ctx.tracer != nil {
		ctx.tracer.printf(0, "evaluating relational operator at offset %d: %q\n", opToken.Offset(), opToken.Text())
		ctx.tracer.printExprValue(1, "left operand:", lhsValue)
		ctx.tracer.printExprValue(1, "right operand:", rhsValue)
	}

	// Translate both args to scalar or vector-of-scalar.
	lhsValue, err = scalarOrVectorOfScalars(lhsValue)
	if err != nil {
		return nil, tokenErrorf(opToken, "invalid left operand for %q: %w", opToken.Text(), err)
	}
	rhsValue, err = scalarOrVectorOfScalars(rhsValue)
	if err != nil {
		return nil, tokenErrorf(opToken, "invalid right operand for %q: %w", opToken.Text(), err)
	}

	// Determine whether or not the lhs and rhs operands are both scalars. If
	// so, then any previous chain result must be a scalar as well, and the
	// final result will be a scalar.
	bothScalars := false
	switch lhsValue.(type) {
	case *scalarValue:
		switch rhsValue.(type) {
		case *scalarValue:
			bothScalars = true
		}
	}

	// Evaluate the current relop expression first, then take care of ANDing
	// in any previous chain value later. If necessary, translate the operands
	// into two equal-length "vectors" of scalar values, and apply the relop
	// elementwise.
	var lvec, rvec []*scalarValue
	lvec, rvec, err = broadcastForScalarOp(lhsValue, rhsValue)
	if err != nil {
		return nil, tokenErrorf(opToken, "operator %q unsupported for operands: %w", opToken.Text(), err)
	}
	resultValues := make([]exprValue, len(lvec))
	for i, _ := range lvec {
		lhs := lvec[i]
		rhs := rvec[i]
		resultValues[i], err = relopImpl(opToken, lhs, rhs)
		if err != nil {
			return nil, tokenErrorf(opToken, "failed to apply operator %q: %w", opToken.Text(), err)
		}
	}
	currValue := &vectorValue{resultValues}

	// Now AND together the value of the current relop expression abd the value
	// of the previous relop in the chain (if any). May need to harmonize vector
	// lengths again.
	var pvec, cvec []*scalarValue
	pvec, cvec, err = broadcastForScalarOp(prevValue, currValue)
	if err != nil {
		return nil, tokenErrorf(opToken, "operator %q unsupported for operands: %w", opToken.Text(), err)
	}
	for i, _ := range pvec {
		resultValues[i] = &scalarValue{pvec[i].scalar.(bool) && cvec[i].scalar.(bool)}
	}

	var result exprValue

	if bothScalars {
		result = resultValues[0]
	} else {
		result = &vectorValue{resultValues}
	}

	if ctx.tracer != nil {
		ctx.tracer.printExprValue(1, "result:", result)
	}
	return result, nil
}

// Attempts to return a representation of the argument that is either a
// *scalarValue or a *vectorValue with *scalarValue elements, converting any
// *nodeValue values to equivalent *scalarValue values as needed. Returns
// nil and an error if unsuccessful.
func scalarOrVectorOfScalars(value exprValue) (exprValue, error) {
	switch v := value.(type) {
	case *scalarValue:
		return v, nil
	case *nodeValue:
		if s, err := v.asScalarValue(); err != nil {
			return nil, err
		} else {
			return s, nil
		}
	case *vectorValue:
		elems := make([]exprValue, len(v.vector))
		for i, e := range v.vector {
			switch vv := e.(type) {
			case *scalarValue:
				elems[i] = vv
			case *nodeValue:
				if s, err := vv.asScalarValue(); err != nil {
					return nil, err
				} else {
					elems[i] = s
				}
			}
		}
		return &vectorValue{elems}, nil
	}
	return nil, fmt.Errorf("unexpected: %T", value) // "can't happen"
}

// Returns the result of "broadcasting" two expression values against one
// another so that a scalar binary operation can be applied elementwise to
// them. Translates non-vector arguments into unit-length vectors, then
// extends unit-length vectors by element replication to create two equal
// length vectors. If both arguments are vectors, they must be of equal
// length. Assuming two equal-length vectors can be so obtained, the results
// of converting their elements to scalar values are returned if possible.
// Otherwise two nil values and a fmt.Errorf error are returned. Assumes
// leftValue and rightValue are of type *scalarValue or *vectorValue only.
func broadcastForScalarOp(leftValue exprValue, rightValue exprValue) ([]*scalarValue, []*scalarValue, error) {
	// Convert arguments to vectors (slices) of scalars.
	vecs := make(map[string][]*scalarValue, 2)
	for side, val := range map[string]exprValue{"left": leftValue, "right": rightValue} {
		switch v := val.(type) {
		case *scalarValue:
			vecs[side] = []*scalarValue{v}
		case *vectorValue:
			vecs[side] = make([]*scalarValue, len(v.vector))
			for i, v := range v.vector {
				if s, err := v.asScalarValue(); err != nil {
					return nil, nil, fmt.Errorf("could not convert %s operand element to scalar: %w", side, err)
				} else {
					vecs[side][i] = s
				}
			}
		}
	}
	// Broadcast and return results.
	lvec := vecs["left"]
	rvec := vecs["right"]
	switch {
	case len(lvec) == len(rvec):
		return lvec, rvec, nil
	case len(lvec) == 1 && len(rvec) != 1:
		newlvec := make([]*scalarValue, len(rvec))
		for i, _ := range rvec {
			newlvec[i] = lvec[0]
		}
		return newlvec, rvec, nil
	case len(lvec) != 1 && len(rvec) == 1:
		newrvec := make([]*scalarValue, len(lvec))
		for i, _ := range lvec {
			newrvec[i] = rvec[0]
		}
		return lvec, newrvec, nil
	default:
		return nil, nil, fmt.Errorf("mismatched vector lengths (%d vs. %d)", len(lvec), len(rvec))
	}
}

// Evaluates a vector expression. Assumes the "[" is at the given AST root.
// Returns results in a vectorValue. See parseVector for vector expression
// AST structure.
func evalVector(ast *astNode, ctx *evalContext) (exprValue, error) {
	var result exprValue
	if ast.right == nil {
		// It's just an expression list in brackets.
		val, err := evalAst(ast.left, ctx)
		if err != nil {
			return nil, err
		}
		switch v := val.(type) {
		case nil:
			result = &vectorValue{[]exprValue{}}
		case *scalarValue, *nodeValue:
			result = &vectorValue{[]exprValue{v}}
		default:
			result = v
		}
		if ctx.tracer != nil {
			ctx.tracer.printf(0, "evaluating vector literal at offset %d: %s\n", ast.token.Offset(), ast.token.Text())
			ctx.tracer.printExprValue(1, "result:", result)
		}
	} else {
		// It's a vector comprehension. Evaluate the governed (left) expression
		// once for each set of bindings defined by the "for list" in the right
		// expression, and use the resulting values as the elements of the
		// returned vector.
		bindingTable, err := evalForBindings(ast.right, ctx)
		if err != nil {
			return nil, err
		}
		var resultValues []exprValue
		for _, bindingRow := range bindingTable {
			symtab := make(map[string]interface{}, len(bindingRow))
			for _, b := range bindingRow {
				symtab[b.token.name] = b.value.content()
			}
			value, err := evalAst(ast.left, ctx.addSymbols(symtab))
			if err != nil {
				return nil, err
			}
			switch v := value.(type) {
			case *scalarValue, *nodeValue:
				resultValues = append(resultValues, v)
			case *vectorValue:
				resultValues = append(resultValues, v.vector...) // flatten
			}
		}
		result = &vectorValue{resultValues}
		if ctx.tracer != nil {
			ctx.tracer.printf(0, "evaluating vector comprehension at offset %d: %s\n", ast.token.Offset(), ast.token.Text())
			ctx.tracer.printExprValue(1, "result:", result)
		}
	}
	return result, nil
}

// A "for" binding.
type forBinding struct {
	token *forBindingToken
	value exprValue
}

// Evaluates the bindings for a vector comprehension. Assumes ast points to the
// root of the the parsed bindings (i.e., either a binding or a comma). Returns
// a table of bindings, each row (element slice) of which contains a binding for
// each symbol named after the "for" to one of its possible values such that the
// full table represents the Cartesian product of all of the symbols' value sets
// with any elements (row) for which any binding predicates are false omitted.
// Evaluates each symbol's values and each binding predicate with all preceding
// symbols defined in the symbol table.
func evalForBindings(ast *astNode, ctx *evalContext) ([][]*forBinding, error) {
	switch t := ast.token.(type) {
	case *forBindingToken:
		// The AST node is for a symbol bound via "in" to an expression. The
		// expression must be vector-valued, and we need to return a one-column
		// table with each row containing a binding of the symbol to one of the
		// vector's elements.
		symName := t.name
		value, err := evalAst(ast.left, ctx)
		if err != nil {
			return nil, err
		} else if vecValue, isVec := value.(*vectorValue); !isVec {
			return nil, tokenErrorf(ast.left.token, `invalid binding for %q: argument of "in" must be vector-valued`, symName)
		} else {
			bindingTable := make([][]*forBinding, 0, len(vecValue.vector))
			for _, v := range vecValue.vector {
				includeElem := true
				if ast.right != nil {
					symTab := map[string]interface{}{symName: v.content()}
					rightVal, err := evalAst(ast.right, ctx.addSymbols(symTab))
					if err != nil {
						return nil, err
					} else {
						var predVal *scalarValue
						switch r := rightVal.(type) {
						case *scalarValue:
							predVal = r
						case *vectorValue:
							if len(r.vector) == 1 {
								switch p := r.vector[0].(type) {
								case *scalarValue:
									predVal = p
								}
							}
						}
						if predVal == nil {
							return nil, tokenErrorf(ast.right.token, `predicate expression does not evaluate to a single boolean value`)
						} else if pred, isBool := predVal.content().(bool); !isBool {
							return nil, tokenErrorf(ast.right.token, `non-boolean predicate expression value: %s`, predVal.summary())
						} else {
							includeElem = pred
						}
					}
				}
				if includeElem {
					bindingTable = append(bindingTable, []*forBinding{&forBinding{t, v}})
				}
			}
			return bindingTable, nil
		}
	default:
		// The AST node must be rooted by a "for" node, and the right child must
		// be rooted by a binding (see parseForBindings). Construct and return
		// the Cartesian product of the bindings from the left child and the
		// ones from the right child, evaluating the latter with the bindings
		// from the former added to the symbol table.
		productBindingTable := [][]*forBinding{}
		leftBindingTable, err := evalForBindings(ast.left, ctx)
		if err != nil {
			return nil, err
		}
		for _, leftBindingRow := range leftBindingTable {
			symTab := make(map[string]interface{}, len(leftBindingTable[0]))
			for _, leftBinding := range leftBindingRow {
				symTab[leftBinding.token.name] = leftBinding.value.content()
			}
			rightBindingTable, err := evalForBindings(ast.right, ctx.addSymbols(symTab))
			if err != nil {
				return nil, err
			}
			for _, rightBindingRow := range rightBindingTable {
				productBindingRow := make([]*forBinding, len(leftBindingRow), len(leftBindingRow)+1)
				copy(productBindingRow, leftBindingRow)
				productBindingRow = append(productBindingRow, rightBindingRow[0])
				productBindingTable = append(productBindingTable, productBindingRow)
			}
		}
		return productBindingTable, nil
	}
}

// Unary operator implementations. Each returns the result of applying a given
// operator to a given scalar value. Each returns *tokenError on type errors.

func unaryPlusImpl(opToken token, value *scalarValue) (*scalarValue, error) {
	if _, ok := value.content().(float64); ok {
		return value, nil
	} else {
		return nil, tokenErrorf(opToken, "unary %q illegal for %s\n", opToken.Text(), value.summary())
	}
}

func unaryMinusImpl(opToken token, value *scalarValue) (*scalarValue, error) {
	if v, ok := value.content().(float64); ok {
		return &scalarValue{-v}, nil
	} else {
		return nil, tokenErrorf(opToken, "unary %q illegal for %s\n", opToken.Text(), value.summary())
	}
}

func notImpl(opToken token, value *scalarValue) (*scalarValue, error) {
	if v, ok := value.content().(bool); ok {
		return &scalarValue{!v}, nil
	} else {
		return nil, tokenErrorf(opToken, "unary %q illegal for %s\n", opToken.Text(), value.summary())
	}
}

// Relational operator implementations. Each returns the boolean result of
// applying the given relational operator to the two scalar values. Each
// returns *tokenError on type errors.

func eqImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue) (*scalarValue, error) {
	var eq interface{}
	switch lval := leftValue.content().(type) {
	case nil:
		switch rightValue.content().(type) {
		case nil:
			eq = true
		default:
			eq = false
		}
	case bool, float64, string:
		switch rval := rightValue.content().(type) {
		case nil:
			switch leftValue.content().(type) {
			case nil:
				eq = true
			default:
				eq = false
			}
		case bool, float64, string:
			if reflect.TypeOf(lval) == reflect.TypeOf(rval) {
				eq = lval == rval
			}
		}
	}
	if eq == nil {
		return nil, tokenErrorf(opToken, "unsupported operation: %s %s %s", leftValue.summary(), opToken.Text(), rightValue.summary())
	} else {
		return &scalarValue{eq.(bool)}, nil
	}
}

func neImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue) (*scalarValue, error) {
	if eq, err := eqImpl(opToken, leftValue, rightValue); err != nil {
		return nil, err
	} else {
		return &scalarValue{!eq.content().(bool)}, nil
	}
}

func ltImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue) (*scalarValue, error) {
	switch lval := leftValue.content().(type) {
	case float64:
		switch rval := rightValue.content().(type) {
		case float64:
			return &scalarValue{lval < rval}, nil
		}
	case string:
		switch rval := rightValue.content().(type) {
		case string:
			return &scalarValue{lval < rval}, nil
		}
	}
	return nil, tokenErrorf(opToken, "unsupported operation: %s %s %s", leftValue.summary(), opToken.Text(), rightValue.summary())
}

func leImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue) (*scalarValue, error) {
	switch lval := leftValue.content().(type) {
	case float64:
		switch rval := rightValue.content().(type) {
		case float64:
			return &scalarValue{lval <= rval}, nil
		}
	case string:
		switch rval := rightValue.content().(type) {
		case string:
			return &scalarValue{lval <= rval}, nil
		}
	}
	return nil, tokenErrorf(opToken, "unsupported operation: %s %s %s", leftValue.summary(), opToken.Text(), rightValue.summary())
}

func gtImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue) (*scalarValue, error) {
	switch lval := leftValue.content().(type) {
	case float64:
		switch rval := rightValue.content().(type) {
		case float64:
			return &scalarValue{lval > rval}, nil
		}
	case string:
		switch rval := rightValue.content().(type) {
		case string:
			return &scalarValue{lval > rval}, nil
		}
	}
	return nil, tokenErrorf(opToken, "unsupported operation: %s %s %s", leftValue.summary(), opToken.Text(), rightValue.summary())
}

func geImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue) (*scalarValue, error) {
	switch lval := leftValue.content().(type) {
	case float64:
		switch rval := rightValue.content().(type) {
		case float64:
			return &scalarValue{lval >= rval}, nil
		}
	case string:
		switch rval := rightValue.content().(type) {
		case string:
			return &scalarValue{lval >= rval}, nil
		}
	}
	return nil, tokenErrorf(opToken, "unsupported operation: %s %s %s", leftValue.summary(), opToken.Text(), rightValue.summary())
}

// Non-relational binary operator implementations. Each returns the result of
// applying a given operator to two scalar values. Each returns *tokenError on
// type errors.

func addImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue, ctx *evalContext) (*scalarValue, error) {
	switch lval := leftValue.content().(type) {
	case float64:
		if rval, ok := rightValue.content().(float64); ok {
			return &scalarValue{lval + rval}, nil
		}
	case string:
		if rval, ok := rightValue.content().(string); ok {
			return &scalarValue{lval + rval}, nil
		}
	}
	return nil, tokenErrorf(opToken, "unsupported operation: %s %s %s", leftValue.summary(), opToken.Text(), rightValue.summary())
}

func subImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue, ctx *evalContext) (*scalarValue, error) {
	switch lval := leftValue.content().(type) {
	case float64:
		if rval, ok := rightValue.content().(float64); ok {
			return &scalarValue{lval - rval}, nil
		}
	}
	return nil, tokenErrorf(opToken, "unsupported operation: %s %s %s", leftValue.summary(), opToken.Text(), rightValue.summary())
}

func mulImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue, ctx *evalContext) (*scalarValue, error) {
	switch lval := leftValue.content().(type) {
	case float64:
		if rval, ok := rightValue.content().(float64); ok {
			return &scalarValue{lval * rval}, nil
		}
	}
	return nil, tokenErrorf(opToken, "unsupported operation: %s %s %s", leftValue.summary(), opToken.Text(), rightValue.summary())
}

func divImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue, ctx *evalContext) (*scalarValue, error) {
	switch lval := leftValue.content().(type) {
	case float64:
		if rval, ok := rightValue.content().(float64); ok {
			return &scalarValue{lval / rval}, nil
		}
	}
	return nil, tokenErrorf(opToken, "unsupported operation: %s %s %s", leftValue.summary(), opToken.Text(), rightValue.summary())
}

func intDivImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue, ctx *evalContext) (*scalarValue, error) {
	switch lval := leftValue.content().(type) {
	case float64:
		if rval, ok := rightValue.content().(float64); ok {
			return &scalarValue{math.Floor(lval / rval)}, nil
		}
	}
	return nil, tokenErrorf(opToken, "unsupported operation: %s %s %s", leftValue.summary(), opToken.Text(), rightValue.summary())
}

func modImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue, ctx *evalContext) (*scalarValue, error) {
	switch lval := leftValue.content().(type) {
	case float64:
		if rval, ok := rightValue.content().(float64); ok {
			return &scalarValue{lval - math.Floor(lval/rval)*rval}, nil
		}
	}
	return nil, tokenErrorf(opToken, "unsupported operation: %s %s %s", leftValue.summary(), opToken.Text(), rightValue.summary())
}

func powImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue, ctx *evalContext) (*scalarValue, error) {
	switch lval := leftValue.content().(type) {
	case float64:
		if rval, ok := rightValue.content().(float64); ok {
			return &scalarValue{math.Pow(lval, rval)}, nil
		}
	}
	return nil, tokenErrorf(opToken, "unsupported operation: %s %s %s", leftValue.summary(), opToken.Text(), rightValue.summary())
}
func andImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue, ctx *evalContext) (*scalarValue, error) {
	switch lval := leftValue.content().(type) {
	case bool:
		switch rval := rightValue.content().(type) {
		case bool:
			return &scalarValue{lval && rval}, nil
		}
	}
	return nil, tokenErrorf(opToken, "unsupported operation: %s %s %s", leftValue.summary(), opToken.Text(), rightValue.summary())
}

func orImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue, ctx *evalContext) (*scalarValue, error) {
	switch lval := leftValue.content().(type) {
	case bool:
		switch rval := rightValue.content().(type) {
		case bool:
			return &scalarValue{lval || rval}, nil
		}
	}
	return nil, tokenErrorf(opToken, "unsupported operation: %s %s %s", leftValue.summary(), opToken.Text(), rightValue.summary())
}

func likeImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue, ctx *evalContext) (*scalarValue, error) {
	switch lval := leftValue.content().(type) {
	case string:
		switch rval := rightValue.content().(type) {
		case *regexp.Regexp:
			submatches := rval.FindStringSubmatch(lval)
			if len(submatches) > 0 {
				ctx.submatches = submatches[1:]
				return &scalarValue{true}, nil
			} else {
				return &scalarValue{false}, nil
			}
		}
	}
	return nil, tokenErrorf(opToken, "unsupported operation: %s %s %s", leftValue.summary(), opToken.Text(), rightValue.summary())
}

func unlikeImpl(opToken token, leftValue *scalarValue, rightValue *scalarValue, ctx *evalContext) (*scalarValue, error) {
	if val, err := likeImpl(opToken, leftValue, rightValue, ctx); err != nil {
		return nil, err
	} else {
		return &scalarValue{!val.content().(bool)}, nil
	}
}

func unionImpl(opToken token, leftValue *vectorValue, rightValue *vectorValue, ctx *evalContext) (exprValue, error) {
	// Create a set containing all argument elements (which must be scalars).
	// Store base types (string, etc.) instead of *scalarValue so we can use
	// the built-in sort function later.
	set := make(map[interface{}]bool)
	for _, v := range leftValue.vector {
		if scalarVal, err := v.asScalarValue(); err != nil {
			return nil, tokenErrorf(opToken, "invalid left operand: %w", err)
		} else {
			set[scalarVal.content()] = true
		}
	}
	for _, v := range rightValue.vector {
		if scalarVal, err := v.asScalarValue(); err != nil {
			return nil, tokenErrorf(opToken, "invalid right operand: %w", err)
		} else {
			set[scalarVal.content()] = true
		}
	}

	// Copy the set contents to a slice, sort its contents, and return the
	// results in a *vectorValue.
	slice := make([]interface{}, 0, len(set))
	for v, _ := range set {
		slice = append(slice, v)
	}
	if sorted, err := sortFunc(ctx.wrapped, slice); err != nil {
		return nil, tokenErrorf(opToken, "%w", err)
	} else {
		sortedSlice := sorted.([]interface{})
		wrapped := make([]exprValue, len(sortedSlice))
		for i, v := range sortedSlice {
			wrapped[i] = &scalarValue{v}
		}
		return &vectorValue{wrapped}, nil
	}
}

func intersectImpl(opToken token, leftValue *vectorValue, rightValue *vectorValue, ctx *evalContext) (exprValue, error) {
	// Create a set containing all the left operand elements (which must be
	// scalars). Store base types (string, etc.) instead of *scalarValue so
	// we can use the built-in uniq function later.
	leftSet := make(map[interface{}]bool)
	for _, v := range leftValue.vector {
		if scalarVal, err := v.asScalarValue(); err != nil {
			return nil, tokenErrorf(opToken, "invalid left operand: %w", err)
		} else {
			baseVal := scalarVal.content()
			leftSet[baseVal] = true
		}
	}

	// Create a slice containing all the right operand elements (as base types)
	// that are also in the left operand set.
	inBoth := make([]interface{}, 0)
	for _, v := range rightValue.vector {
		if scalarVal, err := v.asScalarValue(); err != nil {
			return nil, tokenErrorf(opToken, "invalid right operand: %w", err)
		} else {
			baseVal := scalarVal.content()
			if _, exists := leftSet[baseVal]; exists {
				inBoth = append(inBoth, baseVal)
			}
		}
	}

	// Sort/uniq the slice and return the results in a *vectorValue.
	if unique, err := uniqFunc(ctx.wrapped, inBoth); err != nil {
		return nil, tokenErrorf(opToken, "%w", err)
	} else {
		uniqueSlice := unique.([]interface{})
		wrapped := make([]exprValue, len(uniqueSlice))
		for i, v := range uniqueSlice {
			wrapped[i] = &scalarValue{v}
		}
		return &vectorValue{wrapped}, nil
	}
}

func minusImpl(opToken token, leftValue *vectorValue, rightValue *vectorValue, ctx *evalContext) (exprValue, error) {
	// Put the inner interface{} values of all the right elements in a set.
	right := make(map[interface{}]bool)
	for _, r := range rightValue.vector {
		right[r.(*scalarValue).content()] = true
	}
	// Build a slice of all left elements that aren't in the right set.
	diff := make([]exprValue, 0, len(leftValue.vector))
	for _, l := range leftValue.vector {
		if !right[l.(*scalarValue).content()] {
			diff = append(diff, l)
		}
	}
	// Return the result in normalized (sort/uniq) form.
	diffVec := vectorValue{diff}
	return intersectImpl(opToken, &diffVec, &diffVec, ctx)
}

func equalsImpl(opToken token, leftValue *vectorValue, rightValue *vectorValue, ctx *evalContext) (exprValue, error) {
	// Not the most efficient implementation, but convenient for now.
	leftContainsRight, err := containsImpl(opToken, leftValue, rightValue, ctx)
	if err != nil {
		return nil, err
	}
	rightContainsLeft, err := containsImpl(opToken, rightValue, leftValue, ctx)
	if err != nil {
		return nil, err
	}
	equals := leftContainsRight.(*scalarValue).content().(bool) && rightContainsLeft.(*scalarValue).content().(bool)
	return &scalarValue{equals}, nil
}

func containsImpl(opToken token, leftValue *vectorValue, rightValue *vectorValue, ctx *evalContext) (exprValue, error) {
	// Compute the intersection of the left and right operands
	inter, err := intersectImpl(opToken, leftValue, rightValue, ctx)
	if err != nil {
		return nil, err
	}
	// Get a version of the right operand in the same (sort/uniq) form
	right, err := intersectImpl(opToken, rightValue, rightValue, ctx)
	if err != nil {
		return nil, err
	}
	// Left contains right if left intersect right == right
	interVals := inter.(*vectorValue).vector
	rightVals := right.(*vectorValue).vector
	equal := false
	if len(interVals) == len(rightVals) {
		equal = true
		for i, r := range rightVals {
			if eq, err := eqImpl(opToken, interVals[i].(*scalarValue), r.(*scalarValue)); err != nil {
				return nil, err
			} else if eq.content().(bool) != true {
				equal = false
				break
			}
		}
	}
	return &scalarValue{equal}, nil
}

// Returns the result of decoding scalar node values in a candidate function
// argument. If the argument is a scalar node, it is replaced by the scalar
// value of that node. If the argument is a sequence node whose elements are
// all scalars, it is replaced by a slice containing those scalar values. If
// the argument is a slice that contains one or more scalar nodes, it is
// replaced by a slice with those nodes replaced by their scalar values. An
// error is returned if the value of any scalar node cannot be converted to
// a representable value.
func decodeScalarNodesInArg(yamlRoot Node, arg interface{}) (interface{}, error) {
	switch a := arg.(type) {
	case Node:
		switch a.Kind() {
		case ScalarKind:
			if s, err := (&nodeValue{PathFrom(yamlRoot, a)}).asScalarValue(); err != nil {
				return nil, err
			} else {
				return s.scalar, nil
			}
		case SequenceKind:
			children := a.Value().([]Node)
			allScalars := true
			for _, child := range children {
				if child.Kind() != ScalarKind {
					allScalars = false
					break
				}
			}
			if allScalars {
				args := make([]interface{}, len(children))
				for i, child := range children {
					if s, err := (&nodeValue{PathFrom(yamlRoot, child)}).asScalarValue(); err != nil {
						return nil, err
					} else {
						args[i] = s.scalar
					}
				}
				return args, nil
			}
		}
	case []interface{}:
		elems := make([]interface{}, len(a))
		for i, e := range a {
			switch n := e.(type) {
			case Node:
				if n.Kind() == ScalarKind {
					if s, err := (&nodeValue{PathFrom(yamlRoot, n)}).asScalarValue(); err != nil {
						return nil, err
					} else {
						elems[i] = s.scalar
					}
				} else {
					elems[i] = e
				}
			default:
				elems[i] = e
			}
		}
		return elems, nil
	}
	return arg, nil
}
