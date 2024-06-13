package yamltree

import (
	"errors"
	"fmt"
	"io"
	"reflect"
)

// An Expression value represents a general expression in which path expressions
// may appear (along with other kinds of symbols) as variables. An expression
// may be evaluated under a specified context (see EvaluationContext) which
// includes a YAML Node tree against which to resolve path expression variables,
// a symbol table for other variables, and a table of externally defined function
// implementations.
//
// The Expression language supports scalar, vector, and Node values. Vectors are
// sequences of scalar and/or Node values. Scalar types include boolean, number,
// and string. Node values represent YAML nodes in the context tree. There is
// also a null value which has no type.
//
// The language supports the following operators, shown in order of decreasing
// precedence:
//
//    operators         actions
//    ---------         -------
//    - + not (unary)   numeric negation, numeric no-op, boolean negation
//    ^                 exponentiation
//    * / // %          multiplication, division, integer division, modulo
//    + -               addition (or string concatenation), subtraction
//    intersect         set intersection
//    union             set union
//    minus             set difference
//    equals, contains  set equality, containment
//    =~ !~             regular expression matching (normal and negated)
//    == != < <= > >=   equal, not equal, less than, less than or equal,
//                      greater than, greater than or equal
//    and               boolean AND
//    or                boolean OR
//    ?:                ternary conditional
//    let               symbol binding
//    ,                 expression list delimiter
//
// All binary operators associate left-to-right except for exponentiation,
// which associates right-to-left. The ternary conditional operator also
// associates right-to-left. Parentheses may be used for grouping and for
// overriding natural operator precedence.
//
// A relational operator chain of the form <expr1> <relop12> <expr2> <relop23>
// <expr3>... is equivalent to the conjunction (<expr1> <relop12> <expr2> and
// <expr2> <relop23> <expr3> and...).
//
// Null values compare equal to other null values and to nothing else. They
// may not appear as operands of operators other than == or !=.
//
// When used as operands, scalar (leaf) Node values are automatically converted
// to scalars, and vectors of Node values are automatically converted to vectors
// of scalars. The type of scalar a Node value is converted to is determined by
// its YAML tag. For example, the !!int and !!float tags cause conversion to
// numbers.
//
// Unary and binary operators may be applied to both scalars and vectors. When
// applied to a vector operand, a unary operator returns the vector that results
// from applying the operator to every element of the vector. When applied
// between two vector operands of equal length, a non-set binary operator (i.e.,
// one other than union, intersect, minus, equals, contains) returns the
// vector that results from applying the operator elementwise to the two
// operands. When applied between a vector operand and either a scalar operand
// or a unit-length vector operand, a non-set binary operator effectively
// replaces the scalar or singleton vector element operand by a vector formed
// by replicating the latter as many times as required to equal the length of
// the vector operand. Any other mismatch of operand lengths constitutes an
// error.
//
// The binary set operators union, intersect, minus, equals, and contains treat
// their operands as sets in that they ignore ordering and any repetition of
// elements. They treat scalar operands as sets of size 1. The union, intersect,
// and minus operators return vectors that contain no repeated elements and are
// sorted as described below for the sort function. The equals and contains
// operators returns a boolean scalar.
//
// The boolean AND and OR operators (and, or) short-circuit in the special case
// in which the left operand evaluates to a single boolean value in the form of
// either a scalar or a unit-length vector. Otherwise these operators evaluate
// both operands and operate elementwise.
//
// The ternary conditional operator (?:) requires its first operand to evaluate
// to a single boolean value in the form of either a scalar or a unit-length
// vector. Only one of the remaining two operands is evaluated, the second if
// the boolean is true and the third if it is false.
//
// Function invocations are of the form "<ident>(<exprlist>)", where <ident> is
// an identifier consisting of letters, digits, and/or underscores with the
// first character not a digit, and <exprlist> is a comma-delimited sequence of
// zero or more expressions. If <exprlist> contains multiple expressions, they
// are combined into a vector (after any needed flattening -- see below), and
// this vector is passed to the function as a single argument. Externally
// defined functions may be supplied in the evaluation context. See
// EvaluationContext, ScalarFunction and GeneralFunction for more informaion.
//
// Several functions are built in and are described below. When a description
// refers to "all arguments", it includes all elements of any vector arguments.
//
//     function       action
//     --------       ------
//     all            Returns true iff all arguments are true. Requires
//                    arguments to be convertible to boolean.
//     any            Returns true iff at least one argument is true.
//                    Requires arguments to be convertible to boolean.
//     count          Returns the number of true arguments. Requires
//                    arguments to be convertible to boolean.
//     len            Returns the number of arguments.
//     exists         Returns true iff the number of arguments is at least 1.
//     min            Returns the minimum of its arguments. Requires
//                    arguments to be convertible to number.
//     max            Returns the maximum of its arguments. Requires
//                    arguments to be convertible to number.
//     sum            Returns the sum of its arguments. Requires arguments
//                    to be convertible to number.
//     str            Returns the string values of its arguments. Operates
//                    elementwise on vectors.
//     num            Returns the result of converting its arguments to
//                    numbers. Operates elementwise on vectors. Requires
//                    arguments to be convertible to string.
//     int            Returns the result of rounding its arguments to
//                    integers (half away from zero). Operates elementwise
//                    on vectors. Requires arguments to be convertible to
//                    number.
//     abs            Returns the absolute values of its arguments. Operates
//                    elementwise on vectors. Requires arguments to be
//                    convertible to number.
//     value          Returns the scalar values of its arguments. Operates
//                    elementwise on vectors. Requires arguments to be either
//                    scalars, in which case it is a no-op, or Node values
//                    for scalar nodes, in which case it converts to internal
//                    scalars based on YAML tags.
//     split          Returns the result of splitting the string value of the
//                    second argument into substrings using the first argument
//                    to match substring separators. The first argument may be
//                    a regular expression or convertible to a string. The
//                    second argument must be convertible to a string. An
//                    optional third argument must be convertible to an integer
//                    and gives the maximum number of (leading) substrings to
//                    return (0 means none, negative means no limit). Returns a
//                    vector of string values.
//     join           Returns the string that results from concatenating the
//                    string forms of all its arguments after the first one
//                    with the string form of the first one as a separator.
//                    Requires all arguments to be convertible to string.
//     sort           Returns a vector containing the arguments in increasing
//                    order. Requires the arguments to be convertible to
//                    scalars. If the arguments are of mixed scalar types,
//                    they are grouped in the following order: null, boolean,
//                    number, string.
//     uniq           Same as sort but also removes the second and subsequent
//                    instances of any repeated values.
//     key            Returns the keys with which its arguments are associated
//                    in their parent mappings. Operates elementwise on vectors.
//                    Requires arguments to be Node values. Returns null for
//                    nodes that are not the children of mappings.
//     source         Returns source strings for its arguments. Operates
//                    elementwise on vector arguments. Requires arguments to
//                    be Node values. Source strings are of the form
//                    <filepath>:<linenumber>:<columnnumber>.
//
// The built-in functions that require boolean, number, or string arguments
// automatically convert any scalar Node arguments to those types in the same
// way Node values are automatically converted when used as operands. (In
// effect the value function is automatically invoked on operands and function
// arguments.)
//
// Any string that is valid as an argument to NewPathPattern can be used as
// a path expression variable. The value of a path expression variable is a
// vector of Node values for the terminal nodes of all matching paths in any
// YAML tree provided in the EvaluationContext. Ordering is preserved for any
// YAML sequences in match results, but ordering for mappings is undefined.
// If the context does not specify a YAML tree, then every path expression
// evaluates to an empty vector.
//
// Symbol references are of the form "$<ident>", where <ident> is an identifier
// consisting of letters, digits, and/or underscores with the first character
// not a digit (except for capturing group match symbols; see below). A symbol
// reference is replaced by the value bound to it. (It is an error to reference
// an unbound symbol.) Symbols may be bound to values supplied externally via
// the evaluation context or to values supplied internally by means of a "for"
// clause.
//
// A symbol reference followed by a path expression with no intervening space
// is resolved in two stages. First, the symbol reference is resolved. It is
// an error in this case for it to resolve to anything other than a Node in
// the context YAML tree. Next, the path expression is evaluated as usual but
// against the subtree rooted by the referenced Node instead of the full YAML
// tree. The result is a vector of Node values.
//
// A vector value may be created explicitly using the bracketed list syntax
// "[<exprlist>]", where <exprlist> is a comma-delimited list of expressions,
// or the vector comprehension syntax "[<expr> <forlist>]" in which <expr> is
// an expression and <forlist> is a sequence of clauses of the form "for <ident>
// in <genexpr>" or "for <ident> in <genexpr> if <predexpr>". In the vector
// comprehension case, each identifier <ident> is successively bound to elements
// of its generating expression <genexpr>, which must evaluate to a vector. If
// the predicate expression <predexpr> exists, then those bindings are dropped
// for which it evaluates to either false or to a unit-length vector whose
/// element is false. The remaining bindings are collected into an ordered set,
// and the rest of <forlist> is similarly evaluated once with each binding
// in this set in scope, resulting in a set of bindings for every identifier.
// Finally <expr> is evaluated once for each tuple of bindings in the
// lexicographically ordered Cartesian product of all of the binding sets, and
// the results of bindings in the product, and the results form the vector
// elements of the evaluated vector comprehension. Any nested vector structure
// that arises transiently during the evaluation of any vector is immediately
// flattened; all vectors end up with only scalar or Node elements.
//
// The value of an expression of the form "let <ident> = <expr1> in <expr2>"
// is the result of evaluating <expr2> with the symbol <ident> bound to the
// value of <expr1>. Let expressions associate right to left.
//
// All numbers are represented by float64 values. Thus all integer magnitudes
// up to 2^53, or approximately 9*10^15, (as well as much larger magnitudes
// that for integer multiples of powers of 2) can be represented exactly. The
// built-in function int can be used to round a number to the nearest integer
// value. The integer division operator // and the modulo operator % are defined
// such that x//y = floor(x/y) and (x//y)*y + x%y = x. Number literals may
// include underscores as separators between digits to improve legibility.
//
// String literals are specified using double quotes. Within double quotes, a
// backslash followed by any character (including a backslash or a double quote)
// represents that character.
//
// Regular expression literals are specified using single quotes. Within single
// quotes, two successive single quotes are interpreted as one single quote.
//
// The expressions "<expr> =~ '<regex>'" and "<expr> !~ '<regex>'" return true
// and false respectively if the expression <expr> is string-valued and matches
// the regular expression <regex>. If the match succeeds and <regex> contains
// n parenthesized "capturing groups", then the special symbol references $1,
// $2, ..., $n may be used to refer to the matched contents of these groups
// until another regular expression match succeeds.
type Expression interface {
	// String returns the expression text used to create this Expression.
	String() string

	// Symbols returns a sorted list of the names of all symbols referenced in
	// the expression. Returns an empty slice if the expression references no
	// symbols.
	Symbols() []string

	// Functions returns a sorted list of the names of all functions referenced
	// in the expression. Returns an empty slice if the expression references no
	// functions.
	Functions() []string

	// Dump writes a detailed description of this Expression to the specified
	// writer. Intended for diagnostic use, it generates a multi-line output
	// that lists the original expression text along with the token sequence
	// and the abstract syntax tree it generated.
	Dump(writer io.Writer)

	// Evaluate returns the result of evaluating this Expression in the given
	// context. On success, it returns an interface{} value that holds a scalar
	// value (nil, bool, float64, or string), a Node value, or a vector of
	// scalar and/or Node values in the form of a slice of type []interface{}.
	// On failure it returns an error containing a *EvaluationError. It logs
	// from every successful path expression evaluation to the context's node
	// access logger if it not nil, and it writes a detailed report to the
	// context's evaluation tracer if is is not nil. It does not modify anything
	// else within the context.
	Evaluate(context EvaluationContext) (interface{}, error)
}

// NewExpression returns a new Expression value from the specified expression
// text. On syntax errors it returns nil and an error with concrete type
// *ExpressionError. See Expression for a description of accepted expression // syntax.
func NewExpression(text string) (Expression, error) {
	return compileExpr(text)
}

// Expression implementation.
type exprImpl struct {
	text    string   // original expression text
	tokens  []token  // tokens from scan
	astRoot *astNode // abstract syntax tree from parse
}

func (e *exprImpl) String() string {
	return e.text
}

func (e *exprImpl) Symbols() []string {
	return astSymbols(e.astRoot)
}

func (e *exprImpl) Functions() []string {
	return astFunctions(e.astRoot)
}

func (e *exprImpl) Dump(writer io.Writer) {
	dumpExpression(e, writer)
}

func (e *exprImpl) Evaluate(context EvaluationContext) (result interface{}, err error) {
	return evaluateExpression(e, context)
}

// Returns the Expression that results from compiling the given expression text.
// On failure, returns nil and an error with concrete type *ExpressionError.
func compileExpr(text string) (Expression, error) {
	// First do a lexical scan to generate a token sequence.
	tokens, err := scanExpression(text)
	if err != nil {
		return nil, err
	} else if len(tokens) == 0 {
		return nil, ExpressionErrorf(text, 0, "empty expression")
	}

	// Now parse the token sequence to an AST.
	ast, ntokens, err := parseExpr(tokens)
	if err != nil {
		offset := err.(*tokenError).token.Offset()
		return nil, ExpressionErrorf(text, offset, "%w: %q", err, snippet(text, offset, 50))
	} else if ntokens < len(tokens) {
		// Parse didn't consume all the tokens.
		offset := tokens[ntokens].Offset()
		return nil, ExpressionErrorf(text, offset, "unexpected: %q", snippet(text, offset, 50))
	} else if tokenIsOperator(ast.token, operComma) {
		// Comma not allowed at top level.
		offset := ast.token.Offset()
		return nil, ExpressionErrorf(text, offset, "unexpected top-level comma: %q", snippet(text, offset, 50))
	} else if _, isRe := ast.token.(*singleQuoteToken); isRe {
		// Regular expression not allowed at top level.
		offset := ast.token.Offset()
		return nil, ExpressionErrorf(text, offset, "unexpected top-level regular expression: %q", snippet(text, offset, 50))
	}

	return &exprImpl{text, tokens, ast}, nil
}

// DumpExpression writes a detailed description of an Expression of the type
// created by NewExpression. Intended for diagnostic use, it generates a
// multi-line output that lists the original expression text, the token
// sequence, and the abstract syntax tree it generated.
func dumpExpression(expr Expression, writer io.Writer) {
	e := expr.(*exprImpl)
	indent := "    "

	fmt.Fprintf(writer, "text: %s\n", e.text)

	fmt.Fprintf(writer, "tokens:\n")
	for _, t := range e.tokens {
		dumpToken(writer, indent, t)
	}

	fmt.Fprintf(writer, "ast:\n")
	dumpAst(writer, indent, 1, e.astRoot)
}

func dumpToken(w io.Writer, indent string, t token) {
	fmt.Fprintf(w, "%s%s %q at %d\n", indent, reflect.Indirect(reflect.ValueOf(t)).Type().Name(), t.Text(), t.Offset())
}

func dumpAst(w io.Writer, indent string, depth int, a *astNode) {
	for i := 0; i < depth; i++ {
		fmt.Fprintf(w, "%s", indent)
	}
	if a != nil {
		dumpToken(w, "", a.token)
		if a.left != nil || a.right != nil {
			dumpAst(w, indent, depth+1, a.left)
		}
		if a.right != nil {
			dumpAst(w, indent, depth+1, a.right)
		}
	} else {
		fmt.Fprintf(w, "nil\n")
	}
}

// EvaluationContext defines methods for obtaining contextual information
// needed while evaluating an Expression.
type EvaluationContext interface {
	// YamlRoot returns the global root of the YAML tree that any path
	// expressions in the Expression are to be matched against.
	YamlRoot() Node

	// YamlRef returns the reference ("root") node for path expressions in
	// the Expression unless that node is the same as the global root, in
	// which case YamlRef may return nil. The returned node (if non-nil)
	// must be a descendant of the node returned by YamlRoot.
	YamlRef() Node

	// Symbols returns the symbol table to be used during expression evaluation.
	// It returns a map of symbol names to symbol values, each of which may be
	// nil or of type bool, float64, string, or Node (representing a scalar) or
	// []interface{} (representing a vector) in which every element is of one
	// of these supported scalar types.
	Symbols() map[string]interface{}

	// Functions returns the function table to be used during expression
	// evaluation. It returns a map of function names to implementations, all
	// of which must be of type ScalarFunction or GeneralFunction.
	Functions() map[string]interface{}

	// NodeLogger returns a destination to which YAML node accesses are logged
	// during evaluation. Must be non-nil.
	NodeLogger() NodeAccessLogger

	// EvalTracer returns a destination to which detailed tracing text is
	// written during evaluation. A nil return value means tracing text is not
	// written.
	EvalTracer() io.Writer

	// AddSymbols returns a copy of the receiver EvaluationContext in which
	// all the symbols defined in newSymbols have been added to the symbol
	// table (see Symbols). Any symbol name conflicts are resolved in favor
	// of newSymbols. The mapped values in newSymbols must all be nil, bool,
	// float64, string, Node, or []interface{} containing only such values.
	// Any other value type causes a non-nil error to be returned.
	AddSymbols(newSymbols map[string]interface{}) (EvaluationContext, error)

	// AddFunctions returns a copy of the receiver EvaluationContext in which
	// all the functions defined in newFunctions have been added to the
	// function table (see Functions). Any function name conflicts are resolved
	// in favor of newFunctions. The mapped values in newFunctions must all be
	// of type ScalarFunction or GeneralFunction. Any other value type causes
	// a non-nil error to be returned.
	AddFunctions(newFunctions map[string]interface{}) (EvaluationContext, error)

	// Copy returns a copy of the receiver EvaluationContext. The copy's
	// Symbols and Functions methods must return different map instances than
	// the receiver's.
	Copy() EvaluationContext

	// Interface to the service table (if any). Returns an array of
	// "<PROTOCOL><PORT>" strings.  Eg, ["tcp80", "tcp443"]. They argument is
	// the name of a service found in the ZPL.
	ServiceByName(string) []string
}

// A basic EvaluationContext implementation.
type BasicContext struct {
	yamlRoot   Node
	yamlRef    Node
	symbols    map[string]interface{}
	functions  map[string]interface{}
	services   map[string][]string
	nodeLogger NodeAccessLogger
	evalTracer io.Writer
}

// NewBasicContext creates a BasicContext instance. The first argument must
// be the root of the YAML tree from which any path expressions will be
// resolved. The second argument, if not nil, specifies optional parameters
// for the returned instance. The new instance copies data from the options
// (e.g., symbol and function tables) and shares no mutable state with them.
// If no NodeAccessLogger is specified in the options, the returned instance's
// NodeLogger method returns an instance of NullNodeLogger. A non-nil error is
// returned if a symbol or function table in options contains any values of
// unsupported types (see Symbols and Functions).
func NewBasicContext(yamlRoot Node, options *BasicContextOptions) (EvaluationContext, error) {
	if options == nil {
		options = &BasicContextOptions{}
	}

	// Set up a null logger if caller didn't specify one.
	logger := options.NodeLogger
	if logger == nil {
		logger = &NullNodeAccessLogger{}
	}

	// Create the new instance. Use the Add* functions to get type checking.
	ctx0 := &BasicContext{
		yamlRoot:   yamlRoot,
		yamlRef:    options.YamlRef,
		services:   options.Services,
		nodeLogger: logger,
		evalTracer: options.EvalTracer}
	if ctx1, err := ctx0.AddSymbols(options.Symbols); err != nil {
		return nil, err
	} else if ctx2, err := ctx1.AddFunctions(options.Functions); err != nil {
		return nil, err
	} else {
		return ctx2, nil
	}
}

// NewBasicContextOk is a variant of NewBasicContext that returns a new
// BasicContext instance when the arguments, including any options, are all
// valid. It panics otherwise.
func NewBasicContextOk(yamlRoot Node, options *BasicContextOptions) EvaluationContext {
	if ctx, err := NewBasicContext(yamlRoot, options); err != nil {
		panic(err)
	} else {
		return ctx
	}
}

// BasicContextOptions encapsulates optional parameters for NewBasicContext.
type BasicContextOptions struct {
	// YamlRef (if not nil) is the reference node for path expressions.
	YamlRef Node

	// Symbols is the symbol table.
	Symbols map[string]interface{}

	// Functions is the function table.
	Functions map[string]interface{}

	// NodeLogger is the node access logger.
	NodeLogger NodeAccessLogger

	// EvalTracer is the destination for evaluation tracing.
	EvalTracer io.Writer

	// Parsed services index, with services expanded into "<PROTOCOL><PORT"
	// strings.
	Services map[string][]string
}

func (ctx *BasicContext) YamlRoot() Node {
	return ctx.yamlRoot
}

func (ctx *BasicContext) YamlRef() Node {
	return ctx.yamlRef
}

func (ctx *BasicContext) Symbols() map[string]interface{} {
	return ctx.symbols
}

func (ctx *BasicContext) Functions() map[string]interface{} {
	return ctx.functions
}

func (ctx *BasicContext) NodeLogger() NodeAccessLogger {
	return ctx.nodeLogger
}

func (ctx *BasicContext) EvalTracer() io.Writer {
	return ctx.evalTracer
}

func (ctx *BasicContext) AddSymbols(newSymbols map[string]interface{}) (EvaluationContext, error) {
	ctxCopy := *ctx
	ctxCopy.symbols = make(map[string]interface{}, len(ctx.symbols))
	for k, v := range ctx.symbols {
		ctxCopy.symbols[k] = v
	}
	for k, v := range newSymbols {
		switch x := v.(type) {
		case nil, bool, float64, string, Node:
		case []interface{}:
			for _, vv := range x {
				switch vv.(type) {
				case nil, bool, float64, string, Node:
				default:
					return nil, fmt.Errorf("invalid element type for symbol %q: %v", k, reflect.TypeOf(vv))
				}
			}
		default:
			return nil, fmt.Errorf("invalid type for symbol %q: %v", k, reflect.TypeOf(v))
		}
		ctxCopy.symbols[k] = v
	}
	return &ctxCopy, nil
}

func (ctx *BasicContext) AddFunctions(newFunctions map[string]interface{}) (EvaluationContext, error) {
	ctxCopy := *ctx
	ctxCopy.functions = make(map[string]interface{}, len(ctx.functions))
	for k, v := range ctx.functions {
		ctxCopy.functions[k] = v
	}
	for k, v := range newFunctions {
		switch v.(type) {
		case ScalarFunction, GeneralFunction:
		default:
			return nil, fmt.Errorf("invalid type for function %q: %v", k, reflect.TypeOf(v))
		}
		ctxCopy.functions[k] = v
	}
	return &ctxCopy, nil
}

func (ctx *BasicContext) Copy() EvaluationContext {
	ctxCopy := *ctx
	ctxCopy.symbols = make(map[string]interface{}, len(ctx.symbols))
	for k, v := range ctx.symbols {
		ctxCopy.symbols[k] = v
	}
	ctxCopy.functions = make(map[string]interface{}, len(ctx.functions))
	for k, v := range ctx.functions {
		ctxCopy.functions[k] = v
	}
	return &ctxCopy
}

func (ctx *BasicContext) ServiceByName(n string) []string {
	if ctx.services != nil {
		return ctx.services[n]
	}
	return nil
}

// NodeAccessLogger is an interface that allows accesses to a YAML node tree
// to be recorded along with optional text.
type NodeAccessLogger interface {
	// Log records the fact that a node has been retrieved from (or identified
	// in) a YAML node tree using the specified Node path. Any string arguments
	// are recorded along with the path.
	Log(path []Node, info ...string)

	// Optionally implement this if the logger keeps track of records.
	Entries() []NodeAccessLoggerRecord
}

// NullNodeAccessLogger is a null implementation of NodeAccessLogger. Its
// Log method does nothing.
type NullNodeAccessLogger struct{}

func (log *NullNodeAccessLogger) Log(path []Node, info ...string)   {}
func (log *NullNodeAccessLogger) Entries() []NodeAccessLoggerRecord { return nil }

// AppendingNodeAccessLogger is a NodeAccessLogger implementation that records
// node accesses by appending to an internal slice.
type AppendingNodeAccessLogger struct {
	// Records is a slice of node access records ordered by time of access.
	Records []NodeAccessLoggerRecord
}

func (log *AppendingNodeAccessLogger) Log(path []Node, info ...string) {
	log.Records = append(log.Records, NodeAccessLoggerRecord{path, info})
}

func (log *AppendingNodeAccessLogger) Entries() []NodeAccessLoggerRecord {
	return log.Records
}

// NodeAccessLoggerRecord records a single YAML node access. Used by AppendingNodeAccessLogger.
type NodeAccessLoggerRecord struct {
	Path []Node   // path to the accessed node
	Info []string // associated information (may be empty)
}

// ScalarFunction is the required type for externally defined scalar function
// implementations supplied to an expression evaluation through an evaluation
// context. A scalar function is one that takes scalar or Node arguments and
// returns scalar results. A scalar function can be applied to a vector, in
// which case is is applied elementwise. (It returns an empty vector when
// applied to an empty vector.) The interface{} argument passed to the
// ScalarFunction that implements a scalar function may hold a bool, float64,
// or string value. If the original argument in the expression was a Node
// corresponding to a scalar YAML node, this value will be the result of
// decoding the Node's value in a manner consistent with its YAML tag (e.g.,
// the !!int tag implies conversion to number). The ScalarFunction
// implementation must return a nil, bool, float, or string value plus a nil
// error value if it succeeds. Otherwise it must return a non-nil error value.
type ScalarFunction func(interface{}) (interface{}, error)

// GeneralFunction is the required type of externally defined general function
// implementations supplied to an expression evaluation through an evaluation
// context. Like a scalar function (see ScalarFunction), a general function may
// be invoked with scalar, vector, or Node arguments, but unlike a scalar
// function, a general function must have an implementation that is prepared to
// handle all of these types. Specifically a GeneralFunction's interface{}
// argument may hold a nil, bool, float64, string, *regexp.Regexp, or Node
// value, or it may hold a "vector" value of type []interface{} whose elements
// are all nil, bool, float64, string, *regexp.Regexp, or Node values. It must
// return a value of one of these two forms plus a nil error value if it
// succeeds. It must return a non-nil error value if it fails.
//
// When a GeneralFunction is invoked by the expression evaluator, its first
// argument is set to an EvaluationContext that is a copy of the one provided
// to Evaluate, perhaps with addition symbols defined in the symbol table.
type GeneralFunction func(EvaluationContext, interface{}) (interface{}, error)

// ExpressionError is an error implementation that describes a malformed
// expression.
type ExpressionError struct {
	// Text contains the text of the expression.
	Text string

	// Offset is the byte offset within the expression text at which an error
	// was detected.
	Offset int

	message string
	wrapped error
}

func (e *ExpressionError) Error() string {
	return e.message
}

func (e *ExpressionError) Unwrap() error {
	return e.wrapped
}

// ExpressionErrorf returns an error with a concrete type of *ExpressionError. The
// first two arguments are the associated expression text and the byte offset at
// which the error was detected. The remaining arguments are as for fmt.Errorf.
func ExpressionErrorf(text string, pos int, format string, args ...interface{}) error {
	args1 := append([]interface{}{text}, args...)
	err := fmt.Errorf("syntax error in %+q: "+format, args1...)
	return &ExpressionError{text, pos, err.Error(), errors.Unwrap(err)}
}

// EvaluationError is an error implementation that describes a failed expression
// evaluation.
type EvaluationError struct {
	// Text returns the text of the expression.
	Text string

	// Offset is the byte offset within the expression text of an operation or
	// term associated with the evaluation failure (or zero for the expression
	// as a whole).
	Offset int

	message string
	wrapped error
}

func (e *EvaluationError) Error() string {
	return e.message
}

func (e *EvaluationError) Unwrap() error {
	return e.wrapped
}

// ExpressionErrorf returns an error with a concrete type of *ExpressionError. The
// first two arguments are the associated expression text and the byte offset at
// which the error was detected. The remaining arguments are as for fmt.Errorf.
func EvaluationErrorf(text string, pos int, format string, args ...interface{}) error {
	args1 := append([]interface{}{text}, args...)
	err := fmt.Errorf("failed to evaluate expression %+q: "+format, args1...)
	return &ExpressionError{text, pos, err.Error(), errors.Unwrap(err)}
}
