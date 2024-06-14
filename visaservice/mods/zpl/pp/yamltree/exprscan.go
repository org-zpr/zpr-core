package yamltree

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var (
	spaceRe        = regexp.MustCompile(`^\s+`)
	operatorRe     = regexp.MustCompile(`^([-+*%\^,]|//?|==|!=|<=?|>=?|=~|!~|\?|:|=|(and|or|not|union|intersect|minus|equals|contains)\b)`)
	numberRe       = regexp.MustCompile(`^(?:\d[\d_]*(?:\.(?:\d[\d_]*)?)?|\.\d[\d_]*)(?:[eE][+-]?\d[\d_]*)?`)
	boolRe         = regexp.MustCompile(`^(true|false)\b`)
	nullRe         = regexp.MustCompile(`^null\b`)
	keywordRe      = regexp.MustCompile(`^(for|in|if|let)\b`)
	bracketRe      = regexp.MustCompile(`^[\(\)\[\]]`)
	freeIdentRe    = regexp.MustCompile(`[a-zA-Z_]\w*\b`)
	identRe        = regexp.MustCompile(`^(` + freeIdentRe.String() + `)`)
	symRefRe       = regexp.MustCompile(`^\$(\d+\b|` + freeIdentRe.String() + `)`)
	funcIdentRe    = regexp.MustCompile(`^(` + freeIdentRe.String() + `)\s*\(`)
	forBindIdentRe = regexp.MustCompile(`^(` + freeIdentRe.String() + `)\s*in\b`)
	letBindIdentRe = regexp.MustCompile(`^(` + freeIdentRe.String() + `)\s*=`) // would like a (?![=~]) at the end; fix in code
	allDigitsRe    = regexp.MustCompile(`^\d+$`)
)

// "Enum" type representing an operator.
type operator int

const (
	operUndef operator = iota
	operQuestion
	operColon
	operComma
	operOr
	operAnd
	operNot
	operEq
	operSingleEq
	operNe
	operLt
	operLe
	operGt
	operGe
	operLike
	operUnlike
	operEquals
	operContains
	operSetMinus
	operUnion
	operIntersect
	operPlus
	operMinus
	operMul
	operDiv
	operIntDiv
	operMod
	operPow
)

// The token interface is used for tokens identified in lexical scans of
// expression text. Some of these tokens are also used in AST nodes.
type token interface {
	Text() string
	Offset() int
}

// Base content of all token implementations.
type tokenBase struct {
	text   string // full text of token in input expression
	offset int    // byte offset of token in input expression
}

func (t *tokenBase) Text() string {
	return t.text
}

func (t *tokenBase) Offset() int {
	return t.offset
}

type spaceToken struct {
	*tokenBase
}

type nullToken struct {
	*tokenBase
}

type boolToken struct {
	*tokenBase
	value bool
}

type numberToken struct {
	*tokenBase
	value float64
}

type keywordToken struct {
	*tokenBase
}

type symbolToken struct {
	*tokenBase
	name string
}

type functionToken struct {
	*tokenBase
	name string
}

type forBindingToken struct {
	*tokenBase
	name string
}

type letBindingToken struct {
	*tokenBase
	name string
}

type singleQuoteToken struct {
	*tokenBase
	re *regexp.Regexp
}

type doubleQuoteToken struct {
	*tokenBase
	content string
}

type pathPatternToken struct {
	*tokenBase
	pattern PathPattern
}

type pathPatternSymbolToken struct {
	*tokenBase
	name    string
	pattern PathPattern
}

type bracketToken struct {
	*tokenBase
}

type operatorToken struct {
	*tokenBase
	op operator
}

// An error implementation that describes an error associated with a specific
// token. May include scanning, parsing, or evaluation errors.
type tokenError struct {
	token   token
	message string
	wrapped error
}

func (e *tokenError) Error() string {
	return e.message
}

func (e *tokenError) Unwrap() error {
	return e.wrapped
}

// Returns a tokenError for the specified token. Arguments after the first are
// as for fmt.Errorf.
func tokenErrorf(token token, format string, args ...interface{}) error {
	err := fmt.Errorf(format, args...)
	return &tokenError{token, err.Error(), errors.Unwrap(err)}
}

// Does a lexical scan on the given expression text and returns the resulting
// token sequence. On failure returns an error containing an *ExpressionError.
func scanExpression(input string) ([]token, error) {
	tokens := []token{}

	for pos, n := 0, 0; pos < len(input); pos += n {
		var t token
		var err error

		type scanner func(string, int) (token, int, error)

		// There is some order sensitivity in the token scanning sequence.
		for _, s := range []scanner{scanSpace, scanBracket, scanNull, scanBool, scanNumber, scanOperator,
			scanKeyword, scanFunctionId, scanForBindingId, scanLetBindingId, scanSingleQuote, scanDoubleQuote,
			scanPathPattern, scanPathPatternSymbolRef, scanSymbolRef,
		} {
			t, n, err = s(input, pos)
			if err != nil {
				return nil, err
			} else if t != nil {
				break
			}
		}

		if _, isspace := t.(*spaceToken); isspace {
			continue
		}

		if t == nil {
			return nil, ExpressionErrorf(input, pos, "invalid token at offset %d: %+q", pos, snippet(input, pos, 40))
		}

		tokens = append(tokens, t)
	}

	return tokens, nil
}

// Each token scanner function attempts to parse a token (really a lexeme) of
// a particular type from the input at the specified byte offset. It returns
// the scanned token, the number of bytes consumed from the input, and a nil
// error if the parse succeeds. It returns nil, 0, and an error containing a
// *ExpressionError if it finds something that initially appears to be a token
// of the required type but it is malformed (e.g., a quoted string with no
// closing quote). It returns nil, 0, nil if it finds nothing that looks liks
// a token of the required type.

// Arbitrary whitespace.
func scanSpace(input string, pos int) (token, int, error) {
	if s := spaceRe.FindString(input[pos:]); len(s) > 0 {
		return &spaceToken{&tokenBase{s, pos}}, len(s), nil
	}
	return nil, 0, nil
}

// A boolean literal.
func scanBool(input string, pos int) (token, int, error) {
	if s := boolRe.FindString(input[pos:]); len(s) > 0 {
		return &boolToken{&tokenBase{s, pos}, s == "true"}, len(s), nil
	}
	return nil, 0, nil
}

// A null literal.
func scanNull(input string, pos int) (token, int, error) {
	if s := nullRe.FindString(input[pos:]); len(s) > 0 {
		return &nullToken{&tokenBase{s, pos}}, len(s), nil
	}
	return nil, 0, nil
}

// A numeric literal. Must be expressible as a float64.
func scanNumber(input string, pos int) (token, int, error) {
	if s := numberRe.FindString(input[pos:]); len(s) > 0 {
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return nil, 0, ExpressionErrorf(input, pos, "invalid number %q: %s", s, err.(*strconv.NumError).Err)
		}
		return &numberToken{&tokenBase{s, pos}, f}, len(s), nil
	}
	return nil, 0, nil
}

// A defined keyword.
func scanKeyword(input string, pos int) (token, int, error) {
	if s := keywordRe.FindString(input[pos:]); len(s) > 0 {
		return &keywordToken{&tokenBase{s, pos}}, len(s), nil
	}
	return nil, 0, nil
}

// A symbol reference of the form $<ident>.
func scanSymbolRef(input string, pos int) (token, int, error) {
	if ss := symRefRe.FindStringSubmatch(input[pos:]); len(ss) > 0 {
		ident := ss[1]
		return &symbolToken{&tokenBase{input[pos : pos+1+len(ident)], pos}, ident}, 1 + len(ident), nil
	}
	return nil, 0, nil
}

// A function invocation of the form <ident>(... . The closing parenthesis is
// found during parsing.
func scanFunctionId(input string, pos int) (token, int, error) {
	if ss := funcIdentRe.FindStringSubmatch(input[pos:]); len(ss) > 0 {
		ident := ss[1]
		return &functionToken{&tokenBase{input[pos : pos+len(ident)], pos}, ident}, len(ident), nil
	}
	return nil, 0, nil
}

// A symbol binding of the form <ident> "in" ... .
func scanForBindingId(input string, pos int) (token, int, error) {
	if ss := forBindIdentRe.FindStringSubmatch(input[pos:]); len(ss) > 0 {
		ident := ss[1]
		return &forBindingToken{&tokenBase{input[pos : pos+len(ident)], pos}, ident}, len(ident), nil
	}
	return nil, 0, nil
}

// A symbol binding of the form <ident> "=" ... .
func scanLetBindingId(input string, pos int) (token, int, error) {
	if ss := letBindIdentRe.FindStringSubmatch(input[pos:]); len(ss) > 0 {
		// Make sure the "=" isn't part of "==" or "=~" (regexp package doesn't support lookahead)
		pos1 := pos + len(ss[0])
		if pos1 < len(input) && strings.ContainsAny(input[pos1:pos1+1], "~=") {
			return nil, 0, nil
		}
		ident := ss[1]
		return &letBindingToken{&tokenBase{input[pos : pos+len(ident)], pos}, ident}, len(ident), nil
	}
	return nil, 0, nil
}

// A regular expression in single quotes.
func scanSingleQuote(input string, pos int) (token, int, error) {
	contents, nbytes, err := parseSingleQuoteString(input, pos)
	if err != nil {
		return nil, 0, ExpressionErrorf(input, pos, "%w", err)
	} else if nbytes == 0 {
		return nil, 0, nil
	} else {
		re, err := regexp.Compile(contents)
		if err != nil {
			return nil, 0, ExpressionErrorf(input, pos, "%w", err)
		}
		return &singleQuoteToken{&tokenBase{input[pos : pos+nbytes], pos}, re}, nbytes, nil
	}
}

// A string literal in double quotes.
func scanDoubleQuote(input string, pos int) (token, int, error) {
	contents, nbytes, err := parseDoubleQuoteString(input, pos)
	if err != nil {
		return nil, 0, ExpressionErrorf(input, pos, "%w", err)
	} else if nbytes == 0 {
		return nil, 0, nil
	} else {
		return &doubleQuoteToken{&tokenBase{input[pos : pos+nbytes], pos}, contents}, nbytes, nil
	}
}

// A path expression. Must be convertible to a PathPattern.
func scanPathPattern(input string, pos int) (token, int, error) {
	pattern, n, err := ParsePathExpression(input[pos:])
	if err != nil {
		perr := err.(*PathPatternError)
		return nil, 0, ExpressionErrorf(input, pos+perr.Offset, "invalid path expression %+q: %w", snippet(input, pos, 40), err)
	} else if n != 0 {
		return &pathPatternToken{&tokenBase{input[pos : pos+n], pos}, pattern}, n, nil
	}
	return nil, 0, nil
}

// A symbol reference with an attached path expression.
func scanPathPatternSymbolRef(input string, pos int) (token, int, error) {
	if ss := symRefRe.FindStringSubmatch(input[pos:]); len(ss) > 0 {
		ident := ss[1]
		patPos := pos + 1 + len(ident)
		pattern, n, err := ParsePathExpression(input[patPos:])
		if err != nil {
			perr := err.(*PathPatternError)
			return nil, 0, ExpressionErrorf(input, patPos+perr.Offset, "invalid path expression symbol reference %+q: %w", snippet(input, pos, 40), err)
		} else if n != 0 {
			return &pathPatternSymbolToken{&tokenBase{input[pos : patPos+n], pos}, ident, pattern}, 1 + len(ident) + n, nil
		}
	}
	return nil, 0, nil
}

// A bracket. Matching brackets are located at parse time.
func scanBracket(input string, pos int) (token, int, error) {
	if s := bracketRe.FindString(input[pos:]); len(s) > 0 {
		return &bracketToken{&tokenBase{s, pos}}, len(s), nil
	}
	return nil, 0, nil
}

// An operator. Arity is determined at parse time.
func scanOperator(input string, pos int) (token, int, error) {
	if s := operatorRe.FindString(input[pos:]); len(s) > 0 {
		op := operUndef
		switch s {
		case "and":
			op = operAnd
		case "or":
			op = operOr
		case "=":
			op = operSingleEq
		case "==":
			op = operEq
		case "!=":
			op = operNe
		case "<":
			op = operLt
		case "<=":
			op = operLe
		case ">":
			op = operGt
		case ">=":
			op = operGe
		case "=~":
			op = operLike
		case "!~":
			op = operUnlike
		case "equals":
			op = operEquals
		case "contains":
			op = operContains
		case "minus":
			op = operSetMinus
		case "union":
			op = operUnion
		case "intersect":
			op = operIntersect
		case "+":
			op = operPlus
		case "-":
			op = operMinus
		case "*":
			op = operMul
		case "/":
			op = operDiv
		case "//":
			op = operIntDiv
		case "%":
			op = operMod
		case "^":
			op = operPow
		case "not":
			op = operNot
		case ",":
			op = operComma
		case "?":
			op = operQuestion
		case ":":
			op = operColon
		default:
			panic(fmt.Sprintf("unknown operator %q", op))
		}
		return &operatorToken{&tokenBase{s, pos}, op}, len(s), nil
	}
	return nil, 0, nil
}
