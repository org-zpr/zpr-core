package yamltree

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// PathPattern represents a pattern for matching descending paths through a
// YAML document tree represented by Node objects. See NewPathPattern.
type PathPattern interface {
	// String returns the text of the pattern expression used to create this
	// object.
	String() string

	// Compiled returns the result of compiling this object's pattern
	// expression.
	Compiled() CompiledPathPattern
}

// Internal PathPattern implementation.
type pathPatternImpl struct {
	text     string    // original path expression text
	matchers []matcher // compilation results
}

func (p *pathPatternImpl) String() string {
	return p.text
}

func (p *pathPatternImpl) Compiled() CompiledPathPattern {
	return CompiledPathPattern{p.matchers}
}

// NewPathPattern creates a new PathPattern object for the given path pattern
// expression. It returns a non-nil error containing a *PathPatternError if
// the argument is not a valid path pattern expression as described below.
// The argument is interpreted as a UTF-8 string.
//
// The following are some examples of valid path pattern expression and the
// terminal nodes of the paths they would match in a Node tree:
//
//     Expression    Matched terminal nodes
//     ----------    ----------------------
//     .             root node
//     .foo          node mapped to key named "foo" under root node
//     .foo.bar      node mapped to key named "bar" under ".foo" node
//     foo.bar       same as .foo (leading "." may be omitted)
//     foo.bar$      same as foo.bar but only matches if last node is a leaf
//     foo.[0]       first sequence element node under "foo" node
//     foo[0]        same as foo.[0] (may omit "." before "[")
//     foo.bar*      all nodes mapped to keys whose names start with "bar"
//                   under "foo" node ("*" wildcards supported in key
//                   selectors)
//     foo."bar *"   node mapped to key "bar *" under "foo" node (arbitrary
//                   text supported in key selectors using qouble quotes)
//     foo.'^bar'    same as foo.bar* (regular expressions supported in key
//                   selectors using single quotes)
//     foo.!bar      all nodes mapped to keys whose names are not "bar" under
//                   "foo" node ("!" negates; also works with wildcard patterns
//                   and regular expressions)
//     foo.bar$xyz   same as foo.bar$ but only matches if leaf value is "xyz"
//     foo.bar$*z    same as foo.bar$ but only matches if leaf value ends in "z"
//     foo.bar$"x z" same as foo.bar$ but only matches if leaf value is "x z"
//                   (arbitrary text supported in value selectors using double
//                   quotes)
//     foo.bar$'z$'  same as foo.bar$*z (regular expressions supported in value
//                   selectors using single quotes)
//     foo.bar$!xyz  same as foo.bar$ but only matches if leaf value is not
//                   "xyz" ("!" negates; also works with wildcard patterns and
//                   regular expressions)
//     foo.bar*[*]   all sequence element nodes under all ".foo.bar*" nodes
//     foo.**.bar    all nodes mapped to keys named "bar" under ".foo" node or
//                   under any descendants of ".foo" node reachable through
//                   nested mappings
//     foo.[**].bar  all nodes mapped to keys named "bar" under ".foo" node or
//                   under any descendants of ".foo" node reachable through
//                   nested sequences
//     foo.@.bar     nodes matched by either ".foo.*.bar" or ".foo.[*].bar"
//     foo.@@.bar    nodes matched by either ".foo.**.bar" or ".foo.[**].bar"
//     @@            all nodes except the root
//     @@$           all leaf nodes
//     foo.@@$bar*   all leaf nodes under ".foo" whose values start with "bar"
//     foo.@@$'\d$'  all leaf nodes under ".foo" whose values end with a digit
//     foo.{x.y}bar  same as foo.bar except only matches if foo.x.y also exists
//     foo.!{x.y}bar same as foo.bar except only matches if foo.x.y does not
//                   exist
//     foo{[*].x}[0] same as foo.[0] except only matches if foo[*].x also exists
//     foo!{[1]}[0]  same as foo.[0] except only matches if foo[1] does not
//                   exist
//
// Nodes only match parts of a path pattern if they have the appropriate type.
// For example, if the terminal node of a path matching "foo.bar" is a mapping
// node, then "foo.bar[*]" and "foo.bar$" match nothing.
//
// Sequence node indexing starts at 0. Negative indices count from the end of
// the sequence, with -1 indicating the last element.
//
// The simple wildcards "*", "[*]", and "@" can match at most one node in a
// path, while the arbitrary descent wildcards "**", "[**]", and "@@" match
// sub-paths of one or more nodes.
//
// Bare (unquoted) key and value selectors may contain only letters, digits,
// underscores, and asterisks. Key and value selectors selectors in double
// quotes may include any characters at all. Within double quotes, a double
// quote or backslash must be escaped by preceding by a backslash. In fact,
// any character may be included by backslash-escaping it.
//
// Key and value selectors in single quotes are treated as regular expressions
// that must match some part of a key's name or a leaf node's value. The allowed
// regular expression syntax is that of the standard go regexp package, which is
// essentially that of RE2 (https://golang.org/s/re2syntax). Single quotes may
// be included in regular expressions by doubling them.
//
// If a key or value selector or the index within an index selector is preceded
// by "!", then matching is inverted: a node only is only considered to match if
// it does not match the selector.
//
// A key or index selector may be preceded by one or more lookaside assertions,
// each consisting of a path pattern expression enclosed in "{" and "}" and
// optionally prefixed by "!". Before a match of the key or index selector is
// attempted at some node in a path, all its lookaside assertions' expressions
// are tested for matches relative to the node's parent. All must produce at
// least one match (or, if a "!" is present, zero matches) in order for matching
// to continue with the key or index selector.
//
// If a path pattern expression contains an unquoted "$", then it only matches
// paths that end in leaf (scalar) nodes. Anything after the (first) "$" is a
// value selector which must match the string value of a path's leaf node in
// order for the path to match.
//
// Path pattern expressions obey the following grammar:
//
//     expr      = free ("$" val?)? .
//     free      = "."
//               | "."? (brack | nonbrack) ("."? brack | "." nonbrack)* .
//     brack     = "!"? assert* "[" ("*" | "**" | ("+" | "-")? digits+) "]" .
//     nonbrack  = "!"? assert* ("*" "*"? | "@" "@"? | "*"? nsbare bare* |
//                               "'" sqsafe* ("'" "'" sqsafe*)* "'" |
//                               """ dqsafe* ("\" (""" | "\") dqsafe*)* """) .
//     val       = "!"? (bare+ |
//                       "'" sqsafe* ("'" "'" sqsafe*)* "'" |
//                       """ dqsafe* ("\" (""" | "\") dqsafe*)* """) .
//     assert    = "!"? "{" expr "}"
//     bare      = ? any digit or letter or _ or * ?
//     nsbare    = ? any digit or letter or _ ?
//     sqsafe    = ? any character except ' ?
//     dqsafe    = ? any character except " or \ ?
//
// Legend: X? = optional X, X+ = one or more X, X* = zero or more X, ? text ?
// means what text says.
func NewPathPattern(expr string) (PathPattern, error) {
	matchers, _, err := compilePathPatternExpression(expr, true)
	if err != nil {
		return nil, err
	}
	return &pathPatternImpl{expr, matchers}, nil
}

// NewPathPatternOk creates a new PathPattern object for the given path pattern
// expression, which it assumes to be valid. A thin wrapper for NewPathPattern,
// it panics instead of returning an error code if the argument expression is
// invalid.
func NewPathPatternOk(expr string) PathPattern {
	pat, err := NewPathPattern(expr)
	if err != nil {
		panic(err)
	}
	return pat
}

// ParsePathExpression attempts to parse a path pattern expression at the start
// of the input string. On success it returns a corresponding PathPattern and
// the number of bytes consumed from the input string. It returns nil and zero
// if the first code point in input (which it assumes to be UTF-8) cannot start
// a valid path expression. Otherwise it consumes bytes until it encounters a
// code point that could not possibly be considered part of the path expression
// parsed so far. Parsing fails if input contains an unterminated quoted or
// bracketed subexpression or an invalid regular expression or if it does not
// contain a valid UTF-8 string. In that case an error with a concrete type of
// *PathPatternError is returned.
func ParsePathExpression(input string) (PathPattern, int, error) {
	matchers, n, err := compilePathPatternExpression(input, false)
	if err != nil {
		return nil, 0, err
	} else if n == 0 {
		return nil, 0, nil
	} else {
		return &pathPatternImpl{input[:n], matchers}, n, nil
	}
}

// CompiledPathPattern represents the results of compiling a path pattern
// expression.
type CompiledPathPattern struct {
	matchers []matcher
}

// A node child matcher. Created by path pattern compiler, used by path
// pattern matcher.
type matcher interface {
	// Returns all children of the argument node that match this object.
	// Preserves ordering of sequence node children when more than one
	// match. Returns an empty slice if no children match.
	matchChildren(parent Node) []Node
}

// Matches mapping node children whose keys match (or don't match) a
// given name exactly.
type literalKeyMatcher struct {
	key    string
	negate bool
}

func (m *literalKeyMatcher) matchChildren(parent Node) []Node {
	if parent.Kind() != MappingKind {
		return []Node{}
	} else {
		children := parent.Value().(map[string]Node)
		if !m.negate {
			if child, exists := children[m.key]; exists {
				return []Node{child}
			} else {
				return []Node{}
			}
		} else {
			matches := make([]Node, 0, len(children))
			for key, child := range children {
				if key != m.key {
					matches = append(matches, child)
				}
			}
			return matches
		}
	}
}

// Matches all mapping node children.
type anyKeyMatcher struct{}

func (m *anyKeyMatcher) matchChildren(parent Node) []Node {
	matches := []Node{}
	if parent.Kind() == MappingKind {
		for _, child := range parent.Value().(map[string]Node) {
			matches = append(matches, child)
		}
	}
	return matches
}

// Matches mapping node children whose key names match (or do not match) a
// regular expression.
type regexKeyMatcher struct {
	re     *regexp.Regexp
	negate bool
}

func (m *regexKeyMatcher) matchChildren(parent Node) []Node {
	if parent.Kind() != MappingKind {
		return []Node{}
	} else {
		matches := []Node{}
		for key, child := range parent.Value().(map[string]Node) {
			if m.re.MatchString(key) == !m.negate {
				matches = append(matches, child)
			}
		}
		return matches
	}
}

// Matches sequence node children whose indices match (or do not match) a
// given value exactly.
type literalIndexMatcher struct {
	index  int
	negate bool
}

func (m *literalIndexMatcher) matchChildren(parent Node) []Node {
	if parent.Kind() != SequenceKind {
		return []Node{}
	} else {
		children := parent.Value().([]Node)
		var posIndex int
		if m.index >= 0 {
			posIndex = m.index
		} else {
			posIndex = len(children) + m.index
		}
		if !m.negate {
			if posIndex < len(children) {
				return []Node{children[posIndex]}
			} else {
				return []Node{}
			}
		} else {
			matches := make([]Node, 0, len(children))
			for i, child := range children {
				if i != posIndex {
					matches = append(matches, child)
				}
			}
			return matches
		}
	}
}

// Matches all sequence node children (preserving order).
type anyIndexMatcher struct{}

func (m *anyIndexMatcher) matchChildren(parent Node) []Node {
	matches := []Node{}
	if parent.Kind() == SequenceKind {
		for _, child := range parent.Value().([]Node) {
			matches = append(matches, child)
		}
	}
	return matches
}

// Matches both mapping and sequence node children indiscriminantly.
type anyKeyOrIndexMatcher struct{}

func (m *anyKeyOrIndexMatcher) matchChildren(parent Node) []Node {
	return append((&anyKeyMatcher{}).matchChildren(parent), (&anyIndexMatcher{}).matchChildren(parent)...)
}

// Matches all mapping node children. Used for arbitrary mapping descent
// operator "**". (The matching code handles the required recursion.)
type mappingDescentMatcher struct{}

func (m *mappingDescentMatcher) matchChildren(parent Node) []Node {
	return (&anyKeyMatcher{}).matchChildren(parent)
}

// Matches all sequence node children. Used for arbitrary sequence descent
// operator "[**]". (The matching code handles the required recursion.)
type sequenceDescentMatcher struct{}

func (m *sequenceDescentMatcher) matchChildren(parent Node) []Node {
	return (&anyIndexMatcher{}).matchChildren(parent)
}

// Matches all mapping or sequence node children. Used for arbitrary descent
// operator "@@". (The matching code handles the required recursion.)
type anyDescentMatcher struct{}

func (m *anyDescentMatcher) matchChildren(parent Node) []Node {
	return append((&anyKeyMatcher{}).matchChildren(parent), (&anyIndexMatcher{}).matchChildren(parent)...)
}

// Lookaside assertion matcher. Contains a matcher sequence that must match
// (or not match) at least one path from a node in order for the next key or
// index matcher to be considered.
type lookasideMatcher struct {
	matchers []matcher
	negate   bool
}

func (m *lookasideMatcher) matchChildren(parent Node) []Node {
	return []Node{}
}

// End assertion matcher. Used to assert that a node has no children and that
// its scalar value matches (or does not match) a regular expression.
type endMatcher struct {
	re     *regexp.Regexp // applies to value, not children
	negate bool           // applies to value, not children
}

func (m *endMatcher) matchChildren(parent Node) []Node {
	return []Node{}
}

// PathPatternError describes an error associated with a malformed path
// pattern expression.
type PathPatternError struct {
	// Expression is the associated path pattern expression
	Expression string

	// Byte offset into path pattern expression at which error was detected.
	Offset int

	message string
	wrapped error
}

func (e *PathPatternError) Error() string {
	return e.message
}

func (e *PathPatternError) Unwrap() error {
	return e.wrapped
}

// PathPatternErrorf creates an error containing a *PathPatternError. The first
// two arguments are the associated path pattern expression and the byte offset
// of the error within it. Subsequent arguments are as for fmt.Errorf.
func PathPatternErrorf(expr string, offset int, format string, args ...interface{}) error {
	args1 := append([]interface{}{expr}, args...)
	err := fmt.Errorf("malformed path pattern expression %+q: "+format, args1...)
	return &PathPatternError{expr, offset, err.Error(), errors.Unwrap(err)}
}

// PathError describes an error associated with a path in a Node tree.
type PathError struct {
	// Path is the associated Node path.
	Path []Node

	message string
	wrapped error
}

func (e *PathError) Error() string {
	return e.message
}

func (e *PathError) Unwrap() error {
	return e.wrapped
}

func (e *PathError) String() string {
	if e.wrapped == nil {
		return fmt.Sprintf("yamltree.PathError: %v", e.Error())
	}
	return fmt.Sprintf("yamltree.PathError: %v (nested error: %v)", e.Error(), e.wrapped.Error())
}

// PathErrorf constructs an error value containing a *PathError. The first
// argument is the associated path. Subsequent arguments are as for fmt.Errorf.
func PathErrorf(path []Node, format string, args ...interface{}) error {
	formatSource := func(src NodeSource, includeFile bool) string {
		file := src.File
		if file == "" {
			file = "?"
		}
		if includeFile {
			return fmt.Sprintf("%s:%d:%d", file, src.Line, src.Column)
		} else {
			return fmt.Sprintf("%d:%d", src.Line, src.Column)
		}
	}

	var location strings.Builder

	if expr, err := PathExpression(path); err == nil {
		location.WriteString(expr)
		location.WriteString(" at ")
	}

	sources := PathSources(path)
	location.WriteString(formatSource(sources[0], true))
	for i := 1; i < len(sources); i++ {
		location.WriteString(" via " + formatSource(sources[i], sources[i].File != sources[i-1].File))
	}

	args1 := append([]interface{}{location.String()}, args...)
	err := fmt.Errorf("[%s] "+format, args1...)

	return &PathError{path, err.Error(), errors.Unwrap(err)}
}

// PathSources returns information about where the argument path's nodes were
// defined. The first element of the returned slice describes the location of
// the path's final node, and subsequent elements describe the locations of
// any nodes along the path, in reverse order, at which "discontinuities" such
// as alias dereferences or tree manipulations using ReplaceNode or
// AddNodesToMapping occurred.
func PathSources(path []Node) []NodeSource {
	sources := []NodeSource{}
	if len(path) > 0 {
		last := path[len(path)-1]
		sources = append(sources, last.Source())
		for i := len(path) - 1; i >= 0; i-- {
			node := path[i]
			if nodei, ok := node.(*nodeImpl); ok {
				if nodei.referrers != nil {
					for _, r := range nodei.referrers {
						sources = append(sources, *r)
					}
				}
			}
		}
	}
	return sources
}

// Compiles a path pattern expression into a sequence of matcher objects. On
// success returns the corresponding sequence of matchers, the number of bytes
// consumed from input, and a nil error. On failure returns nil, 0, and a
// PathPatternError describing the problem.
//
// If compileAll is true, input must contain a valid path pattern expression
// and nothing else, and on success the returned byte count is just the length
// of input. If compileAll is false, compilation continues only up to the first
// character of input that cannot not be interpreted as a continuation of a path
// pattern expression, a successful compilation may return a byte count smaller
// than the length of input. When compileAll is false, and error is returned if
// a closing quote or bracket is missing or a regular expression is invalid.
func compilePathPatternExpression(input string, compileAll bool) ([]matcher, int, error) {
	if !utf8.ValidString(input) {
		return nil, 0, PathPatternErrorf(input, 0, "not a valid UTF-8 string")
	}

	matchers := []matcher{}
	var err error

	// From the EBNF (see NewPathPattern), a valid path pattern expression is
	// either "." or a "free" expression (one not bound to a leaf node), both
	// optionally followed by a "$" and a value selector. A free expression is
	// of the form "."? (brack | nonbrack) ("."? brack | "." nonbrack)*, where
	// brack represents a bracketed indexing expression and nonbrack represents
	// a wildcard or key expression. This is equivalent to the slightly simpler
	// form ("."? brack | "." nonbrack)* plus the rule that a nonbrack is
	// allowed at the very start of the expression without a leading ".".
	pos := 0
	if input == "." || strings.HasPrefix(input, ".$") {
		pos++
	} else {
		for pos < len(input) {
			gotDot := false
			if input[pos] == '.' {
				gotDot = true
				pos++
			}
			if strings.HasPrefix(input[pos:], "$") {
				break
			}
			pos1 := pos
			gotBrack := false
			gotNonbrack := false
			if pos == 0 || gotDot {
				if compileNonbracket(input, &pos, &matchers, &err) {
					gotNonbrack = true
				} else if err != nil {
					return nil, 0, err
				}
			}
			if !gotNonbrack {
				if compileBracket(input, &pos, &matchers, &err) {
					gotBrack = true
				} else if err != nil {
					return nil, 0, err
				}
			}
			if !(gotNonbrack || gotBrack) {
				if compileAll {
					return nil, 0, PathPatternErrorf(input, pos1, "invalid key or index specifier: %+q", snippet(input, pos1, 20))
				} else {
					return matchers, pos1, nil
				}
			}
		}
	}
	if strings.HasPrefix(input[pos:], "$") {
		if pos > 0 {
			pos++
			compileValueSelector(input, &pos, &matchers, &err)
			if err != nil {
				return nil, 0, err
			}
		}
	}
	return matchers, pos, nil
}

// Compiles a "nonbracket" expression (i.e., a key or wildcard specifier) if
// one is present at offset *pos in the input text. On success, updates *pos
// to point after the parsed expression, appends a corresponding matcher to
// *matchers, and return true. Otherwise leaves *pos and *matchers unchanged
// and returns false. Sets *err on syntax errors.
func compileNonbracket(input string, pos *int, matchers *[]matcher, err *error) bool {
	newMatchers := []matcher{}
	pos0 := *pos
	// First collect any lookaside assertions ([!]{expr}).
	compileLookasideAssertions(input, pos, matchers, err)
	if *err != nil {
		*pos = pos0
		return false
	}
	// A key selector must follow. See if there's a "!" negation prefix. (Some
	// nonbracket expressions like "*" don't allow negation, but we can check
	// those cases later.)
	negate := false
	if strings.HasPrefix(input[*pos:], "!") {
		negate = true
		*pos++
	}
	// A key selector expression can be single-quoted, double-quoted, or bare.
	// See the EBNF in the NewPathPattern doc.
	if quoted := compileSingleQuoteExpression(input, pos, err); *err != nil {
		*pos = pos0
		return false
	} else if len(quoted) > 0 {
		// Single-quote string. Treat the contents as a regexp.
		regexp, rerr := regexp.Compile(quoted)
		if rerr != nil {
			*err = PathPatternErrorf(input, *pos, `invalid regular expression %+q: %w`, quoted, rerr)
			*pos = pos0
			return false
		}
		newMatchers = append(newMatchers, &regexKeyMatcher{regexp, negate})
		*matchers = append(*matchers, newMatchers...)
		return true
	} else if quoted := compileDoubleQuoteExpression(input, pos, err); *err != nil {
		*pos = pos0
		return false
	} else if len(quoted) > 0 {
		// Double-quote string. Treat the contents as the key selector.
		newMatchers = append(newMatchers, &literalKeyMatcher{quoted, negate})
		*matchers = append(*matchers, newMatchers...)
		return true
	} else {
		// No quotes. If anything follows it must be either a wildcard/descent
		// specifier or a bare key selector.
		n, m := 0, matcher(nil)
		switch {
		case strings.HasPrefix(input[*pos:], "@@"):
			n, m = 2, &anyDescentMatcher{}
		case strings.HasPrefix(input[*pos:], "@"):
			n, m = 1, &anyKeyOrIndexMatcher{}
		case strings.HasPrefix(input[*pos:], "**"):
			n, m = 2, &mappingDescentMatcher{}
		case strings.HasPrefix(input[*pos:], "*") && bareKeyRegexp.FindString(input[*pos:]) == "":
			n, m = 1, &anyKeyMatcher{}
		}
		if m != nil {
			wildOrDesc := input[*pos : *pos+n]
			if bareKeyRegexp.FindString(input[*pos+n:]) != "" {
				*err = PathPatternErrorf(input, *pos+n, `unexpected after %q: %q`, wildOrDesc, snippet(input, *pos+n, 20))
			} else if negate {
				*err = PathPatternErrorf(input, *pos, `illegal negation: %q`, snippet(input, *pos-1, 20))
			} else {
				*pos += n
				newMatchers = append(newMatchers, m)
				*matchers = append(*matchers, newMatchers...)
				return true
			}
		} else if keyText := bareKeyRegexp.FindString(input[*pos:]); len(keyText) > 0 {
			if strings.Index(keyText, "*") == -1 {
				newMatchers = append(newMatchers, &literalKeyMatcher{keyText, negate})
			} else {
				newMatchers = append(newMatchers, &regexKeyMatcher{regexp.MustCompile(regexpFromWildcard(keyText)), negate})
			}
			*matchers = append(*matchers, newMatchers...)
			*pos += len(keyText)
			return true
		}
		// No nonbracket expression here.
		*pos = pos0
		return false
	}
}

var bareKeyRegexp = regexp.MustCompile(`^\*?\w[\w\*]*`)
var bareValueRegexp = regexp.MustCompile(`^[\w\*]+`)

// Compiles a bracketed (index) expression if one is present at offset *pos
// in the input text. On success, updates *pos to point after the parsed
// expression, appends a corresponding matcher to *matchers, and return true.
// Otherwise leaves *pos and *matchers unchanged and returns false. Sets *err
// on syntax errors.
func compileBracket(input string, pos *int, matchers *[]matcher, err *error) bool {
	newMatchers := []matcher{}
	pos0 := *pos
	// First compile any lookaside assertions ([!]{expr}).
	compileLookasideAssertions(input, pos, matchers, err)
	if *err != nil {
		*pos = pos0
		return false
	}
	// Bail out if there is no opening '['.
	if !strings.HasPrefix(input[*pos:], "[") {
		*pos = pos0
		return false
	} else {
		// See if there's a "!" negation prefix. It's not legal for wildcard
		// indexes, but we can check for that case later.
		negate := false
		if strings.HasPrefix(input[*pos+1:], "!") {
			negate = true
			*pos++
		}
		// Everything up to the matching ']' is the index expression, which
		// must be "*", "**", or an integer. See NewPathPattern.
		end := *pos + strings.Index(input[*pos:], "]")
		if end < *pos {
			*err = PathPatternErrorf(input, *pos, `no matching "]": %+q`, snippet(input, *pos, 20))
			*pos = pos0
			return false
		}
		indexExpr := input[*pos+1 : end]
		switch indexExpr {
		case "*", "**":
			if negate {
				*err = PathPatternErrorf(input, *pos, `illegal negation: %q`, snippet(input, *pos, 20))
				*pos = pos0
				return false
			} else {
				switch indexExpr {
				case "*":
					newMatchers = append(newMatchers, &anyIndexMatcher{})
				case "**":
					newMatchers = append(newMatchers, &sequenceDescentMatcher{})
				}
			}
		default:
			index, ierr := strconv.Atoi(indexExpr)
			if ierr != nil {
				*err = PathPatternErrorf(input, *pos, "invalid index specifier: %+q", snippet(input, *pos, 20))
				*pos = pos0
				return false
			}
			newMatchers = append(newMatchers, &literalIndexMatcher{index, negate})
		}
		*matchers = append(*matchers, newMatchers...)
		*pos = end + 1 // skip the ']' too
		return true
	}
}

// Compiles a sequence of lookaside assertions if one is present at offset *pos
// in the input text. On success, updates *pos to point just after the last
// successfully parsed lookaside assertion, appends a matcher for each one to
// *matchers, and returns the number of matchers appended. Otherwise leaves *pos
// and *matchers unchanged and returns 0. Sets *err on syntax errors.
func compileLookasideAssertions(input string, pos *int, matchers *[]matcher, err *error) int {
	// A lookaside assertion is of the form [!]{expr}, where expr is a general
	// path expression.
	negate := false
	pos0 := *pos
	if strings.HasPrefix(input[*pos:], "!") {
		negate = true
		*pos++
	}
	if !strings.HasPrefix(input[*pos:], "{") {
		*pos = pos0
		return 0
	} else {
		subMatchers, n, smerr := compilePathPatternExpression(input[*pos+1:], false)
		if smerr != nil {
			*err = smerr
			*pos = pos0
			return 0
		} else if n == 0 {
			*pos = pos0
			return 0
		} else if end := *pos + 1 + n; end >= len(input) {
			*err = PathPatternErrorf(input, end, `no closing "}": %q`, snippet(input, *pos, 20))
			*pos = pos0
			return 0
		} else if input[end] != '}' {
			*err = PathPatternErrorf(input, end, `expected "}", found %q`, snippet(input, end, 20))
			*pos = pos0
			return 0
		} else {
			*matchers = append(*matchers, &lookasideMatcher{subMatchers, negate})
			*pos = end + 1 // skip the '}'
			return 1 + compileLookasideAssertions(input, pos, matchers, err)
		}
	}
}

// Compiles a value selector expression if one is present at offset *pos in
// the input text. On success, updates *pos to point after the parsed
// expression, appends a corresponding matcher to *matchers, and return true.
// Otherwise leaves *pos and *matchers unchanged and returns false. Sets *err
// on syntax errors.
func compileValueSelector(input string, pos *int, matchers *[]matcher, err *error) bool {
	// See if there's a "!" negation prefix.
	negate := false
	pos0 := *pos
	if strings.HasPrefix(input[*pos:], "!") {
		negate = true
		*pos++
	}
	// A value selector expression can be single-quoted, double-quoted, or
	// unquoted. See the EBNF in the NewPathPattern doc.
	if quoted := compileSingleQuoteExpression(input, pos, err); *err != nil {
		*pos = pos0
		return false
	} else if len(quoted) != 0 {
		// A single-quoted string. Treat the quoted contents as a regexp that
		// leaf node values need to match.
		re, rerr := regexp.Compile(quoted)
		if rerr != nil {
			*err = PathPatternErrorf(input, *pos, `invalid regular expression %+q: %w`, quoted, rerr)
			*pos = pos0
			return false
		}
		*matchers = append(*matchers, &endMatcher{re, negate})
		return true
	} else if quoted := compileDoubleQuoteExpression(input, pos, err); *err != nil {
		*pos = pos0
		return false
	} else if len(quoted) != 0 {
		// A double-quoted string. Leaf nodes need to match the content exactly.
		re := regexp.MustCompile("^" + regexp.QuoteMeta(quoted) + "$")
		*matchers = append(*matchers, &endMatcher{re, negate})
		return true
	} else {
		// Unquoted. A bare value selector may follow. May contain wildcards.
		if valText := bareValueRegexp.FindString(input[*pos:]); len(valText) > 0 {
			re := regexp.MustCompile("^" + regexpFromWildcard(valText) + "$")
			*matchers = append(*matchers, &endMatcher{re, negate})
			*pos += len(valText)
			return true
		} else {
			// Nothing there, so leaf nodes can have any value.
			*matchers = append(*matchers, &endMatcher{nil, false})
			return true
		}
	}
}

// Compiles a single-quote expression if one is present at offset *pos in the
// input text. On success, updates *pos to point after the closing quote and
// returns the quoted contents. Otherwise leaves *pos unchanged and returns an
// empty string. Sets *err if the closing quote cannot be found.
func compileSingleQuoteExpression(input string, pos *int, err *error) string {
	contents, nchars, perr := parseSingleQuoteString(input, *pos)
	if perr != nil {
		*err = PathPatternErrorf(input, *pos, "%w", perr)
	}
	*pos += nchars
	return contents
}

// Compiles a double-quote expression if one is present at offset *pos in the
// input text. On success, updates *pos to point after the closing quote and
// returns the quoted contents. Otherwise leaves *pos unchanged and returns an
// empty string. Sets *err if the closing quote cannot be found.
func compileDoubleQuoteExpression(input string, pos *int, err *error) string {
	contents, nchars, perr := parseDoubleQuoteString(input, *pos)
	if perr != nil {
		*err = PathPatternErrorf(input, *pos, "%w", perr)
	}
	*pos += nchars
	return contents
}

// Returns a regular expression that matches the input string if "*" is treated
// as a simple match-anything wildcard but in which no other characters have
// special significance.
func regexpFromWildcard(input string) string {
	return strings.ReplaceAll(regexp.QuoteMeta(input), `\*`, `.*`)
}

// MatchingPaths searches a Node tree for root-anchored node paths that match
// a given path pattern. It returns an empty slice if no matching paths exist.
// Otherwise it returns all paths as slices of Node objects, with the given
// root node as the first element of each slice. Sequence ordering is preserved
// in the returned paths in the sense that if two returned paths p1 and p2
// contain children of the same sequence node with indices i1 and i2, then p1
// occurs before p2 in the returned slice if and only if i1 < i2. Ordering of
// mapping node children is unpredictable.
func MatchingPaths(root Node, pattern PathPattern) [][]Node {
	if root == nil {
		return [][]Node{}
	}
	matchers := pattern.Compiled().matchers
	if len(matchers) == 0 {
		return [][]Node{[]Node{root}}
	} else {
		childPaths := matchingChildPaths(root, matchers)
		fullPaths := prependNodeToPaths(childPaths, root)
		return fullPaths
	}
}

// Returns all paths that start at children of the specified (sub)tree root
// and match the given sequence of matchers. Returns an empty slice if no
// matches are found. Returns a slice containing a single empty path if the
// matcher sequence contains only an end matcher ($[<value-selector>]) and the
// argument is a leaf node. Preserves sequence ordering.
func matchingChildPaths(root Node, matchers []matcher) [][]Node {
	var resultPaths [][]Node
	if len(matchers) > 0 {
		currentMatcher := matchers[0]

		switch m := currentMatcher.(type) {
		case *lookasideMatcher:
			if root.Kind() != ScalarKind && (len(matchingChildPaths(root, m.matchers)) > 0) == !m.negate {
				resultPaths = matchingChildPaths(root, matchers[1:])
			} else {
				resultPaths = [][]Node{}
			}
		case *endMatcher:
			if root.Kind() == ScalarKind && (m.re == nil || m.re.MatchString(root.Value().(string)) == !m.negate) {
				resultPaths = append(resultPaths, []Node{})
			}
		default:
			var singleDescentPaths [][]Node
			var nextMatchers []matcher
			var currentMatcherIsDescent bool
			switch currentMatcher.(type) {
			case *mappingDescentMatcher, *sequenceDescentMatcher, *anyDescentMatcher:
				// Arbitrary descent matcher. Try a single step of descent here,
				// then two or more steps below.
				currentMatcherIsDescent = true
				singleDescentPaths = matchingChildPaths(root, matchers[1:])
				nextMatchers = matchers
			default:
				// Ordinary matcher.
				nextMatchers = matchers[1:]
			}
			resultPaths = append(resultPaths, singleDescentPaths...)

			var childPaths [][]Node
			matchingChildren := currentMatcher.matchChildren(root)
			for _, child := range matchingChildren {
				if len(matchers) == 1 {
					childPaths = append(childPaths, []Node{child})
				}
				if len(matchers) > 1 || currentMatcherIsDescent {
					grandChildPaths := matchingChildPaths(child, nextMatchers)
					newChildPaths := prependNodeToPaths(grandChildPaths, child)
					childPaths = append(childPaths, newChildPaths...)
				}
			}
			// Add any child paths just found that aren't duplicates of any
			// single-step arbitrary descent paths found before.
			for _, p := range childPaths {
				if !containsPath(singleDescentPaths, p) {
					resultPaths = append(resultPaths, p)
				}
			}
		}
	}
	return resultPaths
}

// Return true iff path is found in paths.
func containsPath(paths [][]Node, path []Node) bool {
	for _, p := range paths {
		if len(p) == len(path) {
			equal := true
			for i, n := range path {
				if n != p[i] {
					equal = false
					break
				}
			}
			if equal {
				return true
			}
		}
	}
	return false
}

// Returns the node paths that result from prepending a given node to each of
// a sequence of node paths.
func prependNodeToPaths(paths [][]Node, node Node) [][]Node {
	newPaths := [][]Node{}
	for _, p := range paths {
		newPaths = append(newPaths, append([]Node{node}, p...))
	}
	return newPaths
}

// PathExpression returns a path pattern expression corresponding to the
// specified node path. The returned expression contains no wildcards and
// does not begin with a period unless the node path has length one, in which
// case "." is returned. Periods before bracketed index specifiers are omitted,
// and index values are positive indices. Key selectors are quoted if they
// contain any special characters. No value selector is included.
//
// An error is returned if the argument path is empty or does not describe a
// node path in the tree rooted by its first element.
func PathExpression(path []Node) (string, error) {
	if len(path) == 0 {
		return "", fmt.Errorf("empty path")
	} else if len(path) == 1 {
		return ".", nil
	} else {
		var buffer strings.Builder
		if err := appendPathExpressionSuffix(&buffer, path[0], path[1:]); err != nil {
			return "", err
		}
		return buffer.String(), nil
	}
}

// Helper for PathExpression. Appends to buffer a path expression suffix
// corresponding to path if it matches starting at any child of parent.
// Returns an error if there is no match.
func appendPathExpressionSuffix(buffer *strings.Builder, parent Node, path []Node) error {
	if len(path) == 0 {
		return nil
	}
	var matchingChild Node
	switch parent.Kind() {
	case MappingKind:
		for key, child := range parent.Value().(map[string]Node) {
			if child == path[0] {
				matchingChild = child
				buffer.WriteString(QuoteKeyMeta(key))
				break
			}
		}
	case SequenceKind:
		for index, child := range parent.Value().([]Node) {
			if child == path[0] {
				matchingChild = child
				buffer.WriteString(fmt.Sprintf("[%d]", index))
				break
			}
		}
	}
	if matchingChild == nil {
		return fmt.Errorf("no match for path after %+q", buffer.String())
	}
	if len(path) > 1 {
		if path[0].Kind() == MappingKind {
			buffer.WriteString(".")
		}
		return appendPathExpressionSuffix(buffer, matchingChild, path[1:])
	}
	return nil
}

// PathExpressionOk returns a path expression corresponding to the specified
// node path, which it assumes to be valid. A thin wrapper for PathExpression,
// it panics instead of returning an error code if the argument path cannot be
// translated to a path expression.
func PathExpressionOk(path []Node) string {
	expr, err := PathExpression(path)
	if err != nil {
		panic(err)
	}
	return expr
}

// QuoteKeyMeta returns the result of double-quoting the argument string if it
// contains any special characters that might render it invalid as a bare key
// selector in a path expression. See PathPattern.
func QuoteKeyMeta(text string) string {
	if keyNeedsQuotingInKeyRegexp.FindString(text) == "" {
		return text
	} else {
		return `"` + charNeedsEscapingInDoubleQuotesRegexp.ReplaceAllString(text, `\$1`) + `"`
	}
}

var (
	keyNeedsQuotingInKeyRegexp            = regexp.MustCompile(`[^\w]`)
	charNeedsEscapingInDoubleQuotesRegexp = regexp.MustCompile(`(["\\])`)
)

// QuoteKeyRegexMeta returns the result of "quoting" (escaping) any regular
// expression or path expression metacharacters in the argument string so
// that it would match literally if used within a singly quoted key regular
// expression in a path expression. See PathPattern.
func QuoteKeyRegexMeta(text string) string {
	return strings.ReplaceAll(regexp.QuoteMeta(text), "'", "''")
}

// AppendToPathCopy returns the result of appending nodes to a path. Unlike
// the builtin append function, it never modifies the original path but rather
// copies it and appends the argument nodes to the result.
func AppendToPathCopy(path []Node, nodes ...Node) []Node {
	newPath := make([]Node, len(path), len(path)+len(nodes))
	copy(newPath, path)
	newPath = append(newPath, nodes...)
	return newPath
}
