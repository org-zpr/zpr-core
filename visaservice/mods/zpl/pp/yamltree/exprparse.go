package yamltree

import (
	"sort"
)

// A node in an abstract syntax tree. Every node has a token representing an
// action to take at evaluation time plus zero, one, or two subtree arguments.
// AST nodes for things like literals contain all their information in their
// tokens and so leave left and right nil. AST nodes for unary operators use
// left for their argument expressions and leave right nil. Binary oprators
// use both left and right.
type astNode struct {
	token token
	left  *astNode
	right *astNode
}

// Returns a sorted slice of the names of all symbols referenced in an AST.
// Returns an empty slice if no symbols are referenced.
func astSymbols(ast *astNode) []string {
	return sortUniqStrings(astSymbolsHelper(ast))
}

// Helper for astSymbols. Doesn't sort or remove duplicates.
func astSymbolsHelper(ast *astNode) []string {
	if ast == nil {
		return []string{}
	} else {
		switch t := ast.token.(type) {
		case *symbolToken:
			return []string{t.name}
		case *pathPatternSymbolToken:
			return []string{t.name}
		default:
			syms := []string{}
			syms = append(syms, astSymbolsHelper(ast.left)...)
			syms = append(syms, astSymbolsHelper(ast.right)...)
			return syms
		}
	}
}

// Returns a sorted slice of the names of all function referenced in an AST.
// Returns an empty slice if no functions are referenced.
func astFunctions(ast *astNode) []string {
	return sortUniqStrings(astFunctionsHelper(ast))
}

// Helper for astFunctions. Doesn't sort or remove duplicates.
func astFunctionsHelper(ast *astNode) []string {
	funcs := []string{}
	if ast != nil {
		switch t := ast.token.(type) {
		case *functionToken:
			funcs = []string{t.name}
		}
		funcs = append(funcs, astFunctionsHelper(ast.left)...)
		funcs = append(funcs, astFunctionsHelper(ast.right)...)
	}
	return funcs
}

// Does a "sort --unique" on a slice of strings.
func sortUniqStrings(ss []string) []string {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	uss := make([]string, 0, len(m))
	for s, _ := range m {
		uss = append(uss, s)
	}
	sort.Strings(uss)
	return uss
}

// Parses a complete expression from a token sequence. On success, returns the
// root of the resulting AST and the number of tokens consumed from the input
// sequence. On failure, returns nil, 0, and an error with a concrete type of
// *tokenError.
//
// Here is an EBNF for the grammar:
//
//     expr      = nonlet | "let" ident "=" expr "in" expr
//     nonlet    = ternable "?" ternable ":" expr
//     ternable  = orable ("or" orable)*
//     orable    = andable ("and" andable)*
//     andable   = compable (("==" | "!=" | "<" | "<=" | ">" | ">=") compable)*
//     compable  = contable (("=~" | "!~") contable)*
//     contable  = minusable (("equals | "contains") minusable)*
//     minusable = unionable ("minus" unionable)*
//     unionable = interable ("union" interable)*
//     interable = matchable ("intersect" matchable)*
//     matchable = addable (("+" | "-") addable)*
//     addable   = multable (("*" | "/" | "//" | "%") multable)*
//     multable  = expable ("^" multable)?
//     expable   = primary | ("-" | "+" | "not") expable
//     primary   = literal | symref | pathexpr | vectexpr | ident "(" exprlist ")" | "(" expr ")"
//     literal   = "null" | boolean | number | sqstring | dqstring
//     symref    = "$" ident pathexpr?
//     vectexpr  = "[" (exprlist | expr forlist+) "]"
//     exprlist  = expr ("," expr)*
//     forlist   = "for" ident "in" expr ("if" expr)?
//     boolean   = "true" | "false"
//     number    = << a real number >>
//     sqstring  = << a single-quotes string >>
//     dqstring  = << a double-quotes string >>
//
// A note on some of the nonterminal names: <x>able generally refers to a
// subexpression that can be joined with other <x>able subexpressions by <x>
// operators. An <x>able contains no <x> operators at its top level.
func parseExpr(tokens []token) (*astNode, int, error) {
	a, n, err := parseNonlet(tokens)
	if err != nil {
		return nil, 0, err
	} else if n > 0 {
		return a, n, nil
	}

	var ast *astNode
	i := 0

	if i < len(tokens) && tokenIsKeyword(tokens[i], "let") {
		letTok := tokens[i]
		i++

		if len(tokens[i:]) < 1 {
			return nil, 0, tokenErrorf(letTok, `dangling "let"`)
		}
		if bindTok, ok := tokens[i].(*letBindingToken); !ok {
			return nil, 0, tokenErrorf(tokens[i], `expected a "let" binding (<name> = <expr>)`)
		} else {
			eqTok := tokens[i+1]
			i += 2 // skip ident and "=" (they're both there -- see scanLetBindingId)

			if len(tokens[i:]) < 1 {
				return nil, 0, tokenErrorf(eqTok, `dangling "=" in "let" expression`)
			} else {
				a, n, err := parseExpr(tokens[i:])
				if err != nil {
					return nil, 0, err
				} else if n == 0 {
					return nil, 0, tokenErrorf(eqTok, `unparsable after "=" in "let" expression"`)
				}
				expr1 := a
				i += n

				if len(tokens[i:]) < 1 || !tokenIsKeyword(tokens[i], "in") {
					return nil, 0, tokenErrorf(letTok, `missing "in" in "let" expression`)
				}
				inTok := tokens[i]
				i++

				if len(tokens[i:]) < 1 {
					return nil, 0, tokenErrorf(inTok, `dangling "in" in "let" expression`)
				} else {
					a, n, err := parseExpr(tokens[i:])
					if err != nil {
						return nil, 0, err
					} else if n == 0 {
						return nil, 0, tokenErrorf(inTok, `unparsable after "in" in "let" expression`)
					}
					expr2 := a
					i += n

					ast = &astNode{bindTok, expr1, expr2}
				}
			}
		}
	}

	return ast, i, nil
}

// All of the following nonterminal parsing functions take a token (sub)sequence
// and return the root of an AST subtree and the number of tokens consumed on
// success. On failure they return a zero token count and an error containing a
// *tokenError.

func parseNonlet(tokens []token) (*astNode, int, error) {
	var ast *astNode
	i := 0

	a, n, err := parseTernable(tokens)
	if err != nil {
		return nil, 0, err
	} else if n == 0 {
		return nil, 0, nil
	} else {
		ast = a
		i = n
	}

	if i < len(tokens) && tokenIsOperator(tokens[i], operQuestion) {
		quesToken := tokens[i]
		i++
		cond := ast
		left, n, err := parseTernable(tokens[i:])
		if err != nil {
			return nil, 0, err
		} else if n == 0 {
			return nil, 0, tokenErrorf(quesToken, `unparsable after "?" in ternary operator expression`)
		} else {
			i += n
			if i < len(tokens) && tokenIsOperator(tokens[i], operColon) {
				colToken := tokens[i]
				i++
				right, n, err := parseExpr(tokens[i:])
				if err != nil {
					return nil, 0, err
				} else if n == 0 {
					return nil, 0, tokenErrorf(colToken, `unparsable after ":" in ternary operator expression`)
				} else {
					i += n
					ast = &astNode{quesToken, cond, &astNode{colToken, left, right}}
				}
			} else {
				return nil, 0, tokenErrorf(quesToken, `missing ":" in ternary operator expression`)
			}
		}
	}

	return ast, i, nil
}

func parseTernable(tokens []token) (*astNode, int, error) {
	return parseBinopExpr(tokens, parseOrable, operOr)
}

func parseOrable(tokens []token) (*astNode, int, error) {
	return parseBinopExpr(tokens, parseAndable, operAnd)
}

func parseAndable(tokens []token) (*astNode, int, error) {
	return parseBinopExpr(tokens, parseCompable, operEq, operNe, operLt, operLe, operGt, operGe)
}

func parseCompable(tokens []token) (*astNode, int, error) {
	return parseBinopExpr(tokens, parseContainsable, operEquals, operContains)
}

func parseContainsable(tokens []token) (*astNode, int, error) {
	return parseBinopExpr(tokens, parseMinusable, operSetMinus)
}

func parseMinusable(tokens []token) (*astNode, int, error) {
	return parseBinopExpr(tokens, parseUnionable, operUnion)
}

func parseUnionable(tokens []token) (*astNode, int, error) {
	return parseBinopExpr(tokens, parseIntersectable, operIntersect)
}

func parseIntersectable(tokens []token) (*astNode, int, error) {
	return parseBinopExpr(tokens, parseMatchable, operLike, operUnlike)
}

func parseMatchable(tokens []token) (*astNode, int, error) {
	return parseBinopExpr(tokens, parseAddable, operPlus, operMinus)
}

func parseAddable(tokens []token) (*astNode, int, error) {
	return parseBinopExpr(tokens, parseMultable, operMul, operDiv, operIntDiv, operMod)
}

func parseMultable(tokens []token) (*astNode, int, error) {
	var ast *astNode
	i := 0

	a, n, err := parseExpable(tokens)
	if err != nil {
		return nil, 0, err
	} else if n == 0 {
		return nil, 0, nil
	} else {
		ast = a
		i = n
	}

	if i < len(tokens) && tokenIsOperator(tokens[i], operPow) {
		expOp := tokens[i]
		i++
		a, n, err := parseMultable(tokens[i:])
		if err != nil {
			return nil, 0, err
		} else if n == 0 {
			return nil, 0, tokenErrorf(expOp, `unparsable after "%s"`, expOp.Text())
		} else {
			ast = &astNode{expOp, ast, a}
			i += n
		}
	}

	return ast, i, nil
}

func parseExpable(tokens []token) (*astNode, int, error) {
	a, n, err := parsePrimary(tokens)
	if err != nil {
		return nil, 0, err
	}
	if n != 0 {
		return a, n, nil
	}

	if len(tokens) > 0 && tokenIsOperator(tokens[0], operMinus, operPlus, operNot) {
		op := tokens[0]
		a, n, err := parseExpable(tokens[1:])
		if err != nil {
			return nil, 0, err
		} else if n == 0 {
			return nil, 0, tokenErrorf(op, `unparsable after "%s"`, op.Text())
		} else {
			return &astNode{op, a, nil}, 1 + n, nil
		}
	}

	return nil, 0, nil
}

func parsePrimary(tokens []token) (*astNode, int, error) {
	if len(tokens) == 0 {
		return nil, 0, nil
	}

	switch t := tokens[0].(type) {

	case *nullToken, *boolToken, *numberToken, *singleQuoteToken, *doubleQuoteToken, *symbolToken, *pathPatternToken, *pathPatternSymbolToken:
		return &astNode{t, nil, nil}, 1, nil

	case *functionToken:
		i := 2 // skip the '(' (it's there -- see scanFunction)

		a, n, err := parseExprList(tokens[i:])
		if err != nil {
			return nil, 0, err
		}
		i += n

		if i >= len(tokens) {
			return nil, 0, tokenErrorf(t, `invalid invocation of "%s": no closing ")"`, t.name)
		} else if !tokenIsBracket(tokens[i], ")") {
			return nil, 0, tokenErrorf(tokens[i], `expected ")" (to close invocation of %q)`, t.name)
		}
		i++

		return &astNode{t, a, nil}, i, nil

	case *bracketToken:
		switch {
		case tokenIsBracket(t, "("):
			a, n, err := parseExpr(tokens[1:])
			if err != nil {
				return nil, 0, err
			} else if n == 0 {
				return nil, 0, tokenErrorf(t, "empty parenthesized expression")
			} else {
				i := 1 + n
				if i >= len(tokens) {
					return nil, 0, tokenErrorf(t, `no matching ")"`)
				} else if !tokenIsBracket(tokens[i], ")") {
					return nil, 0, tokenErrorf(tokens[i], `expected ")"`)
				} else {
					return a, i + 1, nil
				}
			}
		case tokenIsBracket(t, "["):
			return parseVector(tokens)
		}
	}

	return nil, 0, nil
}

func parseExprList(tokens []token) (*astNode, int, error) {
	return parseBinopExpr(tokens, parseExpr, operComma)
}

// Parses a vector expression of the form [<exprlist>] or [<expr> <forlist>].
// On success, returns an AST node containing the "[" token and <exprlist> or
// <expr> as the left child and nil or <forlist> as the right child. See
// parseForList for <forlist> AST structure.
func parseVector(tokens []token) (*astNode, int, error) {
	if len(tokens) < 1 || !tokenIsBracket(tokens[0], "[") {
		return nil, 0, nil
	} else {
		leftBracket := tokens[0]
		i := 1
		var exprList, forList *astNode
		// Look for a comma-delimited expression list or a comprehension body.
		// Both start with an expression.
		a, n, err := parseExprList(tokens[i:])
		if err != nil {
			return nil, 0, err
		} else if n != 0 {
			i += n
			exprList = a
			if !tokenIsOperator(exprList.token, operComma) {
				// Expression list has length 1.
				a, n, err := parseForList(tokens[i:])
				if err != nil {
					return nil, 0, err
				} else if n != 0 {
					forList = a
					i += n
				}
			}
		}
		if i >= len(tokens) {
			return nil, 0, tokenErrorf(leftBracket, `no matching "]"`)
		} else if !tokenIsBracket(tokens[i], "]") {
			return nil, 0, tokenErrorf(tokens[i], `expected "]"`)
		} else {
			i++
			return &astNode{leftBracket, exprList, forList}, i, nil
		}
	}
}

// Parses a "for" list for a vector comprehension. Looks for a token sequence
// of the form (for <ident> in <expr> (if <expr>)?)+. On success, returns an
// AST made up of one or more binding nodes with bound expressions as the left
// child and conditional expressions (or nil) as the right child, all joined
// into a maximally left-unbalanced tree by "for" nodes. (That is, a "for" node
// might may have any number of binding nodes as left descendents but only one
// as a right descendent.)
func parseForList(tokens []token) (*astNode, int, error) {
	var ast *astNode
	var i int

	for i = 0; i < len(tokens); {
		if !tokenIsKeyword(tokens[i], "for") {
			return ast, i, nil
		} else {
			forTok := tokens[i]
			i++
			if len(tokens[i:]) < 1 {
				return nil, 0, tokenErrorf(forTok, `dangling "for"`)
			} else if bindTok, ok := tokens[i].(*forBindingToken); !ok {
				return nil, 0, tokenErrorf(tokens[i], `expected an "in" binding (<name> in <expr>)`)
			} else {
				i += 2 // skip ident and "in" (they're both there -- see scanForBindingId)
				a, n, err := parseExpr(tokens[i:])
				if err != nil {
					return nil, 0, err
				} else if n == 0 {
					return nil, 0, tokenErrorf(tokens[i-1], `unparsable after "in"`)
				} else {
					i += n
					var c *astNode
					if i < len(tokens) && tokenIsKeyword(tokens[i], "if") {
						i++
						c, n, err = parseExpr(tokens[i:])
						if err != nil {
							return nil, 0, err
						} else if n != 0 {
							i += n
						}
					}
					b := &astNode{bindTok, a, c}
					if ast == nil {
						ast = b
					} else {
						ast = &astNode{forTok, ast, b}
					}
				}
			}
		}
	}

	return ast, i, nil
}

// Parses a sequence of one or more subexpressions with intervening operators
// from the specified set. Returns AST subtree root and number of tokens
// consumed on success, *tokenError on failure. Assumes all specified operators
// are left associative.
func parseBinopExpr(tokens []token, subParser func([]token) (*astNode, int, error), ops ...operator) (*astNode, int, error) {
	var ast *astNode
	var pendingOp token
	var i int

	for i = 0; i < len(tokens); {
		subAst, n, err := subParser(tokens[i:])
		if err != nil {
			return nil, 0, err
		} else if n == 0 {
			break
		} else {
			if ast == nil {
				ast = subAst
			} else {
				ast = &astNode{pendingOp, ast, subAst}
			}
			i += n
		}

		if i < len(tokens) && tokenIsOperator(tokens[i], ops...) {
			pendingOp = tokens[i]
			i++
		} else {
			pendingOp = nil
			break
		}
	}

	if pendingOp != nil {
		return nil, 0, tokenErrorf(pendingOp, `unparsable after "%s"`, pendingOp.Text())
	} else {
		return ast, i, nil
	}
}

// Returns true iff t is a *operatorToken and, if ops is nonempty, t's op field
// is equal to one of the elements of ops.
func tokenIsOperator(t token, ops ...operator) bool {
	if bt, ok := t.(*operatorToken); ok {
		for _, op := range ops {
			if op == bt.op {
				return true
			}
		}
	}
	return false
}

// Returns true iff t is a *bracketToken and, if brackets is nonempty, t's
// text is equal to one of the elements of chars.
func tokenIsBracket(t token, brackets ...string) bool {
	if bt, ok := t.(*bracketToken); ok {
		for _, b := range brackets {
			if bt.text == b {
				return true
			}
		}
	}
	return false
}

// Returns true iff t is a *keywordToken and, if keywords is nonempty, t's
// text is equal to one of the elements of chars.
func tokenIsKeyword(t token, keywords ...string) bool {
	if kt, ok := t.(*keywordToken); ok {
		for _, b := range keywords {
			if kt.text == b {
				return true
			}
		}
	}
	return false
}
