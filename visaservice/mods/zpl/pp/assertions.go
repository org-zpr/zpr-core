package pp

import (
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"zpr.org/vsx/zpl/doc"
	yt "zpr.org/vsx/zpl/pp/yamltree"
)

// AttributeExpression represents an attribute expression of the form that
// can appear in condition predicates in standard-language assertions.
type AttributeExpression struct {
	// Name is the name of an attribute with any data source prefix removed.
	Name string

	// Operator is "eq", "ne", "has", or "excludes".
	Operator string

	// Value is the value the named attribute is to be compared to.
	Value string
}

func (ae *AttributeExpression) String() string {
	return fmt.Sprintf("(%v, %v, %v)", ae.Name, ae.Operator, ae.Value)
}

// An EvaluationContext implementation that delegates to another and also
// carries a map of data source names to DataSourceProxy. Used to tunnel
// data source proxies to the implementation of permitted_access_counts.
type dataSourceEvaluationContext struct {
	wrapped     yt.EvaluationContext
	dataSources map[string]DataSourceProxy
}

func (ctx *dataSourceEvaluationContext) YamlRoot() yt.Node {
	return ctx.wrapped.YamlRoot()
}

func (ctx *dataSourceEvaluationContext) YamlRef() yt.Node {
	return ctx.wrapped.YamlRef()
}

func (ctx *dataSourceEvaluationContext) Symbols() map[string]interface{} {
	return ctx.wrapped.Symbols()
}

func (ctx *dataSourceEvaluationContext) Functions() map[string]interface{} {
	return ctx.wrapped.Functions()
}

func (ctx *dataSourceEvaluationContext) NodeLogger() yt.NodeAccessLogger {
	return ctx.wrapped.NodeLogger()
}

func (ctx *dataSourceEvaluationContext) EvalTracer() io.Writer {
	return ctx.wrapped.EvalTracer()
}

func (ctx *dataSourceEvaluationContext) AddSymbols(newSymbols map[string]interface{}) (yt.EvaluationContext, error) {
	ctxCopy := *ctx
	if newWrapped, err := ctx.wrapped.AddSymbols(newSymbols); err != nil {
		return nil, err
	} else {
		ctxCopy.wrapped = newWrapped
		return &ctxCopy, nil
	}
}

func (ctx *dataSourceEvaluationContext) AddFunctions(newFunctions map[string]interface{}) (yt.EvaluationContext, error) {
	ctxCopy := *ctx
	if newWrapped, err := ctx.wrapped.AddFunctions(newFunctions); err != nil {
		return nil, err
	} else {
		ctxCopy.wrapped = newWrapped
		return &ctxCopy, nil
	}
}

func (ctx *dataSourceEvaluationContext) Copy() yt.EvaluationContext {
	ctxCopy := *ctx
	ctxCopy.wrapped = ctx.wrapped.Copy()
	return &ctxCopy
}

func (ctx *dataSourceEvaluationContext) ServiceByName(n string) []string {
	return ctx.wrapped.ServiceByName(n)
}

// A parsed assertion
type assertion struct {
	desc       string // description from the assertion block
	lang       string // language (standardLang or internalLang)
	domain     string // target domain (localDomain or globalDomain)
	assert     string // assertion expression
	assertPath []yt.Node
}

const (
	// Defined assertion languages
	standardLang = "standard"
	internalLang = "internal"

	// Defined assertion domains
	localDomain  = "local"
	globalDomain = "global"
)

// Compiled the internal-language expression(s).
type expression struct {
	text     string
	compiled yt.Expression
}

type ErrorLoggerF func(err error, extraText string)

// ProcessAssertions validates assertions in the argument YAML tree. It searches
// for all "assertions" blocks, evaluates all the assertion expressions in each
// one, and returns a copy of the argument tree with all the "assertions" blocks
// removed. It returns a nil error value if all the assertions pass. Otherwise
// it returns an error describing the first failing assertion unless the
// AbideAsserts option is true, in which case it returns a nil error even if
// some assertions fail. It reports any failing assertions and writes an
// assertion summary line to log if the latter in not nil. The summary line is
// omitted if all assertions pass and the Silent option is true.
//
// If the TraceAsserts option is a nonempty string, then it is interpreted as a
// path expression relative to the root of the YAML tree, and any "assertions"
// block elements (i.e., mappings with "assert" and "desc" keys) that match it
// or whose "assert" or "desc" children match it have their evaluations traced
// to log if it is not nil.
//
// Assertions whose evaluations require access to external data sources use the
// data source proxies in dataSources, which indexes them by their names. If
// the DynamicAsserts option is false, these assertions are ignored.
//
// Very serious errors cause a non-nil error value (and a nil root node) to be
// returned regardless of options.
func ProcessAssertions(root yt.Node, dataSources map[string]DataSourceProxy, log io.Writer, opts *PreprocessOpts) (yt.Node, error) {
	// Get a map of service definitions from the YAML.
	svcIndex, err := parseServiceDefinitions(root) // e.g., "webservice" -> ["tcp80", "tcp443"]
	if err != nil {
		return nil, err
	}

	// Build a set of assertion nodes ("assertions" block elements) that are
	// to have their expressions traced.
	assertionsToTrace := make(map[yt.Node]bool)
	if opts.TraceAsserts != "" {
		if pattern, err := yt.NewPathPattern(opts.TraceAsserts); err != nil {
			return nil, fmt.Errorf("invalid assertion tracing path expression: %w", err)
		} else {
			for _, path := range yt.MatchingPaths(root, pattern) {
				hasDescOrAssertChild, _ := regexp.MatchString(`\.(desc|assert)$`, yt.PathExpressionOk(path))
				if hasDescOrAssertChild {
					assertionsToTrace[path[len(path)-2]] = true
				} else {
					assertionsToTrace[path[len(path)-1]] = true
				}
			}
		}
	}

	// If dynamic assertions are going to be evaluated, construct a map of
	// locally caching data source proxies that wrap the data source proxies
	// supplied by the caller. This map will go into a custom EvaluationContext
	// implementation, which permitted_access_counts (the only internal-language
	// function that knows anything about data source proxies) will type-assert
	// its argument context to in order to pull out the proxies.
	var dataSourcesForContext map[string]DataSourceProxy
	if opts.DynamicAsserts {
		dataSourcesForContext = make(map[string]DataSourceProxy, len(dataSources))
		for name, proxy := range dataSources {
			dataSourcesForContext[name] = newCachingDataSourceProxy(proxy)
		}
	}

	// Arrange to report errors (unless opted out) but return just the first one.
	var errorToReturn error
	recordError := func(err error, extraText string) {
		if errorToReturn == nil {
			errorToReturn = err
		}
		if log != nil {
			fmt.Fprintf(log, "%s\n", err.Error())
			if extraText != "" {
				fmt.Fprintf(log, "%s\n", extraText)
			}
		}
	}

	foundAssertions, checkedAssertions, numAssertionsPassed, numAssertionsTraced := 0, 0, 0, 0

	for _, path := range yt.MatchingPaths(root, yt.NewPathPatternOk(`@@.assertions`)) {
		// Found a path to an "assertions" block. Pick out the "assertions" node and its parent.
		assertions := path[len(path)-1]
		assertionsParent := path[len(path)-2]

		// The "assertions" block must be a sequence. Process its assertion elements one by one.
		if assertions.Kind() != yt.SequenceKind {
			recordError(yt.PathErrorf(path, `"assertions" keys are reserved for assertions blocks (which must be sequences)`), "")
			continue
		}

	assertionLoop:
		for _, assertion := range assertions.Value().([]yt.Node) {
			a, err := parseAssertionBlock(yt.AppendToPathCopy(path, assertion))
			if err != nil {
				recordError(err, "")
				continue assertionLoop
			}
			foundAssertions++

			// Create one or more expressions from the "assert" value. If the
			// internal language was specified, use the "assert" value directly
			// as the (lone) expression string. If the standard language was
			// specified, translate the "assert" value into one or more
			// internal-language expression strings.
			var exprTexts []string
			switch a.lang {
			case internalLang:
				exprTexts = []string{a.assert}
			case standardLang:
				// targetComps := "@@.s.*"
				targetComps := "@@.components.*"
				if a.domain == localDomain {
					// Restrict target components to the children of the first
					// "components" block under the "assertions" block's parent.
					// If there are no "components" blocks, this is irrelevant.
					compsPaths := yt.MatchingPaths(assertionsParent, yt.NewPathPatternOk(targetComps))
					if len(compsPaths) > 0 {
						sort.Slice(compsPaths, func(i, j int) bool { return len(compsPaths[i]) < len(compsPaths[j]) })
						shortestPath := compsPaths[0]
						targetComps = yt.PathExpressionOk(shortestPath[:len(shortestPath)-1]) + ".*"
					}
				}
				translatedExprs, err := translateToInternalLanguage(a.assert, targetComps, svcIndex)
				if err != nil {
					recordError(yt.PathErrorf(a.assertPath, "invalid assertion expression: %w", err), "")
					continue assertionLoop
				}
				exprTexts = translatedExprs
			}

			expressions := make([]expression, len(exprTexts))
			for i, text := range exprTexts {
				compiled, err := yt.NewExpression(text)
				if err != nil {
					recordError(yt.PathErrorf(a.assertPath, `invalid assertion expression: %w`, err), "")
					continue assertionLoop
				}
				expressions[i] = expression{text, compiled}
			}

			if !opts.DynamicAsserts {
				// Not doing dynamic assertions, so skip this one if it would
				// access external data sources. The only internal-language
				// function that does that is permitted_access_counts. (If
				// this assertion translated to more than one expression and
				// any of them invokes that function, then all of them will,
				// so we only need to check the first one.)
				for _, f := range expressions[0].compiled.Functions() {
					if f == "permitted_access_counts" {
						continue assertionLoop
					}
				}
			}

			// We're going to check this assertion.
			checkedAssertions++

			// Create a YAML node logger that will record all node accesses
			// during expression evaluation. Log the assertion node itself
			// and any internal-language translations.
			nodeLogger := &yt.AppendingNodeAccessLogger{}
			if a.lang == internalLang {
				nodeLogger.Log(a.assertPath)
			} else {
				nodeLogger.Log(a.assertPath, exprTexts...)
			}

			evalTracer, doTrace := initEvalTracer(assertion, a, assertionsToTrace, numAssertionsTraced > 0, log)
			if doTrace {
				numAssertionsTraced++
			}

			// Construct an evaluation context for this assertion. If we're
			// doing dynamic assertions, use a custom implementation that
			// includes a data source proxy map.
			context, err := yt.NewBasicContext(root, &yt.BasicContextOptions{
				YamlRef:    assertionsParent,
				Functions:  exprFunctions(),
				NodeLogger: nodeLogger,
				EvalTracer: evalTracer,
				Services:   svcIndex,
			})
			if err != nil {
				return nil, fmt.Errorf("could not create assertion evaluation context: %w", err)
			}
			if opts.DynamicAsserts {
				context = &dataSourceEvaluationContext{context, dataSourcesForContext}
			}

			// Evaluate this assertions internal-language expressions. All must
			// return true for the assertion to pass.
			if !evalAll(context, expressions, a, nodeLogger, recordError) {
				// Declare a failed assertion if any of the expressions were false.
				recordError(yt.PathErrorf(a.assertPath, `assertion failed: %q`, a.desc), pathAccessReport(nodeLogger))
				continue assertionLoop // why keep going?
			}

			// Get here only if the assertion passed.
			numAssertionsPassed++
		}
	}

	if (!opts.Silent || errorToReturn != nil) && log != nil {
		fmt.Fprintf(log, "assertions: %d found, %d checked, %d passed\n", foundAssertions, checkedAssertions, numAssertionsPassed)
	}

	if root, err := removeAssertions(root); err != nil {
		return nil, err
	} else if opts.AbideAsserts {
		return root, nil
	} else {
		return root, errorToReturn
	}
}

// evalAll Evaluates the assertions internal-language expressions. All must return true for the assertion to pass.
func evalAll(context yt.EvaluationContext, expressions []expression, a *assertion, nodeLogger yt.NodeAccessLogger, recordError ErrorLoggerF) bool {
	trueExprs := 0
	for _, e := range expressions {
		// If there are multiple internal-language translations, log
		// the assertion node again with just this translation.
		if a.lang != internalLang && len(expressions) > 1 {
			nodeLogger.Log(a.assertPath, e.text)
		}
		// Evaluate the expression.
		exprVal, err := e.compiled.Evaluate(context)
		if err != nil {
			recordError(yt.PathErrorf(a.assertPath, `failed to evaluate assertion expression: %q (%q): %w`, a.assert, a.desc, err), pathAccessReport(nodeLogger))
			continue
		}
		// The expression should return a single boolean value. Allow
		// this value to live in a one-element slice.
		var thisExprTrue bool
		oneBool := "assertion expressions must return a single boolean value"
		switch v := exprVal.(type) {
		case bool:
			thisExprTrue = v
		case []interface{}:
			if len(v) != 1 {
				recordError(yt.PathErrorf(a.assertPath, `%s; got vector of length %d`, oneBool, len(v)), pathAccessReport(nodeLogger))
				continue // Nope!
			} else if b, ok := v[0].(bool); !ok {
				recordError(yt.PathErrorf(a.assertPath, `%s; got [%v] (%T)`, oneBool, v[0], v[0]), pathAccessReport(nodeLogger))
				continue // Nope!
			} else {
				thisExprTrue = b
			}
		default:
			recordError(yt.PathErrorf(a.assertPath, `%s; got %v (%T)`, oneBool, v, v), pathAccessReport(nodeLogger))
			continue // Nope
		}

		if thisExprTrue {
			trueExprs++
		}
	}
	return trueExprs == len(expressions)
}

// initEvalTracer creates an expression evaluation tracer. Just use a null tracer
// if tracing hasn't been requested for the current assertion.
// Otherwise trace to log.
func initEvalTracer(assertionNode yt.Node, a *assertion, assertionsToTrace map[yt.Node]bool, addCR bool, log io.Writer) (io.Writer, bool) {
	evalTracer := io.Writer(nil)
	traceEnable := false
	if log != nil {
		if assertionsToTrace[assertionNode] {
			evalTracer = log
			if addCR {
				fmt.Fprintf(log, "\n")
			}
			traceEnable = true
			fmt.Fprintf(log, "Evaluation trace for %s\n", yt.PathExpressionOk(a.assertPath))
			for _, src := range yt.PathSources(a.assertPath) {
				fmt.Fprintf(log, "from: %s:%d:%d\n", src.File, src.Line, src.Column)
			}
			fmt.Fprintf(log, "description: %s\n", a.desc)
			if a.lang != internalLang {
				fmt.Fprintf(log, "original text: %s\n", a.assert)
			}
		}
	}
	return evalTracer, traceEnable
}

// Parses ZPR service definitions from the ZPL YAML tree rooted by the argument.
// Returns a map of service IDs to slices of string-valued descriptors of the
// form "<proto><param>" (e.g., ["tcp80", "tcp443"]). Returns an empty map if no
// definitions are found. Returns a non-nil error on parse errors.
func parseServiceDefinitions(root yt.Node) (map[string][]string, error) {
	svcIndex := make(map[string][]string)

	rootPath := []yt.Node{root}
	pps := &PPState{
		fussy: ErrModeSilent,
		doc:   &doc.Doc{ZplRef: newZplRef(rootPath), Main: &doc.Main{}},
	}
	{ // copied from prepropcessor...
		childMap := childPathMap(rootPath)
		if svcsPath, exists := childMap["services"]; !exists {
			return nil, yt.PathErrorf(rootPath, `required "services" key missing`)
		} else if err := pps.parseServices(svcsPath); err != nil {
			return nil, err
		}
	}
	for sname, scoping := range pps.doc.Services {
		desc, err := accessDescriptorsForServices([]*doc.Scoping{scoping})
		if err != nil {
			return nil, err
		}
		svcIndex[sname] = desc
	}
	return svcIndex, nil
}

// Removes all "assertions" blocks from the YAML tree rooted at the argument
// node, returns the root of the modified tree.
func removeAssertions(root yt.Node) (yt.Node, error) {
	// Removing a node replaces all ancestor nodes up to the root, so just
	// keep searching for and removing "assertions" subtrees until none remain.
	var err error
	for {
		assertsPaths := yt.MatchingPaths(root, yt.NewPathPatternOk("@@.assertions"))
		if len(assertsPaths) == 0 {
			break
		}
		asserts := lastNode(assertsPaths[0])
		if root, err = yt.RemoveNode(root, asserts); err != nil {
			return nil, err
		}
	}
	return root, nil
}

// Parses an assertion block. Argument must be path from document root to block.
func parseAssertionBlock(path []yt.Node) (*assertion, error) {
	assertionNode := lastNode(path)

	if assertionNode.Kind() != yt.MappingKind {
		return nil, yt.PathErrorf(path, `assertion block must be mapping (found %s)`, assertionNode.Kind())
	}

	a := assertion{lang: standardLang, domain: globalDomain}
	m := assertionNode.Value().(map[string]yt.Node)

	for key, childNode := range m {
		childPath := yt.AppendToPathCopy(path, childNode)
		switch key {
		case "desc":
			if childNode.Kind() != yt.ScalarKind {
				return nil, yt.PathErrorf(childPath, `assertion %q key must have a string value (found %s)`, key, childNode.Kind())
			} else {
				a.desc = childNode.Value().(string)
			}
		case "lang":
			if childNode.Kind() != yt.ScalarKind {
				return nil, yt.PathErrorf(childPath, `assertion %q key must have a string value (found %s)`, key, childNode.Kind())
			} else {
				lang := childNode.Value().(string)
				if lang != standardLang && lang != internalLang {
					return nil, yt.PathErrorf(childPath, `undefined assertion language: %q`, lang)
				}
				a.lang = lang
			}
		case "domain":
			if childNode.Kind() != yt.ScalarKind {
				return nil, yt.PathErrorf(childPath, `assertion %q key must have a string value (found %s)`, key, childNode.Kind())
			} else {
				domain := childNode.Value().(string)
				if domain != localDomain && domain != globalDomain {
					return nil, yt.PathErrorf(childPath, `undefined assertion domain: %q`, domain)
				}
				a.domain = domain
			}
		case "assert":
			if childNode.Kind() != yt.ScalarKind {
				return nil, yt.PathErrorf(childPath, `assertion %q key must have a string value (found %s)`, key, childNode.Kind())
			} else {
				a.assert = childNode.Value().(string)
				a.assertPath = childPath
			}
		default:
			return nil, yt.PathErrorf(childPath, `unsupported key %q in assertion block`, key)
		}
	}

	for _, key := range []string{"desc", "assert"} {
		if _, defined := m[key]; !defined {
			return nil, yt.PathErrorf(path, `assertion block lacks required %q key`, key)
		}
	}

	key := "domain"
	if a.lang == internalLang && m[key] != yt.Node(nil) {
		domainPath := yt.AppendToPathCopy(path, m[key])
		return nil, yt.PathErrorf(domainPath, `assertion %q key not allowed when "lang" is %q`, key, internalLang)
	}

	return &a, nil
}

// Returns a (multi-line) report describing all paths in the argument list.
func pathAccessReport(nodeLogger yt.NodeAccessLogger) string {
	var buf strings.Builder
	indent1 := "  "
	indent2 := indent1 + "    "
	maxValueWidth := 150
	moreFormat := "...(+ %d more characters)"        // contains one "%d"
	maxValueChars := maxValueWidth - len(moreFormat) // close enough
	reported := make(map[string]bool)
	for i, rec := range nodeLogger.Entries() {
		pathExpr := yt.PathExpressionOk(rec.Path)
		reportedKey := pathExpr + "\x00" + strings.Join(rec.Info, "\x00")
		if !reported[reportedKey] {
			node := lastNode(rec.Path)
			var nodeValue string
			switch node.Kind() {
			case yt.ScalarKind:
				nodeValue = node.Value().(string)
				if nodeValue == "" {
					nodeValue = "<empty string>"
				} else {
					runes := []rune(nodeValue)
					if len(runes) > maxValueWidth {
						nodeValue = fmt.Sprintf("%s"+moreFormat, string(runes[:maxValueChars]), len(runes)-maxValueChars)
					}
				}
			case yt.SequenceKind:
				nodeValue = fmt.Sprintf("<sequence of length %d>", len(node.Value().([]yt.Node)))
			case yt.MappingKind:
				nodeValue = fmt.Sprintf("<mapping of size %d>", len(node.Value().(map[string]yt.Node)))
			}
			fmt.Fprintf(&buf, "%s%03d %s = %s\n", indent1, i, pathExpr, nodeValue)
			for _, src := range yt.PathSources(rec.Path) {
				file := src.File
				if file == "" {
					file = "?"
				}
				fmt.Fprintf(&buf, "%sfrom: %s:%d:%d\n", indent2, file, src.Line, src.Column)
			}
			for _, info := range rec.Info {
				if info != "" {
					fmt.Fprintf(&buf, "%sinfo: %s\n", indent2, regexp.MustCompile(`\s*\n\s*`).ReplaceAllString(info, " "))
				}
			}
		}
		reported[reportedKey] = true
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

// Returns a map of expression function implementations to be added to the
// expression evaluator's set of built-in functions.
func exprFunctions() map[string]interface{} {
	return map[string]interface{}{
		"bitrate":                 yt.ScalarFunction(bitrateImpl),
		"duration":                yt.ScalarFunction(durationImpl),
		"host":                    yt.ScalarFunction(hostImpl),
		"port":                    yt.ScalarFunction(portImpl),
		"port_set":                yt.GeneralFunction(portSetImpl),
		"potential_access":        yt.GeneralFunction(potentialAccessImpl),
		"nonforbidden_access":     yt.GeneralFunction(nonforbiddenAccessImpl),
		"permitted_access":        yt.GeneralFunction(permittedAccessImpl),
		"permitted_access_counts": yt.GeneralFunction(permittedAccessCountsImpl),
	}
}

// A parsed standard-language expression. Defaulted fields set to nil.
type standardExpression struct {
	any               bool              // true if "any" specified
	services          []serviceSpec     // target services
	allowed           bool              // true if "allowed", false if "not allowed"
	constraintFactors []simplePredicate // factors of constraint predicate
	attributeFactors  []simplePredicate // factors of attribute predicate
	countFactors      []simplePredicate // factors of count predicate
}

// A service specification representing (part of) a service expression.
type serviceSpec struct {
	id         string // if nonempty, a service ID
	protocol   string // "tcp", "udp", or "icmp"; "" if id != ""
	parameters string // e.g., "22,100-199"; "" if id != ""
}

// A simple predicate of the form <ident> <op> <value>.
type simplePredicate struct {
	ident string // a constraint or attribute identifier
	op    string // an appropriate operator
	val   string // an appropriate value
}

// Translates a standard-language assertion expression into one or more
// internal-language expressions. Expects targetComps to be a path expression
// that matches all components the assertion is to be applied to. Searches
// svcIndex for any services specified by ID; keys are service IDs, and
// mapped values are slices of potential_access-style descriptors. Returns
// a non-nil error on syntax errors or service ID lookup errors.
func translateToInternalLanguage(exprText string, targetComps string, svcIndex map[string][]string) ([]string, error) {
	expr, err := parseStandardLanguageExpression(exprText)
	if err != nil {
		return []string{}, fmt.Errorf(`syntax error in %q: %w`, exprText, err)
	}

	// A function that returns an internal-language vector literal containing
	// a given sequence of string elements.
	stringVecExpr := func(elems []string) string {
		var buf strings.Builder
		fmt.Fprintf(&buf, "[")
		for i, e := range elems {
			if i > 0 {
				fmt.Fprintf(&buf, ", ")
			}
			fmt.Fprintf(&buf, `"%s"`, e)
		}
		fmt.Fprintf(&buf, "]")
		return buf.String()
	}

	// A function that returns an internal-language quoted string containing a
	// predicate expression reassembled from its parsed form.
	predExpr := func(predFactors []simplePredicate) string {
		var buf strings.Builder
		for i, f := range predFactors {
			if i > 0 {
				fmt.Fprintf(&buf, " and ")
			}
			fmt.Fprintf(&buf, "%s %s %s", f.ident, f.op, f.val)
		}
		return buf.String()
	}

	// Create lists of descriptors for fully and partially specified access
	// forms implied by the target services, looking up any service IDs in
	// svcIndex as needed. Fully specified descriptors will all be of the
	// form "<proto><param>" (e.g., "tcp22"), while partially specified
	// descriptors will all be of the form "<proto>" (e.g., "tcp").
	var fullSvcDescs []string
	var partSvcDescs []string
	for _, svc := range expr.services {
		if svc.id != "" {
			if descs, defined := svcIndex[svc.id]; !defined {
				return nil, fmt.Errorf("undefined service ID: %q", svc.id)
			} else {
				fullSvcDescs = append(fullSvcDescs, descs...)
			}
		} else if svc.protocol == "" {
			return nil, fmt.Errorf("no service ID and empty protocol! svc = %v", svc) // parser should've prevented this
		} else if svc.parameters == "" {
			partSvcDescs = append(partSvcDescs, svc.protocol)
		} else {
			if params, err := expandPortType(svc.parameters); err != nil {
				return []string{}, err // parser should've prevented this
			} else {
				for _, p := range params {
					desc := fmt.Sprintf("%s%d", svc.protocol, p)
					fullSvcDescs = append(fullSvcDescs, desc)
				}
			}
		}
	}

	// Generate the expression translation(s).
	var translations []string
	switch expr.allowed {
	case true:
		// "[any] [SERVICE-EXPRESSION] allowed [with CONSTRAINT-PREDICATE] [for COUNT-PREDICATE] [if ATTRIBUTE-PREDICATE]"
		if len(expr.countFactors) == 0 {
			// "[any] [SERVICE-EXPRESSION] allowed [with CONSTRAINT-PREDICATE] [if ATTRIBUTE-PREDICATE]"
			if len(fullSvcDescs) == 0 && len(partSvcDescs) == 0 {
				t := fmt.Sprintf(`all([permitted_access($comp, "%s", "%s") equals potential_access($comp) for comp in %s])`,
					predExpr(expr.attributeFactors), predExpr(expr.constraintFactors), targetComps)
				translations = append(translations, t)
			}
			if len(fullSvcDescs) > 0 {
				var buf strings.Builder
				fmt.Fprintf(&buf, `all([`)
				if expr.any {
					fmt.Fprintf(&buf, `potential_access($comp) contains %s ? `, stringVecExpr(fullSvcDescs))
				}
				fmt.Fprintf(&buf, `permitted_access($comp, "%s", "%s") contains %s`,
					predExpr(expr.attributeFactors), predExpr(expr.constraintFactors), stringVecExpr(fullSvcDescs))
				if expr.any {
					fmt.Fprintf(&buf, ` : true`)
				}
				fmt.Fprintf(&buf, ` for comp in %s])`, targetComps)
				translations = append(translations, buf.String())
			}
			if len(partSvcDescs) > 0 {
				t := fmt.Sprintf(`all([permitted_access($comp, "%s", "%s") contains [$a for a in potential_access($comp) if $a =~ '^(%s)\d+$'] for comp in %s])`,
					predExpr(expr.attributeFactors), predExpr(expr.constraintFactors), strings.Join(partSvcDescs, "|"), targetComps)
				translations = append(translations, t)
			}
		} else {
			// "[any] [SERVICE-EXPRESSION] allowed [with CONSTRAINT-PREDICATE] for COUNT-PREDICATE [if ATTRIBUTE-PREDICATE]"
			zeroCountAllowed := true
			for _, fact := range expr.countFactors {
				if !(strings.HasPrefix(fact.op, "<") || (fact.op == "==" || fact.op == ">=") && assertAllZerosRe.MatchString(fact.val)) {
					zeroCountAllowed = false
				}
			}
			needLenCheck := !(expr.any || zeroCountAllowed || len(fullSvcDescs) == 0)
			needLetExpr := needLenCheck || len(expr.countFactors) > 1
			var buf strings.Builder
			fmt.Fprintf(&buf, `all([`)
			if needLetExpr {
				fmt.Fprintf(&buf, `let counts = `)
			} else {
				fmt.Fprintf(&buf, `all(`)
			}
			fmt.Fprintf(&buf, `[$ac =~ '=(\d+)$' ? num($1) : null for ac in permitted_access_counts($comp, "%s", "%s")`,
				predExpr(expr.attributeFactors), predExpr(expr.constraintFactors))
			var svcPatterns []string
			if len(fullSvcDescs) > 0 {
				svcPatterns = append(svcPatterns, strings.Join(fullSvcDescs, "|"))
			}
			if len(partSvcDescs) > 0 {
				svcPatterns = append(svcPatterns, fmt.Sprintf(`(%s)\d+`, strings.Join(partSvcDescs, "|")))
			}
			if len(svcPatterns) > 0 {
				fmt.Fprintf(&buf, ` if $ac =~ '^(%s)='`, strings.Join(svcPatterns, "|"))
			}
			fmt.Fprintf(&buf, `]`)
			if needLetExpr {
				fmt.Fprintf(&buf, ` in`)
				if needLenCheck {
					fmt.Fprintf(&buf, ` len($counts) == %d and`, len(fullSvcDescs))
				}
				fmt.Fprintf(&buf, ` all(`)
				for i, fact := range expr.countFactors {
					if i > 0 {
						fmt.Fprintf(&buf, ` and `)
					}
					fmt.Fprintf(&buf, `$counts %s %s`, fact.op, fact.val)
				}
				fmt.Fprintf(&buf, `)`)
			} else {
				fmt.Fprintf(&buf, ` %s %s)`, expr.countFactors[0].op, expr.countFactors[0].val)
			}
			fmt.Fprintf(&buf, ` for comp in %s])`, targetComps)
			translations = append(translations, buf.String())
		}
	case false:
		// "[SERVICE-EXPRESSION] not allowed [with CONSTRAINT-PREDICATE] [if ATTRIBUTE-PREDICATE]"
		if len(fullSvcDescs) == 0 && len(partSvcDescs) == 0 {
			t := fmt.Sprintf(`all([nonforbidden_access($comp, "%s", "%s") equals [] for comp in %s])`,
				predExpr(expr.attributeFactors), predExpr(expr.constraintFactors), targetComps)
			translations = append(translations, t)
		}
		if len(fullSvcDescs) > 0 {
			t := fmt.Sprintf(`all([nonforbidden_access($comp, "%s", "%s") intersect %s equals [] for comp in %s])`,
				predExpr(expr.attributeFactors), predExpr(expr.constraintFactors), stringVecExpr(fullSvcDescs), targetComps)
			translations = append(translations, t)
		}
		if len(partSvcDescs) > 0 {
			t := fmt.Sprintf(`all([not any([$a =~ '^(%s)\d+$' for a in nonforbidden_access($comp, "%s", "%s")]) for comp in %s])`,
				strings.Join(partSvcDescs, "|"), predExpr(expr.attributeFactors), predExpr(expr.constraintFactors), targetComps)
			translations = append(translations, t)
		}
	}

	return translations, nil
}

var (
	// Regexes for parsing assertion expressions in the "standard" language.
	assertExprRe = regexp.MustCompile(`^\s*` +
		`(?P<ANY>any\s+)?(?P<SVCEXPR>(\([^)]+?\)|(tcp|udp|icmp)(\s*[\s\d,-]+)?)\s*(and\s*(\([^)]+?\)|(tcp|udp|icmp)(\s*[\s\d,-]+)?))*)?` +
		`(?P<ALLOWED>\b(not\s+)?allowed)\s*` +
		`(\bwith\s+(?P<CONSPRED>(\S+\s*){3}(and\s+(\S+\s*){3})*)\s*)?` +
		`(\bfor\s+(?P<COUNTPRED>(\S+\s*){3}(and\s+(\S+\s*){3})*)\s*)?` +
		`(\bif\s+(?P<ATTRPRED>(\S+\s*){3}(and\s+(\S+\s*){3})*))?` +
		`\s*$`)
	assertServiceSpecRe = regexp.MustCompile(`^\((?P<SVCID>[^)]+?)\)|(?P<PROTO>tcp|udp|icmp)(\s*(?P<PARAMS>[\s\d,-]+))?$`)
	assertSimplePredRe  = regexp.MustCompile(`^(?P<IDENT>\w+\s*\(\w+\s*\)|[\w.]+)\s*(?P<OP>([^\w\s]+|\w+\b))\s*(?P<VAL>\S+)\s*$`)
	assertAndRe         = regexp.MustCompile(`\s*\band\b\s*`)
	assertIcmpParamsRe  = regexp.MustCompile(`^\d+(,\d+)?$`)
	assertConsIdentRe   = regexp.MustCompile(`^max\s*\((?P<QUANT>\S+)\s*\)$`)
	assertConsValRe     = regexp.MustCompile(`^\d+$`)
	assertRelOpRe       = regexp.MustCompile(`^(==?|!=|<|<=|>|>=)$`)
	assertAttrOpRe      = regexp.MustCompile(`^(==?|!=|eq|ne|has|excludes)$`)
	assertAttrValRe     = regexp.MustCompile(`^\S+$`)
	assertCountIdentRe  = regexp.MustCompile(`^count\s*\(\s*(?P<ITEM>\S+)\s*\)$`)
	assertAllDigitsRe   = regexp.MustCompile(`^\d+$`)
	assertAllZerosRe    = regexp.MustCompile(`^0$`)
	assertWhitespaceRe  = regexp.MustCompile(`\s+`)
)

// Returns the text of a named submatch (capturing group) after a successful
// regular expression match. Arguments: input = original input to RE match,
// re = the RE that input matched, submatches = the match result (e.g., the
// return value of regexp's FindStringSubmatchIndex), submatchName = the
// submatch name (e.g., "foo" for the RE `...(?P<foo>...)...`).
func extractSubmatchText(input string, re *regexp.Regexp, submatches []int, submatchName string) string {
	return string(re.ExpandString([]byte{}, "$"+submatchName, input, submatches))
}

// Parses an expression in the standard assertion language, returns a parsed
// expression struct on success, nil and an error on failure.
//
// Grammar:
//
//	expr := posexpr | negexpr
//	posexpr := svcexpr? "allowed" ("with" conspred)? ("for" <countpred>)? ("if" condpred)?
//	negexpr := svcexpr ? "not' "allowed" ("with" conspred)? ("if" condpred)?
//	svcexpr := "any"? svcspec ("and" svcspec)*
//	svcspec := "(" svcid ")" | "tcp" ports? | "udp" ports? | "icmp" types?)
//	conspred := (bwpred | durpred) ("and" (bwpred | durpred))*
//	condpred := attrkey attrop attrval ("and" attrkey attrop attrval)*
//	countpred := "count" "(" countitem ")" relop countval ("and" "count" "(" countitem ")" relop countval)*
//	countitem := "users"
//	bwpred := "max(bandwidth)" relop bwval
//	durpred := "max(duration)" relop durval
//	relop := "=" | "==" | "!=" | "<" | "<=" | ">" | ">="
//	attrop := "=" | "==" | "!=" | "eq" | "ne" | "has" | "excludes"
//	svcid := [a ZPL service ID]
//	ports := [a ZPL PORTS_TYPE value]
//	types := [a ZPL PORTS_TYPE value with <= 2 numbers]
//	bwval := [a ZPL BANDWIDTH_TYPE value]
//	durval := [a ZPL DURATION_TYPE value]
//	countval := [a nonnegative integer]
//	attrkey := [a string of the form datasource.attrname]
//	attrval := [a string]
//
// Although "=[=]" and "!=" operators are allowed in attribute predicates for
// convenience, they are translated to "eq" and "ne" in the returned structure.
// Similarly, "=" in a count predicate is translated to "==".
func parseStandardLanguageExpression(exprText string) (*standardExpression, error) {
	// The grammar is just simple enough to parse with a regular expression.
	// If we add much to it, for example if we decide to allow "or" and
	// parentheses in predicates, then we'll need to write a real parser.
	exprSubmatches := assertExprRe.FindStringSubmatchIndex(exprText)
	if exprSubmatches == nil {
		expected := "[any] [SERVICE-EXPRESSION] [not] allowed [with CONSTRAINT-PREDICATE] [for COUNT-PREDICATE] [if ATTRIBUTE-PREDICATE]"
		return nil, fmt.Errorf(`expected %q`, expected)
	}

	svcExpr := extractSubmatchText(exprText, assertExprRe, exprSubmatches, "SVCEXPR")
	svcSpecs, err := parseServiceExpression(svcExpr)
	if err != nil {
		return nil, err
	}

	any := extractSubmatchText(exprText, assertExprRe, exprSubmatches, "ANY") != ""
	not := strings.HasPrefix(extractSubmatchText(exprText, assertExprRe, exprSubmatches, "ALLOWED"), "not")

	consPred := strings.TrimSpace(extractSubmatchText(exprText, assertExprRe, exprSubmatches, "CONSPRED"))
	consPredFactors, err := parseConstraintPredicate(consPred, !not)
	if err != nil {
		return nil, err
	}

	countPred := strings.TrimSpace(extractSubmatchText(exprText, assertExprRe, exprSubmatches, "COUNTPRED"))
	countPredFactors, err := parseCountPredicate(countPred)
	if err != nil {
		return nil, err
	}
	if not && len(countPredFactors) > 0 {
		return nil, fmt.Errorf(`count predicates may not appear in "not allowed" assertions: %q`, countPred)
	}

	attrPred := strings.TrimSpace(extractSubmatchText(exprText, assertExprRe, exprSubmatches, "ATTRPRED"))
	attrPredFactors, err := parseConditionPredicate(attrPred)
	if err != nil {
		return nil, err
	}

	allParsed := extractSubmatchText(exprText, assertExprRe, exprSubmatches, "0")
	if len(allParsed) < len(exprText) {
		return nil, fmt.Errorf("extraneous text at end of expression: %q", exprText[len(allParsed):])
	}

	return &standardExpression{
		any:               any,
		services:          svcSpecs,
		allowed:           !not,
		constraintFactors: consPredFactors,
		attributeFactors:  attrPredFactors,
		countFactors:      countPredFactors,
	}, nil
}

// Parses a standard-language service expression of the form [any] {<svcid> |
// <proto> [<params>]} [and {<svcid> | <proto> <params>}...]. Returns the
// individual service specifications in a slice.
func parseServiceExpression(svcExpr string) ([]serviceSpec, error) {
	var specs []serviceSpec

	if svcExpr != "" {
		for _, spec := range assertAndRe.Split(svcExpr, -1) {
			if spec == "" {
				return nil, fmt.Errorf(`misplaced "and" in service expression %q`, svcExpr)
			}

			specSubmatches := assertServiceSpecRe.FindStringSubmatchIndex(spec)
			if specSubmatches == nil {
				return nil, fmt.Errorf(`found %q where "[any] {SERVICE-ID | PROTOCOL [PARAMETERS]}" expected`, spec)
			}
			svcId := extractSubmatchText(spec, assertServiceSpecRe, specSubmatches, "SVCID")
			proto := extractSubmatchText(spec, assertServiceSpecRe, specSubmatches, "PROTO")
			params := strings.TrimSpace(extractSubmatchText(spec, assertServiceSpecRe, specSubmatches, "PARAMS"))

			if proto != "" {
				switch proto {
				case "tcp", "udp":
					if params != "" {
						if err := doc.AssertValidTcpUdpPortType(params); err != nil {
							return nil, fmt.Errorf("invalid %s parameter string %q: %w", proto, params, err)
						}
					}
				case "icmp":
					if params != "" && assertIcmpParamsRe.FindString(params) == "" {
						return nil, fmt.Errorf("invalid %s parameter string: %q", proto, params)
					}
				default:
					return nil, fmt.Errorf("invalid protocol: %q", proto)
				}
			}

			specs = append(specs, serviceSpec{id: svcId, protocol: proto, parameters: params})
		}
	}

	return specs, nil
}

// Parses a standard-language constraint predicate of the form max(<ident>) <op>
// <val> [and max(<ident>) <op> <val>...]. Assumes the constraint expression is
// part of a test for allowed or forbidden access as the second argument is
// true or false respectively. Returns the factor predicates in a slice.
func parseConstraintPredicate(predText string, testingForAllowedAccess bool) ([]simplePredicate, error) {
	var factors []simplePredicate

	if predText != "" {
		for _, factor := range assertAndRe.Split(predText, -1) {
			if factor == "" {
				return nil, fmt.Errorf(`misplaced "and" in constraint predicate %q`, predText)
			}

			predSubmatches := assertSimplePredRe.FindStringSubmatchIndex(factor)
			if predSubmatches == nil {
				return nil, fmt.Errorf(`found %q where "max(IDENTIFIER) OPERATOR VALUE" expected`, factor)
			}
			ident := extractSubmatchText(factor, assertSimplePredRe, predSubmatches, "IDENT")
			op := extractSubmatchText(factor, assertSimplePredRe, predSubmatches, "OP")
			val := assertWhitespaceRe.ReplaceAllString(extractSubmatchText(factor, assertSimplePredRe, predSubmatches, "VAL"), "")

			identSubmatches := assertConsIdentRe.FindStringSubmatchIndex(ident)
			if identSubmatches == nil {
				return nil, fmt.Errorf(`found %q where "max(bandwidth)" or "max(duration)" expected`, ident)
			}
			quant := extractSubmatchText(ident, assertConsIdentRe, identSubmatches, "QUANT")
			switch quant {
			case "bandwidth":
				if _, err := doc.ParseBandwidthType(val); err != nil {
					return nil, fmt.Errorf(`invalid %q constraint in (sub)predicate %q: %w`, ident, factor, err)
				}
			case "duration":
				if _, err := doc.ParseDurationType(val); err != nil {
					return nil, fmt.Errorf(`invalid %q constraint in (sub)predicate %q: %w`, ident, factor, err)
				}
			default:
				return nil, fmt.Errorf("invalid constraint identifier %q in constraint predicate %q", ident, predText)
			}

			if assertRelOpRe.FindString(op) == "" {
				return nil, fmt.Errorf(`invalid operator %q in constraint (sub)predicate %q`, op, factor)
			}

			factors = append(factors, simplePredicate{ident: "max(" + quant + ")", op: op, val: val})
		}
	}

	return factors, nil
}

// Parses a standard-language condition predicate of the form <ident> <op>
// <val> [and <ident> <op> <val>...]. Replaces <op> values of "=[=]" and "!="
// by "eq" and "ne", respectively. Returns the factor predicates in a slice.
func parseConditionPredicate(predText string) ([]simplePredicate, error) {
	var factors []simplePredicate

	if predText != "" {
		for _, factor := range assertAndRe.Split(predText, -1) {
			if factor == "" {
				return nil, fmt.Errorf(`misplaced "and" in condition predicate %q`, predText)
			}

			predSubmatches := assertSimplePredRe.FindStringSubmatchIndex(factor)
			if predSubmatches == nil {
				return nil, fmt.Errorf(`found %q where "IDENTIFIER OPERATOR VALUE" expected`, factor)
			}
			ident := extractSubmatchText(factor, assertSimplePredRe, predSubmatches, "IDENT")
			op := extractSubmatchText(factor, assertSimplePredRe, predSubmatches, "OP")
			val := extractSubmatchText(factor, assertSimplePredRe, predSubmatches, "VAL")

			if assertAttrOpRe.FindString(op) == "" {
				return nil, fmt.Errorf("invalid operator %q in condition (sub)predicate %q", op, factor)
			} else if (op == "has" || op == "excludes") && strings.Contains(val, ",") {
				return nil, fmt.Errorf(`commas not allowed in right operand of operator %q: %q`, op, factor)
			} else if op == "=" || op == "==" {
				op = "eq"
			} else if op == "!=" {
				op = "ne"
			}

			if !assertAttrValRe.MatchString(val) {
				return nil, fmt.Errorf("invalid comparison target %q in condition (sub)predicate %q", val, factor)
			}

			factors = append(factors, simplePredicate{ident, op, val})
		}
	}

	return factors, nil
}

// Parses a standard-language count predicate of the form count(ident>) <op>
// <val> [and count(<ident>) <op> <val>...]. Requires <ident> to be "users".
// Replaces <op> value of "=" by "==". Returns the factor predicates in a slice.
func parseCountPredicate(predText string) ([]simplePredicate, error) {
	var factors []simplePredicate

	if predText != "" {
		for _, factor := range assertAndRe.Split(predText, -1) {
			if factor == "" {
				return nil, fmt.Errorf(`misplaced "and" in count predicate %q`, predText)
			}

			predSubmatches := assertSimplePredRe.FindStringSubmatchIndex(factor)
			if predSubmatches == nil {
				return nil, fmt.Errorf(`found %q where "count(ITEM) OPERATOR VALUE" expected`, factor)
			}

			ident := extractSubmatchText(factor, assertSimplePredRe, predSubmatches, "IDENT")
			op := extractSubmatchText(factor, assertSimplePredRe, predSubmatches, "OP")
			val := assertWhitespaceRe.ReplaceAllString(extractSubmatchText(factor, assertSimplePredRe, predSubmatches, "VAL"), "")

			identSubmatches := assertCountIdentRe.FindStringSubmatchIndex(ident)
			if identSubmatches == nil {
				return nil, fmt.Errorf(`found %q where "count(ITEM)" expected`, ident)
			}
			countItem := extractSubmatchText(ident, assertCountIdentRe, identSubmatches, "ITEM")

			if countItem != "users" {
				return nil, fmt.Errorf(`unsupported item name %q in count (sub)predicate %q (only "users" supported)`, countItem, factor)
			} else if assertRelOpRe.FindString(op) == "" {
				return nil, fmt.Errorf("invalid operator %q in count (sub)predicate %q", op, factor)
			} else if assertAllDigitsRe.FindString(val) == "" {
				return nil, fmt.Errorf("invalid comparison target %q in count (sub)predicate %q (must be nonnegative integer)", val, factor)
			}

			if op == "=" {
				op = "=="
			}

			factors = append(factors, simplePredicate{countItem, op, val})
		}
	}

	return factors, nil
}

// Expands a ZPL port_type value into a sorted list of port numbers. Expects
// the argument string to be a comma-delimited sequence of port numbers and/or
// port number ranges of the form <num1>-<num2>. Returns a slice containing all
// represented port numbers in increasing order. Returns an error on invalid
// syntax.
func expandPortType(input string) ([]uint16, error) {
	portSet := make(map[uint16]bool)

	for _, p := range strings.Split(input, ",") {
		if matches := portOrPortRangeRe.FindAllStringSubmatch(p, -1); matches == nil {
			return nil, fmt.Errorf("not a valid port_type value: %q", p)
		} else {
			for _, m := range matches {
				if p1, err := stringToUint16(m[1]); err != nil {
					return nil, err
				} else {
					p2 := p1
					if m[2] != "" {
						if p2, err = stringToUint16(m[2]); err != nil {
							return nil, err
						} else if p2 < p1 {
							return nil, fmt.Errorf("invalid port range: %v-%v\n", p1, p2)
						}
					}
					for i := int(p1); i <= int(p2); i++ {
						portSet[uint16(i)] = true
					}
				}
			}
		}
	}

	ports := make(uint16Slice, 0, len(portSet))
	for p, _ := range portSet {
		ports = append(ports, p)
	}
	sort.Sort(ports)

	return ports, nil
}

// Converts a string to a float64. On failure returns an error suitable for
// returning from an external expression function implementation.
func stringToFloat64(s string) (float64, error) {
	if f, err := strconv.ParseFloat(s, 64); err != nil {
		return 0., fmt.Errorf("not a number: %q", s)
	} else {
		return f, nil
	}
}

// Converts a string to a uint16. On failure returns an error suitable for
// returning from an external expression function implementation.
func stringToUint16(s string) (uint16, error) {
	if n, err := strconv.ParseUint(s, 10, 16); err != nil {
		return 0., fmt.Errorf("not a 16-bit unsigned integer: %q", s)
	} else {
		return uint16(n), nil
	}
}

// sort.Interface implementation for uint16
type uint16Slice []uint16

func (x uint16Slice) Len() int           { return len(x) }
func (x uint16Slice) Less(i, j int) bool { return x[i] < x[j] }
func (x uint16Slice) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }
