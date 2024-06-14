package pp

// This file contains implementations of internal assertion language functions
// that get registered with the assertion expression evaluator.

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"zpr.org/vsx/zpl/doc"
	yt "zpr.org/vsx/zpl/pp/yamltree"
)

// Implementation for an expression function that converts a ZPL bandwidth_type
// or capacity_type value to an equivalent number of bits per second. The
// argument must contain a bandwidth_type string of the form <num><pfx><dunit>ps
// or a capacity_type string of the form <num><pfx><dunit>/<num><tunit>, where
// <num> is a number, <pfx> is one of the standard metric prefixes k, M, G,
// etc., <dunit> (data unit) is either B or b, and <tunit> (time unit) is s, m,
// h, or d. (Here d always means 24 hours.) Any leading whitespace is ignored,
// as is any text that follows the bandwidth_type or capacity_type value (e.g.,
// a grouping key). This function is intended for use in expression evaluation
// contexts as a ScalarFunction.
func bitrateImpl(arg interface{}) (interface{}, error) {
	if s, ok := arg.(string); !ok {
		return nil, fmt.Errorf("requires string, got %T", s)
	} else if bps, err := doc.ParseBandwidthType(s); err == nil {
		return bps, nil
	} else if bits, period, err := doc.ParseCapacityType(s); err == nil {
		return bits / period, nil
	} else {
		return nil, fmt.Errorf("not a valid bandwidth_type or capacity_type: %q", s)
	}
}

// Implementation for an expression function that converts a ZPL duration_type
// or capacity_type value to an equivalent number of seconds. The argument must
// contain a duration_type string of the form <num><tunit> or a capacity_type
// string of the form <num><pfx><dunit>/<num><tunit>, where <num> is a number,
// <pfx> is one of the standard metric prefixes k, M, G, etc., <dunit> (data
// unit) is either B or b, and <tunit> (time unit) is s, m, h, or d. (Here
// d always means 24 hours.) Any leading whitespace is ignored, as is any text
// that follows the duration_type or capacity_type value (e.g., a grouping key).
// For a capacity_type argument, only the text after the slash is converted.
// This function is intended for use in expression evaluation contexts as a
// ScalarFunction.
func durationImpl(arg interface{}) (interface{}, error) {
	if s, ok := arg.(string); !ok {
		return nil, fmt.Errorf("requires string, got %T", s)
	} else if secs, err := doc.ParseDurationType(s); err == nil {
		return secs, nil
	} else if _, secs, err := doc.ParseCapacityType(s); err == nil {
		return secs, nil
	} else {
		return nil, fmt.Errorf("not a valid duration_type or capacity_type: %q", s)
	}
}

// Implementation for an expression function that extracts and returns the host
// part of a ZPL netaddr_type. Requires the argument to be a netaddr_type string
// of the form <host>:<port>. Ignores any surrounding whitespace, returns <host>
// as a string with any enclosing square brackets removed. This function is
// intended for use in expression evaluation contexts as a ScalarFunction.
func hostImpl(arg interface{}) (interface{}, error) {
	if s, ok := arg.(string); !ok {
		return nil, fmt.Errorf("requires string, got %T", s)
	} else if host, _, err := net.SplitHostPort(strings.TrimSpace(s)); err != nil {
		return nil, err
	} else {
		return host, nil
	}
}

// Implementation for an expression function that extracts and returns the port
// part of a ZPL netaddr_type. Requires the argument to be a netaddr_type string
// of the form <host>:<port>. Ignores any surrounding whitespace, returns <port>
// as a number. This function is intended for use in expression evaluation
// contexts as a ScalarFunction.
func portImpl(arg interface{}) (interface{}, error) {
	if s, ok := arg.(string); !ok {
		return nil, fmt.Errorf("requires string, got %T", s)
	} else if _, port, err := net.SplitHostPort(strings.TrimSpace(s)); err != nil {
		return nil, err
	} else if portnum, err := stringToFloat64(port); err != nil {
		return nil, err
	} else {
		return portnum, nil
	}
}

// Matches a port number n or a port number range of the form n-m. Submatches: $1 = n, $2 = m.
var portOrPortRangeRe = regexp.MustCompile(`^\s*(\d+)(?:\s*-\s*(\d+))?\s*$`)

// Implementation for the internal-language port_set function which translates
// one or more ZPL port_type values into a set of port numbers. Requires the
// argument to be convertible to one or more strings containing comma-delimited
// sequences of port numbers and/or port ranges of the form <num1>-<num2>.
// Conversion may include translating single numeric values to string form or
// decoding scalar Node values. Any whitespace around string values is ignored.
// If the argument is a []interface{} containing multiple port_type values (or
// values convertible to port_type), then the set union of their contents is
// computed. The resulting port numbers are returned in a []interface{} with
// float64 elements in increasing order. This function is intended for use in
// expression evaluation contexts as a GeneralFunction. (It cannot be
// implemented as a ScalarFunction because it returns a multivalued result.)
//
// Does it seem like this function might not exactly be efficient for large port
// ranges? It should, because it isn't. Given the input "1-65535", it produces
// a half-megabyte block of memory containing consecutive integral float64
// values. How dumb is that? It might seem better to provide a function that
// answers questions like "is this port in this set of ports?" by taking a
// port_type and an integer and telling whether the second argument is in the
// set defined by the first. That would take very little memory, but other
// questions like "how many ports are in this set?" or "what is the smallest
// port number in this set" would require additional functions. With a vector,
// all of those questions and more can be answered using machinery that already
// exists in the expression language. A better and fancier alternative might be
// to modify the expression interpreter to allow external functions to return
// custom "dynamic" vectors (e.g., with len and elem functions). Maybe some day.
// Until then, enjoy your slightly warmer CPU.
func portSetImpl(ctx yt.EvaluationContext, arg interface{}) (interface{}, error) {
	var args []interface{}
	switch a := arg.(type) {
	case []interface{}:
		args = a
	default:
		args = []interface{}{a}
	}

	argStrings := make([]string, len(args))
	for i, arg := range args {
		switch a := arg.(type) {
		case yt.Node:
			if a.Kind() != yt.ScalarKind {
				return nil, yt.PathErrorf(yt.PathFrom(ctx.YamlRoot(), a), "%v node not convertible to port_type", a.Kind())
			} else {
				argStrings[i] = a.Value().(string)
			}
		default:
			argStrings[i] = fmt.Sprintf("%v", a)
		}
	}

	var uintPorts uint16Slice

	if len(argStrings) == 1 {
		if ports, err := expandPortType(argStrings[0]); err != nil {
			return nil, err
		} else {
			uintPorts = ports
		}
	} else {
		portSet := map[uint16]bool{}
		for _, s := range argStrings {
			if ports, err := expandPortType(s); err != nil {
				return nil, err
			} else {
				for _, p := range ports {
					portSet[p] = true
				}
			}
		}
		for p, _ := range portSet {
			uintPorts = append(uintPorts, p)
		}
		sort.Sort(uintPorts)
	}

	result := make([]interface{}, len(uintPorts))
	for i, p := range uintPorts {
		result[i] = float64(p)
	}

	return result, nil
}

// Implementation for the internal-language potential_access function, which
// takes either a ZPL policy node or a ZPL component node as an argument and
// returns a corresponding set of descriptors for all the kinds of access the
// policy or component can possibly permit. This set is in the form of a sorted
// slice of string descriptors of the form "<proto><param>", where <proto> is a
// protocol (e.g., "tcp") and <param> is a corresponding port number or other
// discriminating code (e.g., a type value for icmp). The returned slice
// contains no repeated strings and is sorted in standard text order.
//
// The lone argument must be of Node type and correspond to the root of a ZPL
// component block or a policy block within a component block.
//
// The returned value is an interface{} slice whose elements are all strings.
// Its contents are found by inspecting the scopes of all policies indicated
// by the first argument.
//
// This function must be registered with the expression evaluator as a
// GeneralFunction.
func potentialAccessImpl(ctx yt.EvaluationContext, arg interface{}) (interface{}, error) {
	// Collect the potential_access argument(s) in a slice.
	var args []interface{}
	switch a := arg.(type) {
	case []interface{}:
		args = a
	default:
		args = []interface{}{a}
	}

	if len(args) != 1 {
		return nil, fmt.Errorf("must be invoked with one argument (found %d)", len(args))
	}

	// Extract the policies to examine.
	var parsedPolicies []parsedPolicy
	switch a := args[0].(type) {
	case yt.Node:
		if pols, err := parsePolicies(ctx, a); err != nil {
			return nil, err
		} else {
			parsedPolicies = pols
		}
	default:
		return nil, fmt.Errorf("the argument must be a YAML node for a component or policy block; found %v (%T)", a, a)
	}

	// Build the union of the sets of access descriptors for all the policies.
	// TODO Will have to change this to inspect services named in the enclosing component.
	potentialAccess := make(map[string]bool)
	for _, pol := range parsedPolicies {
		if ctx.NodeLogger() != nil {
			ctx.NodeLogger().Log(pol.path, fmt.Sprintf("potential access for policy: {%s}", strings.Join(pol.comServices, ", ")))
		}
		for _, a := range pol.comServices {
			potentialAccess[a] = true
		}
	}

	// Return the access descriptors in a sorted slice
	result := make([]interface{}, 0, len(potentialAccess))
	for a, _ := range potentialAccess {
		result = append(result, a)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].(string) < result[j].(string) })

	return result, nil
}

// Implementation for the internal-language permitted_access function, which
// examines a ZPL policy or component node and returns a summary of the kinds
// of access the policy or component is guaranteed to permit to any agent whose
// attributes satisfy a given condition predicate, provided the constraints of
// any visa granted to such an agent satisfy a given constraint predicate.
//
// The second argument must be a slice containing three elements: (1) the root
// of a policy block or component block, (2) a condition predicate, and (3) a
// constraint predicate. Predicates are ignored if nil or empty.
//
// The returned value contains a slice of access descriptors that constitute a
// subset of that returned by potentialAccessImpl.
//
// This function must be registered with the expression evaluator as a
// GeneralFunction.
func permittedAccessImpl(ctx yt.EvaluationContext, arg interface{}) (interface{}, error) {
	return permittedOrNonforbiddenAccess(ctx, arg, "permitted")
}

// Implementation for the internal-language nonforbidden_access function, which
// examines a ZPL policy or component node and returns a summary of the kinds of
// access the policy or component is not guaranteed to deny to any agent whose
// attributes satisfy a given condition predicate, provided the constraints of
// any visa granted to such an agent satisfy a given constraint predicate.
//
// The second argument must be a slice containing three elements: (1) the root
// of a policy block or component block, (2) a condition predicate, and (3) a
// constraint predicate. Predicates are ignored if nil or empty.
//
// The returned value contains a slice of access descriptors that constitute a
// subset of that returned by potentialAccessImpl.
//
// This function must be registered with the expression evaluator as a
// GeneralFunction.
func nonforbiddenAccessImpl(ctx yt.EvaluationContext, arg interface{}) (interface{}, error) {
	return permittedOrNonforbiddenAccess(ctx, arg, "nonforbidden")
}

// Common implementation for permittedAccess and nonforbiddenAccess. Last
// argument must be "permitted" or "nonforbidden".
func permittedOrNonforbiddenAccess(ctx yt.EvaluationContext, arg interface{}, accessRealm string) (interface{}, error) {
	// Extract the permitted_access or nonforbidden_access arguments.
	var node yt.Node
	var condPred string
	var consPred string
	signatureFailCode := 0
	if a, ok := arg.([]interface{}); !ok {
		signatureFailCode = 1
	} else if len(a) != 3 {
		signatureFailCode = 2
	} else if node, ok = a[0].(yt.Node); !ok {
		signatureFailCode = 3
	} else if condPred, ok = a[1].(string); !ok && a[1] != nil {
		signatureFailCode = 4
	} else if consPred, ok = a[2].(string); !ok && a[2] != nil {
		signatureFailCode = 5
	}
	if signatureFailCode > 0 {
		return nil, fmt.Errorf("(ERR1.%d) requires three arguments (node, string, string)", signatureFailCode)
	}

	// Extract the policies to examine.
	parsedPolicies, err := parsePolicies(ctx, node)
	if err != nil {
		return nil, err
	}

	// Build a set of potential_access-style descriptors for access permitted or
	// not forbidden by the policies.
	allComputedAccess := make(map[string]bool) // e.g., "tcp80" -> true, etc.
	for _, pp := range parsedPolicies {
		pol := pp.parsed
		polPath := pp.path

		// TODO After the change to components, can replace this with a
		// call to potentialAccess for the component outside the loop,
		// since policy blocks won't have their own scopes any more.
		var polPotentialAccess []string // e.g., ["tcp22", "udp53"]
		paResult, err := potentialAccessImpl(ctx, lastNode(polPath))
		if err != nil {
			return nil, err
		}
		paSlice := paResult.([]interface{})
		for _, a := range paSlice {
			polPotentialAccess = append(polPotentialAccess, a.(string))
		}

		var polComputedAccess []string
		var polTestInfo string
		not := func(b bool) string {
			if b {
				return ""
			} else {
				return " not"
			}
		}

		constraintsSatisfied := true
		if consPred != "" {
			constraintsSatisfied, err = predicateImpliesPolicyConstraintsSatisfied(consPred, pol)
			if err != nil {
				return nil, err
			}
		}

		switch accessRealm {
		case "permitted":
			conditionsSatisfied := true
			if condPred != "" {
				conditionsSatisfied, err = predicateImpliesPolicyConditionsSatisfied(condPred, pol)
				if err != nil {
					return nil, err
				}
			}
			if conditionsSatisfied && constraintsSatisfied {
				polComputedAccess = polPotentialAccess
			}
			polTestInfo = fmt.Sprintf("conditions%s satisfied, constraints%s satisfied", not(conditionsSatisfied), not(constraintsSatisfied))
		case "nonforbidden":
			conditionsViolated := false
			if condPred != "" {
				conditionsViolated, err = predicateImpliesPolicyConditionsViolated(condPred, pol)
				if err != nil {
					return nil, err
				}
			}
			if !conditionsViolated && constraintsSatisfied {
				polComputedAccess = polPotentialAccess
			}
			polTestInfo = fmt.Sprintf("conditions%s violated, constraints%s satisfied", not(conditionsViolated), not(constraintsSatisfied))
		default:
			return nil, fmt.Errorf("invalid accessRealm %q!", accessRealm) // "can't happen"
		}

		if ctx.NodeLogger() != nil {
			ctx.NodeLogger().Log(polPath, polTestInfo, fmt.Sprintf("%s access for policy: {%s}", accessRealm, strings.Join(polComputedAccess, ", ")))
		}
		for _, a := range polComputedAccess {
			allComputedAccess[a] = true
		}
	}

	if ctx.NodeLogger() != nil && node.Kind() != yt.SequenceKind {
		// Policy nodes are sequences, so this node must be for a component.
		compPath := yt.PathFrom(ctx.YamlRoot(), node)
		compAccess := make([]string, 0, len(allComputedAccess))
		for a, _ := range allComputedAccess {
			compAccess = append(compAccess, a)
		}
		sort.Strings(compAccess)
		ctx.NodeLogger().Log(compPath, fmt.Sprintf("%s access for component: {%s}", accessRealm, strings.Join(compAccess, ", ")))
	}

	// Return the access descriptors in a sorted slice
	result := make([]interface{}, 0, len(allComputedAccess))
	for a, _ := range allComputedAccess {
		result = append(result, a)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].(string) < result[j].(string) })

	return result, nil
}

// A parsed policy block.
type parsedPolicy struct {
	path        []yt.Node   // path from overall root to policy block
	parsed      *doc.Policy // parsed policy
	comServices []string    // parent components services in expanded "<PROTOCOL><PORT>" form.
}

// Parses one or more policy blocks. The Node argument must be the root of
// either a policy block, in which just that block is parsed, or a component
// block, in which all of the component's policies are parsed.
//
// TODO: (mathias asks...) Why is there another parser here?  Surely the parsing
//       should be done once... in the preprocessor code.  This does not take
//       care of apply or allow, for example.
func parsePolicies(ctx yt.EvaluationContext, blockNode yt.Node) ([]parsedPolicy, error) {
	results := make([]parsedPolicy, 0)
	blockPath := yt.PathFrom(ctx.YamlRoot(), blockNode)

	// Exploit the fact that policy blocks live in sequences (within component
	// blocks), whereas component blocks live in mappings (within system blocks)
	// to decide which kind of block to attempt to parse.
	if len(blockPath) < 2 {
		return nil, yt.PathErrorf(blockPath, "can't inspect presumed policy or component block's parent")
	} else {
		parent := blockPath[len(blockPath)-2] // Why -2?
		switch parent.Kind() {
		case yt.SequenceKind:
			// Assume it's a policy block -- we need the parent services befofre parsing.
			// So find the enclosing component so we can get the list of services.
			var svcNames []string
			grandparent := blockPath[len(blockPath)-3]
			if grandparent.Kind() == yt.MappingKind {
				cMap := childPathMap([]yt.Node{grandparent})
				svcNames = extractServicesFromComponentNArr(cMap)
			}
			if len(svcNames) == 0 {
				panic("every policy must have at least one service in its parent component")
			}
			var svcs []string
			for _, sname := range svcNames {
				if expanded := ctx.ServiceByName(sname); len(expanded) > 0 {
					svcs = append(svcs, expanded...)
				} else {
					return nil, yt.PathErrorf(blockPath, "policy references unknown service: '%v'", sname)
				}
			}
			if pol, err := ParsePolicy(blockPath, svcNames, nil, DSCheckOff, nil, ErrModeSilent); err != nil {
				return nil, yt.PathErrorf(blockPath, "not a valid policy block: %w", err)
			} else {
				results = append(results, parsedPolicy{
					path:        blockPath,
					parsed:      pol,
					comServices: svcs})
			}
		case yt.MappingKind:
			// Assume it's a component block. Find and parse its policy blocks.
			if m, ok := blockNode.Value().(map[string]yt.Node); !ok {
				return nil, yt.PathErrorf(blockPath, `not a valid component block: not a mapping: %v`, blockNode)
			} else if polsNode, ok := m["policies"]; !ok {
				return nil, yt.PathErrorf(blockPath, `not a valid component block: no "policies" key: %v`, blockNode)
			} else if polsSeq, ok := polsNode.Value().([]yt.Node); !ok {
				return nil, yt.PathErrorf(yt.AppendToPathCopy(blockPath, polsNode), `not a valid component block: "policies" not a sequence: %v`, polsNode)
			} else {
				var svcs []string
				for _, sname := range extractServicesFromComponent(m) {
					if expanded := ctx.ServiceByName(sname); len(expanded) > 0 {
						svcs = append(svcs, expanded...)
					} else {
						return nil, yt.PathErrorf(blockPath, "component references unknown service: %v", sname)
					}
				}
				if len(svcs) == 0 {
					panic("every component must have at least one service")
				}
				for _, polNode := range polsSeq {
					polPath := yt.AppendToPathCopy(blockPath, polsNode, polNode)
					if pol, err := ParsePolicy(polPath, svcs, nil, DSCheckOff, nil, ErrModeSilent); err != nil {
						return nil, yt.PathErrorf(polPath, "not a valid policy block: %w", err)
					} else {
						results = append(results, parsedPolicy{
							path:        polPath,
							parsed:      pol,
							comServices: svcs})
					}
				}
			}
		}
	}
	if len(results) == 0 {
		return nil, yt.PathErrorf(blockPath, "not a valid component or policy block: %v", blockNode)
	}

	return results, nil
}

// extractServicesFromComponent given a component node returns the list of
// services (strings) referenced.
func extractServicesFromComponent(m map[string]yt.Node) []string {
	var scopes []string
	if svcsNode, ok := m["services"]; ok {
		for _, scopeNode := range childPathSeq([]yt.Node{svcsNode}) {
			if sname, err := doc.NewZplString(scopeNode); err == nil {
				scopes = append(scopes, sname.String())
			}
		}
	}
	return scopes
}

func extractServicesFromComponentNArr(m map[string][]yt.Node) []string {
	var scopes []string
	if svcsPath, ok := m["services"]; ok {
		for _, svcNode := range childPathSeq(svcsPath) {
			if sname, err := doc.NewZplString(svcNode); err == nil {
				scopes = append(scopes, sname.String())
			}
		}
	}
	return scopes
}

// Tells whether or not a predicate implies the conditions of a policy. Returns
// true iff knowledge that an agent's attributes satisfy pred is sufficient to
// conclude that pol's conditions would all be met for that agent. Returns a
// non-nil error if pred is not parsable by parseConditionPredicate.
func predicateImpliesPolicyConditionsSatisfied(pred string, pol *doc.Policy) (bool, error) {
	predFactors, err := parseConditionPredicate(pred)
	if err != nil {
		return false, err
	}
	allCondsImplied := true
condLoop:
	for _, cond := range pol.Conditions {
		for _, expr := range cond.AttrExprs {
			exprImplied := false
			for _, fact := range predFactors {
				if fact.ident == expr.Key.String() {
					switch fact.op + " " + expr.Op.String() {
					case "eq eq", "ne ne", "has has", "excludes excludes", "excludes ne":
						exprImplied = fact.val == expr.Value.String()
					case "eq ne":
						exprImplied = fact.val != expr.Value.String()
					case "eq has":
						exprImplied = commaDelimitedStringIncludes(fact.val, expr.Value.String())
					case "eq excludes":
						exprImplied = !commaDelimitedStringIncludes(fact.val, expr.Value.String())
					}
				}
				if exprImplied {
					break
				}
			}
			if !exprImplied {
				allCondsImplied = false
				break condLoop
			}
		}
	}
	return allCondsImplied, nil
}

// Tells whether or not a predicate implies violation of the conditions of a
// policy. Returns true iff knowledge that an agent's attributes satisfy pred
// is sufficient to conclude that pol's conditions would not all be met for
// that agent. Returns a non-nil error if pred is not parsable by
// parseConditionPredicate.
func predicateImpliesPolicyConditionsViolated(pred string, pol *doc.Policy) (bool, error) {
	predFactors, err := parseConditionPredicate(pred)
	if err != nil {
		return false, err
	}
	someCondRefuted := false
condLoop:
	for _, cond := range pol.Conditions {
		for _, expr := range cond.AttrExprs {
			exprRefuted := false
			for _, fact := range predFactors {
				if fact.ident == expr.Key.String() {
					switch fact.op + " " + expr.Op.String() {
					case "eq ne", "ne eq", "has excludes", "excludes eq", "excludes has":
						exprRefuted = fact.val == expr.Value.String()
					case "eq eq":
						exprRefuted = fact.val != expr.Value.String()
					case "eq has":
						exprRefuted = !commaDelimitedStringIncludes(fact.val, expr.Value.String())
					case "eq excludes":
						exprRefuted = commaDelimitedStringIncludes(fact.val, expr.Value.String())
					}
				}
				if exprRefuted {
					break
				}
			}
			if exprRefuted {
				someCondRefuted = true
				break condLoop
			}
		}
	}
	return someCondRefuted, nil
}

// Tells whether or not a predicate implies a policy's constraints. Returns true
// iff knowledge that the characteristics of a network flow satisfy pred is
// sufficient to conclude that the flow would satisfy all constraints that pol
// makes for flow properties named in pred. Returns a non-nil error if pred is
// not parsable by parseContraintsPredicate.
func predicateImpliesPolicyConstraintsSatisfied(pred string, pol *doc.Policy) (bool, error) {
	predFactors, err := parseConstraintPredicate(pred, true)
	if err != nil {
		return false, err
	}

	allConsSat := true
	if pol.Constraints != nil {
		for _, fact := range predFactors {
			var factVal, consVal float64
			switch fact.ident {
			case "max(bandwidth)":
				if pol.Constraints.Bandwidth.Value() == nil {
					continue
				}
				consVal, _ = doc.ParseBandwidthType(pol.Constraints.Bandwidth.String())
				factVal, _ = doc.ParseBandwidthType(fact.val)
			case "max(duration)":
				if pol.Constraints.Duration.Value() == nil {
					continue
				}
				consVal, _ = doc.ParseDurationType(pol.Constraints.Duration.String())
				factVal, _ = doc.ParseDurationType(fact.val)
			default:
				return false, fmt.Errorf("invalid constraint identifier: %q", fact.ident)
			}

			factSat := false
			switch fact.op {
			case "=", "==":
				factSat = consVal == factVal
			case "!=":
				factSat = consVal != factVal
			case "<":
				factSat = consVal < factVal
			case "<=":
				factSat = consVal <= factVal
			case ">":
				factSat = consVal > factVal
			case ">=":
				factSat = consVal >= factVal
			}
			if !factSat {
				allConsSat = false
				break
			}
		}
	}

	return allConsSat, nil
}

// Implementation for the internal-language permitted_access_counts function,
// which accepts the same arguments as permitted_access and returns the same
// information plus current counts of agents with for kind of access. Returns
// a slice of string descriptors of the form "<proto><param>=<count>", where
// <proto> is a protocol (e.g., "tcp"), <param> is a corresponding port number
// or other discriminating code (e.g., a type value for icmp), and <count> is
// an agent count.
//
// As for permittedAccessImpl, the second argument must be a slice containing
// three elements: (1) the root of a policy block or component block, (2) a
// condition predicate, and (3) a constraint predicate. Each returned agent
// count represents the number of users whose attributes satisfy the condition
// predicate (or, if it is empty, the policy conditions for the associated
// <proto><param> access) and are sufficient to grant access for which the
// constraint predicate is satisfied. Counts are obtained by querying data
// sources through DataSourceProxy instances that are obtained from the
// context argument, which is required to have an underlying type of
// *dataSourceEvaluationContext.
//
// This function must be registered with the expression evaluator as a
// GeneralFunction.
func permittedAccessCountsImpl(ctx yt.EvaluationContext, arg interface{}) (interface{}, error) {
	// Extract the permitted_access_counts arguments.
	var node yt.Node
	var condPred string
	var consPred string
	signatureFailCode := 0
	if a, ok := arg.([]interface{}); !ok {
		signatureFailCode = 1
	} else if len(a) != 3 {
		signatureFailCode = 2
	} else if node, ok = a[0].(yt.Node); !ok {
		signatureFailCode = 3
	} else if condPred, ok = a[1].(string); !ok && a[1] != nil {
		signatureFailCode = 4
	} else if consPred, ok = a[2].(string); !ok && a[2] != nil {
		signatureFailCode = 5
	}
	if signatureFailCode > 0 {
		return nil, fmt.Errorf("(ERR2.%d) requires three arguments (node, string, string)", signatureFailCode)
	}

	// Extract the policies to examine from the YAML.
	parsedPolicies, err := parsePolicies(ctx, node)
	if err != nil {
		return nil, err
	}

	// Extract the data source proxy map from the evaluation context.
	// See ProcessAssertions.
	var dataSourceProxies map[string]DataSourceProxy // DS name -> proxy
	if dsCtx, ok := ctx.(*dataSourceEvaluationContext); !ok {
		return nil, fmt.Errorf("cannot extract data source proxy map from evaluation context of type %T", ctx)
	} else {
		dataSourceProxies = dsCtx.dataSources
	}

	// Set up a map of access descriptors (a la potential_access) to sets of
	// unique IDs for all agents whose attributes satisfy the argument
	// predicate (if any) and also entitle them to the corresponding forms
	// of access according to at least one of the policies we're about to
	// examine.  These ID sets will be unions of corresponding the sets
	// computed for the different policies.
	unionAgentIds := make(map[string]map[string]bool) // descriptor (e.g., "tcp22") -> ID -> true

	// Set up (1) a set of unique IDs for all agents whose attributes satisfy
	// the argument condition predicate and (2) a map of data source names to
	// corresponding agent counts. Don't populate these yet; do so later only
	// if some policy's conditions and constraints are found to be satisfied
	// by both of the argument predicates.
	var condPredAgentIds map[string]bool   // agent ID -> true
	var condPredAgentCounts map[string]int // DS name -> count

	for _, pp := range parsedPolicies {
		pol := pp.parsed
		polPath := pp.path

		// Get the potential access for this policy.
		// TODO After the change to components, replace this with a call to
		// potentialAccess for the component and move it outside the loop,
		// since policy blocks won't have their own scopes any more.
		var polPotentialAccess []string // e.g., ["tcp22", "udp53"]
		paResult, err := potentialAccessImpl(ctx, lastNode(polPath))
		if err != nil {
			return nil, err
		}
		paSlice := paResult.([]interface{})
		for _, a := range paSlice {
			polPotentialAccess = append(polPotentialAccess, a.(string))
		}

		conditionsSatisfied := true
		if condPred != "" {
			conditionsSatisfied, err = predicateImpliesPolicyConditionsSatisfied(condPred, pol)
			if err != nil {
				return nil, err
			}
		}

		constraintsSatisfied := true
		if consPred != "" {
			constraintsSatisfied, err = predicateImpliesPolicyConstraintsSatisfied(consPred, pol)
			if err != nil {
				return nil, err
			}
		}

		not := func(b bool) string {
			if b {
				return ""
			} else {
				return " not"
			}
		}
		polTestInfo := fmt.Sprintf("conditions%s satisfied, constraints%s satisfied", not(conditionsSatisfied), not(constraintsSatisfied))

		// Computed results for this policy.
		var polAgentIds map[string]bool        // ID -> true
		var polAgentCounts map[string]int      // DS name -> count
		var polPermittedAccess map[string]bool // access desc (e.g., "tcp443") -> true

		if conditionsSatisfied && constraintsSatisfied {
			// The argument predicates (if any) satisfy this policy's conditions
			// and constraints, so now we need to get the IDs of all agents the
			// policy would grant access to. If there is a condition predicate,
			// then we need to find out which agents' attributes satisfy it.
			// Otherwise we need to know which agents' attributes satisfy all of
			// this policy's condition expressions.
			if condPred != "" {
				// There is a condition predicate argument. Break it into simple
				// predicate factors, group them by data source, and query each
				// data source for the IDs of the agents that satisfy the
				// corresponding factors. We only need to do this once, because
				// the results are independent of which policy we're looking at.
				if condPredAgentIds == nil {
					condPredAgentIds = make(map[string]bool)
					condPredFactors, _ := parseConditionPredicate(condPred) // can't fail at this point
					if len(condPredFactors) > 0 {
						attrExprs := make(map[string][]AttributeExpression) // ds name -> attr exprs
						exprSource := fmt.Sprintf("condition predicate %q", condPred)
						for _, fact := range condPredFactors {
							identFields := strings.SplitN(fact.ident, ".", 2)
							if len(identFields) != 2 {
								return nil, fmt.Errorf(`attribute identifier %q not of the form "<datasource>.<attribute>" in %s`, fact.ident, exprSource)
							}
							dsName := identFields[0]
							attrName := identFields[1]
							attrExprs[dsName] = append(attrExprs[dsName], AttributeExpression{Name: attrName, Operator: fact.op, Value: fact.val})
						}
						if agentIds, agentCounts, err := queryDataSourcesForAgentIds(dataSourceProxies, attrExprs, exprSource); err != nil {
							return nil, err
						} else {
							condPredAgentIds = agentIds
							condPredAgentCounts = agentCounts
						}
					}
				}
				polAgentIds = condPredAgentIds
				polAgentCounts = condPredAgentCounts
			} else {
				// There is no condition predicate argument, so we need to find
				// the IDs of all agents whose attribute satisfy the current
				// policy's conditions. So group the conditions' attribute
				// expressions by data source, and query each data source for
				// the agent IDs that satisfy the corresponding expressions.
				attrExprs := make(map[string][]AttributeExpression) // DS name -> exprs
				attrExprTexts := make([]string, 0)
				for _, cond := range pol.Conditions {
					for _, expr := range cond.AttrExprs {
						exprText := fmt.Sprintf("[%s, %s, %s]", expr.Key.String(), expr.Op.String(), expr.Value.String())
						identFields := strings.SplitN(expr.Key.String(), ".", 2)
						if len(identFields) != 2 {
							return nil, fmt.Errorf(`attribute identifier %q not of the form "<datasource>.<attribute>" in %s`,
								expr.Key.String(), "policy attribute expression "+exprText)
						}
						dsName := identFields[0]
						attrName := identFields[1]
						attrExprs[dsName] = append(attrExprs[dsName], AttributeExpression{Name: attrName, Operator: expr.Op.String(), Value: expr.Value.String()})
						attrExprTexts = append(attrExprTexts, exprText)
					}
				}
				exprSource := "policy attribute expression(s) " + strings.Join(attrExprTexts, ", ")
				if agentIds, agentCounts, err := queryDataSourcesForAgentIds(dataSourceProxies, attrExprs, exprSource); err != nil {
					return nil, err
				} else {
					polAgentIds = agentIds
					polAgentCounts = agentCounts
				}
			}

			// Compute that access this policy permits and add the IDs of the agents
			// it authorizes to the union sets.
			polPermittedAccess = make(map[string]bool, len(pp.comServices))
			for _, desc := range pp.comServices {
				polPermittedAccess[desc] = true
				idSet := unionAgentIds[desc]
				if idSet == nil {
					idSet = make(map[string]bool)
					unionAgentIds[desc] = idSet
				}
				for id, _ := range polAgentIds {
					idSet[id] = true
				}
			}

		}

		if ctx.NodeLogger() != nil {
			polCountInfo := ""
			if conditionsSatisfied && constraintsSatisfied {
				if len(polAgentCounts) > 0 {
					var counts []string
					for dsName, count := range polAgentCounts {
						counts = append(counts, fmt.Sprintf("(%s, %d)", dsName, count))
					}
					sort.Strings(counts)
					polCountInfo = fmt.Sprintf("data source agent counts: %s", strings.Join(counts, ", "))
				}
			}

			access := make([]string, 0, len(polPermittedAccess))
			for desc, _ := range polPermittedAccess {
				access = append(access, desc)
			}
			sort.Strings(access)

			ctx.NodeLogger().Log(polPath, polTestInfo, polCountInfo, fmt.Sprintf("permitted access for policy: {%s}", strings.Join(access, ", ")))
		}
	}

	// Build a sorted list of access descriptors plus agent counts.
	countDescs := make([]string, 0, len(unionAgentIds))
	for desc, idSet := range unionAgentIds {
		countDescs = append(countDescs, fmt.Sprintf("%s=%d", desc, len(idSet)))
	}
	sort.Strings(countDescs)

	if ctx.NodeLogger() != nil && node.Kind() != yt.SequenceKind {
		// Policy nodes are sequences, so this node must be for a component.
		compPath := yt.PathFrom(ctx.YamlRoot(), node)
		ctx.NodeLogger().Log(compPath, fmt.Sprintf("agent counts for component: {%s}", strings.Join(countDescs, ", ")))
	}

	// Return the results in a sorted slice
	result := make([]interface{}, 0, len(countDescs))
	for _, a := range countDescs {
		result = append(result, a)
	}
	return result, nil
}

// Returns a slice of descriptors of the form "<proto><params>" representing
// the the scope of the specified component.
func accessDescriptorsForServices(scopings []*doc.Scoping) ([]string, error) {
	var descs []string
	for _, scoping := range scopings {
		if !scoping.TCP.Empty() {
			if ports, err := expandPortType(scoping.TCP.String()); err != nil {
				return nil, err
			} else {
				for _, p := range ports {
					descs = append(descs, fmt.Sprintf("tcp%d", p))
				}
			}
		}
		if !scoping.UDP.Empty() {
			if ports, err := expandPortType(scoping.UDP.String()); err != nil {
				return nil, err
			} else {
				for _, p := range ports {
					descs = append(descs, fmt.Sprintf("udp%d", p))
				}
			}
		}
		if scoping.ICMP != nil {
			if scoping.ICMP.TypeCodes.Value() != nil {
				if types, err := expandPortType(scoping.ICMP.TypeCodes.String()); err != nil {
					return nil, err
				} else {
					for _, t := range types {
						descs = append(descs, fmt.Sprintf("icmp%d", t))
					}
				}
			}
		}
	}
	return descs, nil
}

// Queries external data sources for the IDs of agents that satisfy a collection
// of attribute expressions. The first two arguments contain data source proxies
// and attribute expressions, in both cases indexed by data source name. The
// last argument is a brief description of where the expression came from and is
// included in an error value in case of failure. On success returns (1) a set
// of all agent IDs (mapped to true) that occur in the query results from all
// data sources in the key set of attrExprs and (2) a map of data source names
// to corresponding result set sizes.
func queryDataSourcesForAgentIds(dataSources map[string]DataSourceProxy, attrExprs map[string][]AttributeExpression, exprSource string) (map[string]bool, map[string]int, error) {
	var resultIds map[string]bool        // ID -> true
	resultCounts := make(map[string]int) // DS name -> count
	for dsName, dsExprs := range attrExprs {
		if proxy, ok := dataSources[dsName]; !ok {
			return nil, nil, fmt.Errorf(`no proxy defined for data source %q referenced in %s`, dsName, exprSource)
		} else if agentIds, err := proxy.AgentIds(dsExprs); err != nil {
			return nil, nil, fmt.Errorf(`failed to query data source proxy %q referenced in %s: %w`, dsName, exprSource, err)
		} else {
			resultCounts[dsName] = len(agentIds)
			if resultIds == nil {
				resultIds = make(map[string]bool)
				for _, id := range agentIds {
					resultIds[id] = true
				}
			} else {
				newResultIds := make(map[string]bool, len(resultIds))
				for _, id := range agentIds {
					if resultIds[id] {
						newResultIds[id] = true
					}
				}
				resultIds = newResultIds
			}
		}
	}
	return resultIds, resultCounts, nil
}

// Returns true iff string s1, viewed as a comma-delimited sequence of string
// components, contains s2 as a component.
func commaDelimitedStringIncludes(s1, s2 string) bool {
	for _, s := range strings.Split(s1, ",") {
		if s == s2 {
			return true
		}
	}
	return false
}
