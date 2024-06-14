package yamltree

import (
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Implementations of functions built in to the expression evaluator.

// Built-in "any" function. Returns true if any of the arguments is true,
// false if they are all false. Stops checking arguments as soon as a true
// one is found. Returns an error if any argument is found to be anything
// other than a boolean. Should be registered as a GeneralFunction.
func anyFunc(ctx EvaluationContext, arg interface{}) (interface{}, error) {
	arg1, err := decodeScalarNodesInArg(ctx.YamlRoot(), arg)
	if err != nil {
		return nil, err
	}
	var args []interface{}
	switch a := arg1.(type) {
	case nil:
		args = []interface{}{}
	case []interface{}:
		args = a
	default:
		args = []interface{}{arg1}
	}
	for _, a := range args {
		if b, ok := a.(bool); !ok {
			return nil, fmt.Errorf("all arguments must be boolean (saw %T)", a)
		} else if b {
			return true, nil
		}
	}
	return false, nil
}

// Built-in "all" function. Returns true if all of the arguments are true (or
// if there are no arguments) and false otherwise. Stops checking arguments as
// soon as a false one is found. Returns an error if any argument is found to
// be anything other than a boolean. Should be registered as a GeneralFunction.
func allFunc(ctx EvaluationContext, arg interface{}) (interface{}, error) {
	arg1, err := decodeScalarNodesInArg(ctx.YamlRoot(), arg)
	if err != nil {
		return nil, err
	}
	var args []interface{}
	switch a := arg1.(type) {
	case nil:
		args = []interface{}{}
	case []interface{}:
		args = a
	default:
		args = []interface{}{arg1}
	}
	for _, a := range args {
		if b, ok := a.(bool); !ok {
			return nil, fmt.Errorf("all arguments must be boolean (saw %T)", a)
		} else if !b {
			return false, nil
		}
	}
	return true, nil
}

// Built-in "count" function. Returns the number of true arguments. Returns
// an error if any of the arguments are not boolean.
// Should be registered as a GeneralFunction.
func countFunc(ctx EvaluationContext, arg interface{}) (interface{}, error) {
	arg1, err := decodeScalarNodesInArg(ctx.YamlRoot(), arg)
	if err != nil {
		return nil, err
	}
	var args []interface{}
	switch a := arg1.(type) {
	case nil:
		args = []interface{}{}
	case []interface{}:
		args = a
	default:
		args = []interface{}{arg1}
	}
	numTrue := 0
	for _, a := range args {
		if b, ok := a.(bool); !ok {
			return nil, fmt.Errorf("all arguments must be boolean (saw %T)", a)
		} else if b {
			numTrue++
		}
	}
	return float64(numTrue), nil
}

// Built-in "len" function. Returns the number of argument passed to it.
// Should be registered as a GeneralFunction.
func lenFunc(ctx EvaluationContext, arg interface{}) (interface{}, error) {
	arg1, err := decodeScalarNodesInArg(ctx.YamlRoot(), arg)
	if err != nil {
		return nil, err
	}
	switch a := arg1.(type) {
	case nil:
		return 0., nil
	case []interface{}:
		return float64(len(a)), nil
	default:
		return 1., nil
	}
}

// Built-in "exists" function. Returns true if the number of arguments
// is nonzero, false otherwise. Should be registered as a GeneralFunction.
func existsFunc(ctx EvaluationContext, arg interface{}) (interface{}, error) {
	count, err := lenFunc(ctx, arg)
	return count.(float64) > 0, err
}

// Built-in "sum" function. Returns the sum of the arguments or zero
// if there are no arguments. Returns an error if any of the arguments
// is non-numeric. Should be registered as a GeneralFunction.
func sumFunc(ctx EvaluationContext, arg interface{}) (interface{}, error) {
	arg1, err := decodeScalarNodesInArg(ctx.YamlRoot(), arg)
	if err != nil {
		return nil, err
	}
	var args []interface{}
	switch a := arg1.(type) {
	case nil:
		args = []interface{}{}
	case []interface{}:
		args = a
	default:
		args = []interface{}{arg1}
	}
	sum := 0.
	for _, a := range args {
		if x, ok := a.(float64); !ok {
			return nil, fmt.Errorf("all arguments must be numeric (found %T)", a)
		} else {
			sum += x
		}
	}
	return sum, nil
}

// Built-in "min" function. Returns the minimum of the arguments. Returns
// an error if there are no arguments or if any or them are non-numeric.
// Should be registered as a GeneralFunction.
func minFunc(ctx EvaluationContext, arg interface{}) (interface{}, error) {
	arg1, err := decodeScalarNodesInArg(ctx.YamlRoot(), arg)
	if err != nil {
		return nil, err
	}
	var args []interface{}
	switch a := arg1.(type) {
	case nil:
		args = []interface{}{}
	case []interface{}:
		args = a
	default:
		args = []interface{}{arg1}
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("argument list must not be empty")
	}
	min := math.Inf(1)
	for _, a := range args {
		if x, ok := a.(float64); !ok {
			return nil, fmt.Errorf("all arguments must be numeric (found %T)", a)
		} else if x < min {
			min = x
		}
	}
	return min, nil
}

// Built-in "max" function. Returns the maximum of the arguments. Returns
// an error if there are no arguments or if any or them are non-numeric.
// Should be registered as a GeneralFunction.
func maxFunc(ctx EvaluationContext, arg interface{}) (interface{}, error) {
	arg1, err := decodeScalarNodesInArg(ctx.YamlRoot(), arg)
	if err != nil {
		return nil, err
	}
	var args []interface{}
	switch a := arg1.(type) {
	case nil:
		args = []interface{}{}
	case []interface{}:
		args = a
	default:
		args = []interface{}{arg1}
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("argument list must not be empty")
	}
	max := math.Inf(-1)
	for _, a := range args {
		if x, ok := a.(float64); !ok {
			return nil, fmt.Errorf("all arguments must be numeric (found %T)", a)
		} else if x > max {
			max = x
		}
	}
	return max, nil
}

// Built-in "sort" function. Returns a sorted slice of the arguments.
// Should be registered as a GeneralFunction.
func sortFunc(ctx EvaluationContext, arg interface{}) (interface{}, error) {
	// Convert args to a vector of scalars represented by a []interface{}
	arg1, err := decodeScalarNodesInArg(ctx.YamlRoot(), arg)
	if err != nil {
		return nil, err
	}
	var args []interface{}
	switch a := arg1.(type) {
	case nil:
		args = []interface{}{}
	case []interface{}:
		args = a
	default:
		args = []interface{}{arg1}
	}

	// Group the args by type. Only a few types are possible.
	var nilArgs, boolArgs, floatArgs, stringArgs []interface{}
	for _, a := range args {
		switch a.(type) {
		case nil:
			nilArgs = append(nilArgs, a)
		case bool:
			boolArgs = append(boolArgs, a)
		case float64:
			floatArgs = append(floatArgs, a)
		case string:
			stringArgs = append(stringArgs, a)
		default:
			return nil, fmt.Errorf("argument of unexpected type in sort: %v (%v)\n", a, reflect.TypeOf(a))
		}
	}

	// Sort the individual groups.
	sort.Slice(boolArgs, func(i, j int) bool { return boolArgs[i].(bool) == false })
	sort.Slice(floatArgs, func(i, j int) bool { return floatArgs[i].(float64) < floatArgs[j].(float64) })
	sort.Slice(stringArgs, func(i, j int) bool { return stringArgs[i].(string) < stringArgs[j].(string) })

	// Reassemble the groups in proper order.
	sortedArgs := make([]interface{}, 0, len(args))
	sortedArgs = append(sortedArgs, nilArgs...)
	sortedArgs = append(sortedArgs, boolArgs...)
	sortedArgs = append(sortedArgs, floatArgs...)
	sortedArgs = append(sortedArgs, stringArgs...)

	return sortedArgs, nil
}

// Built-in "sort" function. Returns a sorted slice of the arguments with any
// repeated values removed. Should be registered as a GeneralFunction.
func uniqFunc(ctx EvaluationContext, arg interface{}) (interface{}, error) {
	// Convert args to a vector of scalars represented by a []interface{}
	arg1, err := decodeScalarNodesInArg(ctx.YamlRoot(), arg)
	if err != nil {
		return nil, err
	}
	var args []interface{}
	switch a := arg1.(type) {
	case nil:
		args = []interface{}{}
	case []interface{}:
		args = a
	default:
		args = []interface{}{arg1}
	}

	// Build a uniq'd slice of arguments.
	set := make(map[interface{}]bool)
	for _, a := range args {
		set[a] = true
	}

	uniqArgs := make([]interface{}, 0, len(set))
	for a, _ := range set {
		uniqArgs = append(uniqArgs, a)
	}

	// Return a sorted copy.
	return sortFunc(ctx, uniqArgs)
}

// Built-in "str" function. Returns the result of converting its argument
// to string. Should be registered as a ScalarFunction.
func strFunc(arg interface{}) (interface{}, error) {
	return fmt.Sprintf("%v", arg), nil
}

// Built-in "num" function. Returns the result of converting its arguments to
// a number if it is a string. Return its argument if it is a number. Returns
// an error if the argument is neither a string nor a number or if conversion
// fails. Should be registered as a ScalarFunction.
func numFunc(arg interface{}) (interface{}, error) {
	switch a := arg.(type) {
	case string:
		if f, err := strconv.ParseFloat(a, 64); err != nil {
			return 0., fmt.Errorf("cannot convert %q to number: %w", a, err.(*strconv.NumError).Err)
		} else {
			return f, nil
		}
	case float64:
		return a, nil
	default:
		return 0., fmt.Errorf("cannot convert %T to number", a)
	}
}

// Built-in "abs" function. Returns the absolute value of its result. Returns
// an error if the argument is non-numeric. Should be registered as a
// ScalarFunction.
func absFunc(arg interface{}) (interface{}, error) {
	if f, ok := arg.(float64); ok {
		return math.Abs(f), nil
	} else {
		return nil, fmt.Errorf("number required (found %T)", arg)
	}
}

// Built-in "int" function. Returns the result of rounding its argument to
// the nearest integer using half-away-from-zero rounding. Returns an error
// if the argument is non-numeric. Should be registered as a ScalarFunction.
func intFunc(arg interface{}) (interface{}, error) {
	if f, ok := arg.(float64); ok {
		return math.Round(f), nil
	} else {
		return nil, fmt.Errorf("number required (found %T)", arg)
	}
}

// Built-in "value" function. Just returns its argument. Relies on the
// automatic value conversion performed for ScalarFunction implementations
// to do its job of converting scalar Node values to internal scalars,
// Should be registered as a ScalarFunction.
func valueFunc(arg interface{}) (interface{}, error) {
	return arg, nil
}

// Built-in "split" function. Returns the vector of strings that results from
// splitting the second argument on occurrences of the first. Should be
// registered as a GeneralFunction.
func splitFunc(ctx EvaluationContext, arg interface{}) (interface{}, error) {
	var args []interface{}
	switch a := arg.(type) {
	case []interface{}:
		args = append(args, a...)
	default:
		args = append(args, a)
	}

	if len(args) < 2 || len(args) > 3 {
		return nil, fmt.Errorf("requires two or three arguments (found %d)", len(args))
	}

	scalarArgs := make([]interface{}, len(args))

	for i, a := range args {
		var scalar interface{}
		switch v := a.(type) {
		case *regexp.Regexp:
			if i > 0 {
				return nil, fmt.Errorf("second argument must be convertible to string (found regular expression)")
			}
			scalarArgs[0] = v
			continue
		case Node:
			if v.Kind() != ScalarKind {
				return nil, PathErrorf(PathFrom(ctx.YamlRoot(), v), "node not convertible to scalar: %s", v.Kind())
			} else {
				scalar = v.Value()
			}
		default:
			scalar = v
		}
		scalarArgs[i] = fmt.Sprintf("%v", scalar)
	}

	maxSplit := -1
	if len(scalarArgs) == 3 {
		if n, err := strconv.Atoi(scalarArgs[2].(string)); err != nil {
			return nil, fmt.Errorf("third argument not convertible to integer: %q", scalarArgs[2])
		} else {
			maxSplit = n
		}
	}

	var substrings []string
	switch splitter := scalarArgs[0].(type) {
	case *regexp.Regexp:
		substrings = splitter.Split(scalarArgs[1].(string), maxSplit)
	default:
		substrings = strings.SplitN(scalarArgs[1].(string), splitter.(string), maxSplit)
	}

	results := make([]interface{}, len(substrings))
	for i, s := range substrings {
		results[i] = s
	}
	return results, nil
}

// Built-in "join" function. Returns the string resulting from concatenating
// the string forms of all arguments after the first with the string form of
// the first argument as a separator. Should be registered as a GeneralFunction.
func joinFunc(ctx EvaluationContext, arg interface{}) (interface{}, error) {
	var args []interface{}
	switch a := arg.(type) {
	case []interface{}:
		args = append(args, a...)
	default:
		args = append(args, a)
	}

	if len(args) == 0 || args[0] == nil {
		return nil, fmt.Errorf("at least one argument is required")
	}

	strArgs := make([]string, len(args))
	for i, a := range args {
		var scalar interface{}
		switch v := a.(type) {
		case Node:
			if v.Kind() != ScalarKind {
				return nil, PathErrorf(PathFrom(ctx.YamlRoot(), v), "node not convertible to scalar: %s", v.Kind())
			} else {
				scalar = v.Value()
			}
		default:
			scalar = v
		}
		strArgs[i] = fmt.Sprintf("%v", scalar)
	}

	return strings.Join(strArgs[1:], strArgs[0]), nil
}

// Built-in "key" function. Returns the key under which each Node argument is
// mapped in its parent or null for nodes whose parents aren't mappings.
// Returns an error if any of the arguments are not of type Node. Should be
// registered as a GeneralFunction.
func keyFunc(ctx EvaluationContext, arg interface{}) (interface{}, error) {
	key := func(node Node) (interface{}, error) {
		path := PathFrom(ctx.YamlRoot(), node)
		if len(path) == 0 {
			return nil, PathErrorf(path, "node not found under root")
		}
		if len(path) < 2 {
			return nil, nil
		}
		parent := path[len(path)-2]
		if parent.Kind() != MappingKind {
			return nil, nil
		}
		for k, n := range parent.Value().(map[string]Node) {
			if n == node {
				return k, nil
			}
		}
		return nil, fmt.Errorf("found node that is not a child of its parent!")
	}

	switch a := arg.(type) {
	case Node:
		return key(a)
	case []interface{}:
		result := make([]interface{}, len(a))
		for i, v := range a {
			switch vv := v.(type) {
			case Node:
				if k, err := key(vv); err != nil {
					return nil, err
				} else {
					result[i] = k
				}
			default:
				return nil, fmt.Errorf("all arguments must be YAML nodes (found %T)", vv)
			}
		}
		return result, nil
	default:
		return nil, fmt.Errorf("all arguments must be YAML nodes (found %T)", a)
	}
}

// Built-in "source" function. Returns a source string of the form
// <filename>:<line>:<column> for each Node argument. Returns an error
// if any of the arguments are not of type Node. Should be registered
// as a GeneralFunction.
func sourceFunc(ctx EvaluationContext, arg interface{}) (interface{}, error) {
	sourceText := func(n Node) string {
		s := n.Source()
		return fmt.Sprintf("%s:%d:%d", s.File, s.Line, s.Column)
	}

	switch a := arg.(type) {
	case nil:
		return []interface{}{}, nil
	case Node:
		return sourceText(a), nil
	case []interface{}:
		result := make([]interface{}, len(a))
		for i, v := range a {
			switch vv := v.(type) {
			case Node:
				result[i] = sourceText(vv)
			default:
				return nil, fmt.Errorf("all arguments must be YAML nodes (found %T)", vv)
			}
		}
		return result, nil
	default:
		return nil, fmt.Errorf("all arguments must be YAML nodes (found %T)", a)
	}
}
