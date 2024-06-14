package pp

import (
	"fmt"
	"strings"

	"zpr.org/vsx/zpl/fs"
	"zpr.org/vsx/zpl/pp/yamltree"
	yt "zpr.org/vsx/zpl/pp/yamltree"
)

func GetProperty(tag string, y map[string]interface{}) (interface{}, error) {
	for k, v := range y {
		if k == tag {
			return v, nil
		}
	}
	return nil, fmt.Errorf("property not found: %v", tag)
}

func HasProperty(tag string, y map[string]interface{}) bool {
	for k := range y {
		if k == tag {
			return true
		}
	}
	return false
}

func GetListProperty(tag string, y map[string]interface{}) ([]interface{}, error) {
	pval, err := GetProperty(tag, y)
	if err != nil {
		return nil, err
	}
	if pval == nil {
		return nil, nil
	}
	if arrval, ok := pval.([]interface{}); ok {
		return arrval, nil
	}
	return nil, fmt.Errorf("not a list: %v", tag)
}

func GetStrListProperty(tag string, y map[string]interface{}) ([]string, error) {
	pval, err := GetProperty(tag, y)
	if err != nil {
		return nil, err
	}
	if pval == nil {
		return nil, nil
	}
	if arrval, ok := pval.([]string); ok {
		return arrval, nil
	}
	return nil, fmt.Errorf("not a list of strings: %v", tag)
}

func GetObjectProperty(tag string, y map[string]interface{}) (map[string]interface{}, error) {
	pval, err := GetProperty(tag, y)
	if err != nil {
		return nil, err
	}
	if pval == nil {
		return nil, nil
	}
	if oval, ok := pval.(map[string]interface{}); ok {
		return oval, nil
	}
	return nil, fmt.Errorf("not an object: %v (%#v)", tag, pval)
}

// AsKeydObject attempts to cast `o` into an object with one string key.
func AsKeydObject(o interface{}) (name string, val interface{}, ok bool) {
	ok = false
	oo, valid := o.(map[string]interface{})
	if !valid {
		return
	}
	if len(oo) != 1 {
		return
	}
	for k, v := range oo {
		name = k
		val = v
		ok = true
		return
	}
	return
}

// Loads and parses a YAML file, returns root of resulting tree.
func LoadYamlTree(file string, store fs.FileStore) (yamltree.Node, error) {
	absfile, err := store.Abs(file)
	if err != nil {
		return nil, err
	}
	data, derr := store.ReadFile(absfile)
	if derr != nil {
		return nil, fmt.Errorf("failed to load YAML: %w", derr)
	}

	root, rerr := yamltree.ReadYamlFromString(string(data), absfile)
	if rerr != nil {
		return nil, fmt.Errorf("failed to parse YAML from %q: %w", absfile, rerr)
	}

	return root, nil
}

// Returns the single node path that matches path expression expr in the tree
// rooted by root. Returns an error if the number of matching paths is not
// exactly one.
func singleMatchingPath(root yt.Node, expr string) ([]yt.Node, error) {
	pattern, err := yt.NewPathPattern(expr)
	if err != nil {
		return nil, err
	}

	paths := yt.MatchingPaths(root, pattern)
	if len(paths) == 0 {
		return nil, fmt.Errorf("not found")
	} else if len(paths) > 1 {
		return nil, fmt.Errorf("multiple matches (%d)", len(paths))
	}

	return paths[0], nil
}

// Returns the last element of a node path. Panics if the node path is empty.
func lastNode(path []yt.Node) yt.Node {
	if len(path) == 0 {
		panic("attempted to get the last node of an empty path!")
	}
	return path[len(path)-1]
}

// lastNodeKey returns the key under which the last element of a node path is mapped by its
// parent. Panics if the node path has length less than two, if its last node's
// predecessor is not a mapping node, or if its last node is not a child of its
// predecessor.
func lastNodeKey(path []yt.Node) string {
	k, err := tryLastNodeKey(path)
	if err != nil {
		panic(err)
	}
	return k
}

// tryLastNodeKey is just like lastNodeKey but returns an error on failure instead of
// panicking.
func tryLastNodeKey(path []yt.Node) (string, error) {
	last := lastNode(path)
	if len(path) < 2 {
		return "", yt.PathErrorf(path, "path too short to determine final node's key!")
	}
	pred := path[len(path)-2]
	if err := validateNodeKind(pred, yt.MappingKind); err != nil {
		return "", yt.PathErrorf(path, "cannot determine final node's key: %w", err)
	}
	for key, child := range pred.Value().(map[string]yt.Node) {
		if child == last {
			return key, nil
		}
	}
	return "", yt.PathErrorf(path, "final node is not a child of its predecessor!")
}

// Returns an error if a node is not of a specified kind.
func validateNodeKind(node yt.Node, kind yt.NodeKind) error {
	if node.Kind() != kind {
		return fmt.Errorf("%s required (found %s)", kind.String(), node.Kind().String())
	}
	return nil
}

// validateLastNodeKind Returns a PathError if the last node of a path is not of a specified kind.
func validateLastNodeKind(path []yt.Node, kind yt.NodeKind) error {
	lastNode := lastNode(path)
	if lastNode.Kind() != kind {
		return yt.PathErrorf(path, "%s found where %s required", lastNode.Kind().String(), kind.String())
	}
	return nil
}

func isLastNodeEmpty(path []yt.Node) bool {
	lastNode := lastNode(path)
	return lastNode.Tag() == "!!null" || lastNode.Value() == ""
}

func validateLastNodeKindForTag(path []yt.Node, kind yt.NodeKind, tag string) error {
	lastNode := lastNode(path)
	if lastNode.Kind() != kind {
		return yt.PathErrorf(path, "failed to parse %v: %s found where %s required", tag, lastNode.Kind().String(), kind.String())
	}
	return nil
}

// Returns a string suitable for matching any of a set of keys in a node path
// expression. The string is of the form '^(k0|k1|k2...)$' (including the single
// quotes), where k0, k1, ... are versions of the arguments with any regular
// expression or path expression metacharacter suitable escaped.
func pathExpressionKeyDisjunction(keys ...string) string {
	var buf strings.Builder
	buf.WriteString("'^(")
	for i, k := range keys {
		if i > 0 {
			buf.WriteString("|")
		}
		buf.WriteString(yt.QuoteKeyRegexMeta(k))
	}
	buf.WriteString(")$'")
	return buf.String()
}
