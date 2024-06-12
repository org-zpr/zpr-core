// Package yamltree provides support for representing a YAML document as a
// tree structure in which nodes record the locations of their definitions
// in the YAML source. It also provides a mechanism for locating nodes in
// a tree using path expressions and a facility for evaluating more general
// expressions in which path expressions can appear as variables.
//
//
// While YAML's aliasing mechanism enables the representation of general
// directed graphs, not merely trees, this package's ReadYaml function
// replicates aliased nodes as needed to produce a tree. (It fails if any
// cycles are present.) The tree structure allows any node to be identified
// with a unique path from the root.
//
// This package uses gopkg.in/yaml.v3 (https://pkg.go.dev/gopkg.in/yaml.v3)
// for YAML parsing but conceals that detail in its external API. For
// compatibility with code that uses yaml.v3 directly, it provides a way to
// convert a tree into a map[string]interface{} of the same form as the one
// yaml.v3's Unmarshal() function can produce. See NativeTree.
package yamltree

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Node is an interface implemented by nodes in a YAML document tree. There
// are three kinds of Node instance: scalars for leaf nodes, sequences for
// ordered branching nodes, and mappings for unordered (keyed) branching nodes.
// All scalar nodes have string values, as do all mapping keys.
type Node interface {
	// Kind tells what kind of node this is.
	Kind() NodeKind

	// Tag returns the YAML tag associated with this node. For example, it
	// returns "!!int" if this node is a node that the YAML parser identified
	/// as having an integer value.
	Tag() string

	// Value returns the value of this node using a kind-dependent type. It
	// returns a string for a scalar node, a []Node for a sequence node, or
	// a map[string]Node for a mapping node.
	Value() interface{}

	// DecodedValue returns the result of decoding this node's scalar value, if
	// if has one, to a type consistent with its YAML tag. For a scalar node it
	// returns an interface value containing a concrete nil, bool, int64,
	// float64, or string value as the YAML tag is "!!null", "!!bool", "!!int",
	// "!!float", or "!!str", respectively. For a non-scalar node it returns nil
	// and an error. It also returns nil and an error if a value conversion
	// fails, e.g., due to a type range error. Any returned error has a concrete
	// type of *NodeError.
	DecodedScalarValue() (interface{}, error)

	// Source tells where this node was defined.
	Source() NodeSource

	// Referrers returns a slice of locations of nodes that refer in some manner
	// to this node. The degree of indirection increases with distance from the
	// start of the slice.
	Referrers() []NodeSource

	// String returns a very brief description of this node.
	String() string
}

// NodeKind enumerates node kinds. Legal values are ScalarKind, SequenceKind,
// and MappingKind.
type NodeKind int

const (
	UndefinedKind NodeKind = iota // not used
	ScalarKind                    // scalar node
	SequenceKind                  // sequence node
	MappingKind                   // mapping node
)

// Returns a string value corresponding to a NodeKind value.
func (k NodeKind) String() string {
	switch k {
	case UndefinedKind:
		return "<undefined-kind>"
	case ScalarKind:
		return "scalar"
	case SequenceKind:
		return "sequence"
	case MappingKind:
		return "mapping"
	default:
		return fmt.Sprintf("<invalid-NodeKind(%d)>", k)
	}
}

// NodeSource describes where in a YAML document a Node was defined.
type NodeSource struct {
	// File is nominally the name of the source file the Node's definition was
	// read from. May be "" or any other string if the definition was not read
	// from a file.
	File string

	// Line is the line number of the start of the node's definition in the
	// source. One-based.
	Line int

	// Columns is the column number of the start of the node's definition in
	// the source. One-based.
	Column int
}

// Internal Node implementation.
type nodeImpl struct {
	kind      NodeKind      // scalar, sequence, or mapping
	value     interface{}   // string, []Node, or map[string]Node
	tag       string        // type tag (e.g., "!!str")
	source    *NodeSource   // location of node definition in YAML source
	referrers []*NodeSource // locations of referring nodes (e.g., alias nodes); nil if none
}

func (n *nodeImpl) Kind() NodeKind {
	return n.kind
}

func (n *nodeImpl) Tag() string {
	return n.tag
}

func (n *nodeImpl) Value() interface{} {
	return n.value
}

func (n *nodeImpl) DecodedScalarValue() (interface{}, error) {
	return decodeScalarNodeValue(n)
}

func (n *nodeImpl) Source() NodeSource {
	return *n.source
}

func (n *nodeImpl) Referrers() []NodeSource {
	refs := make([]NodeSource, len(n.referrers))
	for i, r := range n.referrers {
		refs[i] = *r
	}
	return refs
}

func (n *nodeImpl) String() string {
	var valueText string
	switch n.Kind() {
	case ScalarKind:
		valueText = n.Value().(string)
	case SequenceKind:
		valueText = fmt.Sprintf("%d", len(n.Value().([]Node)))
	case MappingKind:
		valueText = fmt.Sprintf("%d", len(n.Value().(map[string]Node)))
	}
	return fmt.Sprintf("Node(%p %s %s)", n, n.Tag(), valueText)
}

// NodeError describes an error associated with a tree node.
type NodeError struct {
	// Node is the associated tree node.
	Node Node

	message string
	wrapped error
}

func (e *NodeError) Error() string {
	return e.message
}

func (e *NodeError) Unwrap() error {
	return e.wrapped
}

// NodeErrorf constructs an error value containing a *NodeError. The first
// argument is the associated Node. Subsequent arguments are as for fmt.Errorf.
func NodeErrorf(node Node, format string, args ...interface{}) error {
	source := node.Source()
	file := source.File
	if file == "" {
		file = "?"
	}
	prefix := fmt.Sprintf("[%v:%d:%d] ", file, source.Line, source.Column)
	args1 := append([]interface{}{prefix}, args...)
	err := fmt.Errorf("%s"+format, args1...)
	return &NodeError{node, err.Error(), errors.Unwrap(err)}
}

// Constructs a *NodeError error value associated with a raw node.
func rawNodeErrorf(rawNode *yaml.Node, file string, format string, args ...interface{}) error {
	dummy := Node(&nodeImpl{UndefinedKind, "<undefined-value>", "", &NodeSource{file, rawNode.Line, rawNode.Column}, nil})
	return NodeErrorf(dummy, format, args...)
}

// Returns a representation of a filename suitable for error messages.
func filenameForError(file string) string {
	if file != "" {
		return file
	} else {
		return "<unknown-filename>"
	}
}

// ReadYaml reads a YAML document and parses it into a tree of Node instances.
// It returns the tree's root node.
//
// The io.Reader argument must provide the text of a valid YAML document. If
// the file argument is not an empty string, it is used as a file name in any
// error messages.
//
// There are three kinds of Node instance in the returned tree: scalars for
// leaf nodes, sequences for ordered branching nodes, and mappings for
// unordered (keyed) branching nodes. All scalar nodes have string values. (No
// attempt is made to decode numbers, timestamps, etc.) Anchors and aliases are
// supported by replicating referenced subtrees. Thus the result is always a
// tree, even if the input YAML structure is not. Cycles in the input YAML are
// disallowed and reported as errors.
//
// The Source values of the Node objects in the returned tree tell where the
// corresponding nodes values were defined in the YAML source. Key locations
// are not recorded. Where aliases occur in the source, recorded locations are
// for the referenced nodes.
//
// Compound mapping keys are unsupported; all keys must be string-valued. Merge
// keys (!!merge, <<:) are also unsupported.
func ReadYaml(reader io.Reader, file string) (Node, error) {
	decoder := yaml.NewDecoder(reader)
	rawNode := yaml.Node{}
	err := decoder.Decode(&rawNode)
	if err != nil {
		return nil, fmt.Errorf("failed to parse YAML from %v: %w", filenameForError(file), err)
	} else if rawNode.Kind != yaml.DocumentNode {
		return nil, fmt.Errorf("expected DocumentNode (got %v) from %v", rawNode.Kind, filenameForError(file))
	} else {
		root, err := treeForRawNode(rawNode.Content[0], file, map[*yaml.Node]bool{})
		if err != nil {
			return nil, err
		} else {
			return root, nil
		}
	}
}

// Helper function for ReadYaml(). The map argument is updated as raw nodes
// are visited and is used to detect aliasing cycles.
func treeForRawNode(rawRoot *yaml.Node, file string, visited map[*yaml.Node]bool) (Node, error) {
	visited[rawRoot] = true
	defer delete(visited, rawRoot)
	source := &NodeSource{file, rawRoot.Line, rawRoot.Column}
	var root, child Node
	var err error
	switch rawRoot.Kind {
	case yaml.ScalarNode:
		root = &nodeImpl{ScalarKind, rawRoot.Value, rawRoot.Tag, source, nil}
	case yaml.SequenceNode:
		children := []Node{}
		for _, elemNode := range rawRoot.Content {
			child, err = treeForRawNode(elemNode, file, visited)
			if err != nil {
				break
			}
			children = append(children, child)
		}
		root = &nodeImpl{SequenceKind, children, rawRoot.Tag, source, nil}
	case yaml.MappingNode:
		children := map[string]Node{}
		for i := 0; i < len(rawRoot.Content); i += 2 {
			rawKeyNode := rawRoot.Content[i]
			rawValNode := rawRoot.Content[i+1]
			if rawKeyNode.Kind != yaml.ScalarNode {
				return nil, rawNodeErrorf(rawKeyNode, file, "non-scalar keys not supported: %#v (tag %v)", rawKeyNode.Value, rawKeyNode.Tag)
			}
			if rawKeyNode.Tag == "!!merge" {
				return nil, rawNodeErrorf(rawKeyNode, file, "merge keys not supported: %#v", rawKeyNode.Value)
			}
			child, err = treeForRawNode(rawValNode, file, visited)
			if err != nil {
				break
			}
			children[rawKeyNode.Value] = child
		}
		root = &nodeImpl{MappingKind, children, rawRoot.Tag, source, nil}
	case yaml.AliasNode:
		var target Node
		rawAnchorNode := rawRoot.Alias
		if rawAnchorNode == nil {
			return nil, rawNodeErrorf(rawRoot, file, "anchor %#v undefined", rawRoot.Anchor)
		}
		_, circular := visited[rawAnchorNode]
		if circular {
			return nil, rawNodeErrorf(rawRoot, file, "circular reference: *%v", rawRoot.Value)
		}
		target, err = treeForRawNode(rawAnchorNode, file, visited)
		if err != nil {
			return nil, err
		}
		referrers := []*NodeSource{&NodeSource{file, rawRoot.Line, rawRoot.Column}}
		targetImpl := target.(*nodeImpl)
		root = &nodeImpl{targetImpl.kind, targetImpl.value, targetImpl.tag, targetImpl.source, referrers}
	default:
		return nil, rawNodeErrorf(rawRoot, file, "found invalid YAML node kind: %v", rawRoot.Kind)
	}
	if err != nil {
		return nil, err
	}
	return root, nil
}

// ReadYamlFromString reads a YAML document from a string and parses it into
// a tree of Node instances. It is a thin wrapper around ReadYaml.
func ReadYamlFromString(document string, file string) (Node, error) {
	reader := bytes.NewReader([]byte(document))
	return ReadYaml(reader, file)
}

// WriteYaml writes a YAML document for a Node tree of the type generated by
// ReadYaml. The second argument is taken as the root of the tree. The YAML
// document written through the first argument is equivalent to the one that
// was originally read and parsed by ReadYaml (but not generally identical due
// to indentation and other formatting issues). A non-nil error is returned if
// the Node tree is invalid or an I/O error occurs.
func WriteYaml(writer io.Writer, root Node) error {
	encoder := yaml.NewEncoder(writer)
	nativeRoot := NativeTree(root)
	err := encoder.Encode(nativeRoot)
	if err != nil {
		return fmt.Errorf("failed to write YAML: %w", err)
	} else {
		return nil
	}
}

// WriteTamlToString returns a string containing a YAML document for a Node
// tree of the type generated by ReadYaml. It is a thin wrapper around
// WriteYaml. It panics instead of returning an error if the argument is a
// foreign Node implementation.
func WriteYamlToString(root Node) string {
	buf := bytes.NewBuffer([]byte{})
	err := WriteYaml(buf, root)
	if err != nil {
		panic(err)
	}
	return buf.String()
}

// WriteYamlSourceOrder does the same thing as WriteYaml except that it attempts
// to preserve the original source ordering of all mapping keys. Note that this
// function depends on undocumented behavior of the underlying YAML parsing
// library, so no guarantees can be given. A non-nil error is returned if the
// Node tree is invalid or an I/O error occurs.
func WriteYamlSourceOrder(writer io.Writer, root Node) error {
	// OK, this is an ugly hack. It _appears_ that the YAML parsing library
	// (yaml.v3) always output mapping keys in lexicographic order and always
	// formats mappings in block style with each key the first thing on its
	// line, possibly excepting "-" sequence element markers (none of this is
	// documented). All this is OK, but we'd prefer that mapping keys appear
	// in their original YAML source order. The YAML parsing library preserves
	// source location information in its node structure, so maybe a future
	// version will sort keys in source order, but for now we resort to the
	// following unseemliness. First we build a copy of the input Node tree
	// in which all keys have sequence numbers prepended to them so as to force
	// lexicographic sorting to be the same as source ordering. Next we let the
	// library do its thing, which now puts the keys in source order. Finally
	// we strip out the sequence numbers. Hopefully this can all go away some
	// day.
	if labeledRoot, err := labelKeysSequentially(root); err != nil {
		return err
	} else {
		buf := bytes.NewBuffer([]byte{})
		if err := WriteYaml(buf, labeledRoot); err != nil {
			return err
		}
		labeledYaml := buf.Bytes()
		// RE to match key lines in labeled YAML. Keys are assumed to be double-
		// quoted and start with "\e" (which is how the YAML library formats an
		// escape character) and a six-digit integer. Capturing groups match the
		// text before the key, the key (minus the label prefix), and the text
		// after the key. Watch for escaped quotes inside the quoted key in case
		// some reprobate decides to get cute.
		labelRe := regexp.MustCompile(`(?m)^(?P<before>[\s-]*)"(\\e\d{6})(?P<key>(?:[^\\"]*(?:(?:\\\\)*\\")?)*)":(?P<after>(?: .*)?\n)`)
		var delabeledYaml []byte
		prevLineEnd := 0
		for _, submatches := range labelRe.FindAllSubmatchIndex(labeledYaml, -1) {
			lineStart := submatches[0]
			lineEnd := submatches[1]
			if lineStart > prevLineEnd {
				delabeledYaml = append(delabeledYaml, labeledYaml[prevLineEnd:lineStart]...)
			}
			prevLineEnd = lineEnd
			key := labelRe.Expand([]byte{}, []byte("$key"), labeledYaml, submatches)
			if bytes.Contains(key, []byte{'\\'}) {
				// Key has escapes, so need to restore the outer quotes.
				key = append([]byte{'"'}, append(key, '"')...)
			}
			delabeledYaml = labelRe.Expand(delabeledYaml, []byte("$before"), labeledYaml, submatches)
			delabeledYaml = append(delabeledYaml, key...)
			delabeledYaml = labelRe.Expand(delabeledYaml, []byte(":$after"), labeledYaml, submatches)
		}
		if len(labeledYaml) > prevLineEnd {
			delabeledYaml = append(delabeledYaml, labeledYaml[prevLineEnd:len(labeledYaml)]...)
		}
		if _, err := writer.Write(delabeledYaml); err != nil {
			return err
		}
		return nil
	}
}

// Prepends an escape character and six digits to every mapping key in the
// argument tree and returns the resulting tree. See WriteYamlSourceOrder.
// Hopefully this can go away some day.
func labelKeysSequentially(root Node) (Node, error) {
	var err error
	switch root.Kind() {
	case MappingKind:
		oldChildren := root.Value().(map[string]Node)
		newChildren := make(map[string]Node, len(oldChildren))
		for i, oldKey := range MappingKeysInSourceOrder(root) {
			// Prepend sequence number label. Include a control character so
			// that the key will have to be double-quoted in the YAML output.
			// Knowing that it's quoted and how it's quoted will help us find
			// the key later using a regex.
			newKey := fmt.Sprintf("\033%06d%s", i, oldKey)
			if newChildren[newKey], err = labelKeysSequentially(oldChildren[oldKey]); err != nil {
				return nil, err
			}
		}
		return ReplaceNodeValue(root, newChildren)
	case SequenceKind:
		oldChildren := root.Value().([]Node)
		newChildren := make([]Node, len(oldChildren))
		for i, oldChild := range oldChildren {
			if newChildren[i], err = labelKeysSequentially(oldChild); err != nil {
				return nil, err
			}
		}
		return ReplaceNodeValue(root, newChildren)
	default:
		return root, nil
	}
}

// WriteYamlToStringSourceOrder does the same thing as WriteYamlToString
// except that it attempts to preserve the original source ordering of all
// mapping keys. Note that this function depends on undocumented behavior of the
// underlying YAML parsing library, so no guarantees can be given. It is a thin
// wrapper around WriteYamlSourceOrder. It panics instead of returning an
// error if the argument is a foreign Node implementation.
func WriteYamlToStringSourceOrder(root Node) string {
	buf := bytes.NewBuffer([]byte{})
	err := WriteYamlSourceOrder(buf, root)
	if err != nil {
		panic(err)
	}
	return buf.String()
}

// MappingKeysInSourceOrder returns the keys of the argument Node, which must
// describe a mapping node, in the order in which they were defined in the YAML
// source. Specifically, the returned key list is sorted lexicographically
// according to the triples (file name, line number, column number) associated
// with the keys' values. This function panics if the argument is not a mapping
// Node.
func MappingKeysInSourceOrder(node Node) []string {
	childMap := node.Value().(map[string]Node)
	keys := make([]string, 0, len(childMap))
	for k, _ := range childMap {
		keys = append(keys, k)
	}
	source := func(i int) NodeSource {
		node := childMap[keys[i]]
		src := node.Source()
		refs := node.Referrers()
		if len(refs) > 0 {
			src = refs[len(refs)-1]
		}
		return src
	}
	less := func(i1, i2 int) bool {
		s1 := source(i1)
		s2 := source(i2)
		diff := strings.Compare(s1.File, s2.File)
		if diff != 0 {
			return diff < 0
		}
		diff = s1.Line - s2.Line
		if diff != 0 {
			return diff < 0
		}
		return s1.Column-s2.Column < 0
	}
	sort.Slice(keys, less)
	return keys
}

// Returns a new Node that is the result of replacing the value of the
// argument Node by a new value. The returned Node has the same source
// and referrers as node, but its kind may change depending on the type
// of newValue.
//
// If newValue is nil, the new Node has a tag of "!!null". Otherwise the
// new Node's tag is determined from newValue's dynamic type, which must
// be bool, a built-in integer or floating-point type, string, []Node, or
// map[string]Node. The new Node's kind is also set accordingly.
//
// This function returns a non-nil error if newValue has an unsupported
// dynamic type or if node is of a foreign implementation.
func ReplaceNodeValue(node Node, newValue interface{}) (Node, error) {
	n, ok := node.(*nodeImpl)
	if !ok {
		return nil, NodeErrorf(node, "cannot replace node value: unsupported Node implementation: %T", node)
	}
	if newValue == nil {
		return &nodeImpl{ScalarKind, "", "!!null", n.source, n.referrers}, nil
	} else {
		switch v := newValue.(type) {
		case bool:
			return &nodeImpl{ScalarKind, strconv.FormatBool(v), "!!bool", n.source, n.referrers}, nil
		case int:
			return &nodeImpl{ScalarKind, strconv.FormatInt(int64(v), 10), "!!int", n.source, n.referrers}, nil
		case int8:
			return &nodeImpl{ScalarKind, strconv.FormatInt(int64(v), 10), "!!int", n.source, n.referrers}, nil
		case int16:
			return &nodeImpl{ScalarKind, strconv.FormatInt(int64(v), 10), "!!int", n.source, n.referrers}, nil
		case int32:
			return &nodeImpl{ScalarKind, strconv.FormatInt(int64(v), 10), "!!int", n.source, n.referrers}, nil
		case int64:
			return &nodeImpl{ScalarKind, strconv.FormatInt(int64(v), 10), "!!int", n.source, n.referrers}, nil
		case uint:
			return &nodeImpl{ScalarKind, strconv.FormatUint(uint64(v), 10), "!!int", n.source, n.referrers}, nil
		case uint8:
			return &nodeImpl{ScalarKind, strconv.FormatUint(uint64(v), 10), "!!int", n.source, n.referrers}, nil
		case uint16:
			return &nodeImpl{ScalarKind, strconv.FormatUint(uint64(v), 10), "!!int", n.source, n.referrers}, nil
		case uint32:
			return &nodeImpl{ScalarKind, strconv.FormatUint(uint64(v), 10), "!!int", n.source, n.referrers}, nil
		case uint64:
			return &nodeImpl{ScalarKind, strconv.FormatUint(uint64(v), 10), "!!int", n.source, n.referrers}, nil
		case float32:
			return &nodeImpl{ScalarKind, strconv.FormatFloat(float64(v), 'g', -1, 32), "!!float", n.source, n.referrers}, nil
		case float64:
			return &nodeImpl{ScalarKind, strconv.FormatFloat(float64(v), 'g', -1, 64), "!!float", n.source, n.referrers}, nil
		case string:
			return &nodeImpl{ScalarKind, v, "!!str", n.source, n.referrers}, nil
		case []Node:
			newChildren := make([]Node, len(v))
			for i, child := range v {
				newChildren[i] = deepCopy(child)
			}
			return &nodeImpl{SequenceKind, newChildren, "!!seq", n.source, n.referrers}, nil
		case map[string]Node:
			newChildren := make(map[string]Node, len(v))
			for key, child := range v {
				newChildren[key] = deepCopy(child)
			}
			return &nodeImpl{MappingKind, newChildren, "!!map", n.source, n.referrers}, nil
		default:
			return nil, NodeErrorf(node, "cannot replace node value: unsupported value type: %T", newValue)
		}
	}
}

// ReplaceNode returns the result of replacing one node with another in a tree
// of the type that ReadYaml generates. It takes the first argument to be the
// root of the original tree. On success it returns the root of a new tree in
// which orig has been replaced by a deep copy of repl. If ref is not nil, then
// the copy of repl has ref's source value prepended to its referrers list.
//
// This function returns nil and an error if (1) orig is not root or a
// descendant of root or (2) any of the arguments are of foreign Node
// implementations. Any error value returned contains a *NodeError.
//
// ReplaceNode does not mutate any of its arguments. The returned tree shares
// as much of the original tree's state as possible. The replacement node is
// deeply copied in order to guarantee that the result is tree-structured,
// even if the replacement node or any of its descendants are already in the
// tree under root.
func ReplaceNode(root Node, orig Node, repl Node, ref Node) (Node, error) {
	for _, n := range []Node{root, orig, repl, ref} {
		if n != nil {
			if _, ok := n.(*nodeImpl); !ok {
				return nil, NodeErrorf(n, "cannot replace node: unsupported Node implementation: %T", n)
			}
		}
	}

	if orig == repl {
		return root, nil
	}

	newRoot, replaced := replaceNode(root, orig, deepCopy(repl), ref)
	if !replaced {
		return nil, NodeErrorf(orig, "node to be replaced not found in tree")
	}
	return newRoot, nil
}

// Helper for ReplaceNode. Returns new root and a boolean value that is true
// iff repl is found (and replaced). Assumes all arguments are of nodeImpl
// type. On success, replaces orig with a copy of repl in which the referrers
// field has been modified by prepending ref's source field (unless ref is nil.)
func replaceNode(root Node, orig Node, repl Node, ref Node) (Node, bool) {
	if orig == root {
		replImplCopy := *repl.(*nodeImpl)
		if ref != nil {
			if len(replImplCopy.referrers) == 0 {
				replImplCopy.referrers = []*NodeSource{}
			}
			if s := ref.(*nodeImpl).source; s != nil {
				refSourceCopy := *s
				replImplCopy.referrers = append([]*NodeSource{&refSourceCopy}, replImplCopy.referrers...)
			}
		}
		return Node(&replImplCopy), true
	}

	switch root.Kind() {
	case SequenceKind:
		oldChildren := root.Value().([]Node)
		for i, c := range oldChildren {
			newChild, replaced := replaceNode(c, orig, repl, ref)
			if replaced {
				newChildren := append([]Node(nil), oldChildren...)
				newChildren[i] = newChild
				rootImplCopy := *root.(*nodeImpl)
				rootImplCopy.value = newChildren
				return Node(&rootImplCopy), true
			}
		}
	case MappingKind:
		oldChildren := root.Value().(map[string]Node)
		for k, c := range oldChildren {
			newChild, replaced := replaceNode(c, orig, repl, ref)
			if replaced {
				newChildren := make(map[string]Node, len(oldChildren))
				for kk, cc := range oldChildren {
					newChildren[kk] = cc
				}
				newChildren[k] = newChild
				rootImplCopy := *root.(*nodeImpl)
				rootImplCopy.value = newChildren
				return Node(&rootImplCopy), true
			}
		}
	}

	// Didn't find orig.
	return root, false
}

// RemoveNode returns the result of removing a node from a tree of the type
// that ReadYaml generates. It takes the first argument as the tree's root
// and returns the root of the tree that results from removing the target
// node and any descendants of the target node. It returns a nil root and
// an error if (1) the target node is not a descendant of root or (2) either
// argument is of a foreign Node implementation. It returns (nil, nil) if the
// two arguments are identical. Any error returned contains a *NodeError.
//
// RemoveNode does not mutate any of its arguments. The returned tree shares
// as much of the original tree's state as possible.
func RemoveNode(root Node, target Node) (Node, error) {
	for _, n := range []Node{root, target} {
		if _, ok := n.(*nodeImpl); !ok {
			return nil, NodeErrorf(n, "cannot remove node: unsupported Node implementation: %T", n)
		}
	}
	newRoot, removed := removeNode(root, target)
	if !removed {
		return nil, NodeErrorf(target, "node to be removed not found in tree")
	}
	return newRoot, nil
}

// Attempts to remove a node from a tree, returns new root and a bool that is
// true iff the node was removed. Returns nil as the new root if target == root.
func removeNode(root Node, target Node) (Node, bool) {
	if target == root {
		return nil, true
	}

	switch root.Kind() {
	case SequenceKind:
		oldChildren := root.Value().([]Node)
		for i, oldChild := range oldChildren {
			newChild, removed := removeNode(oldChild, target)
			if removed {
				newChildren := append([]Node(nil), oldChildren...)
				newChildren[i] = newChild
				if newChild == nil {
					newChildren = append(newChildren[:i], newChildren[i+1:]...)
					if len(newChildren) == 0 {
						return nil, true
					}
				}
				rootImplCopy := *root.(*nodeImpl)
				rootImplCopy.value = newChildren
				return Node(&rootImplCopy), removed
			}
		}
	case MappingKind:
		oldChildren := root.Value().(map[string]Node)
		for k, oldChild := range oldChildren {
			newChild, removed := removeNode(oldChild, target)
			if removed {
				newChildren := make(map[string]Node, len(oldChildren))
				for kk, c := range oldChildren {
					if c != oldChild {
						newChildren[kk] = c
					}
				}
				if newChild != nil {
					newChildren[k] = newChild
				}
				if len(newChildren) == 0 {
					return nil, true
				}
				rootImplCopy := *root.(*nodeImpl)
				rootImplCopy.value = newChildren
				return Node(&rootImplCopy), removed
			}
		}
	}

	// Didn't find target.
	return root, false
}

// AddNodesToMapping returns the result of adding children to a mapping node in
// a tree of the type that ReadYaml generates. It takes the first argument as
// the tree's root and returns the root of the tree that results from adding
// deep copies of all of the the nodes in children to parent under their
// associated mapping keys, replacing any children already mapped to those keys.
// It prepends the source field of referrer to the referrer lists of all of the
// new child copies if referrer is not nil. It returns nil and a non-nil error if
// (1) parent is not a descendant of root, (2) parent is not a mapping node, or
// (3) root, parent, any of the values in children, or referrer are of foreign
// Node implementations. Any error value returned contains a *NodeError.
//
// AddNodeToMapping does not mutate any of its arguments. The returned tree
// shares as much of the original tree's state as possible.
func AddNodesToMapping(root Node, parent Node, children map[string]Node, referrer Node) (Node, error) {
	if len(children) == 0 {
		return root, nil
	}

	for _, node := range []Node{root, parent, referrer} {
		if node != nil {
			if _, ok := node.(*nodeImpl); !ok {
				return nil, NodeErrorf(node, "cannot add mapping children: unsupported Node implementation: %T", node)
			}
		}
	}

	if parent.Kind() != MappingKind {
		return nil, NodeErrorf(parent, "intended parent not a mapping node")
	}

	for _, child := range children {
		if _, ok := child.(*nodeImpl); !ok {
			return nil, NodeErrorf(child, "cannot add mapping child: unsupported Node implementation: %T", child)
		}
	}

	childrenCopies := make(map[string]Node, len(children))
	for key, child := range children {
		childCopy := deepCopy(child)
		childCopyImpl := childCopy.(*nodeImpl)
		if referrer != nil {
			if len(childCopyImpl.referrers) == 0 {
				childCopyImpl.referrers = []*NodeSource{}
			}
			if s := referrer.(*nodeImpl).source; s != nil {
				refSourceCopy := *s
				childCopyImpl.referrers = append([]*NodeSource{&refSourceCopy}, childCopyImpl.referrers...)
			}
		}
		childrenCopies[key] = childCopy
	}

	newRoot, added := addNodesToMapping(root, parent, childrenCopies)
	if !added {
		return nil, NodeErrorf(parent, "intended parent node not found in tree")
	}

	return newRoot, nil
}

// Attempts to add new children to a mapping parent in a tree, returns new root
// and a bool equal to true iff the children were added. Assumes parent is a
// mapping node.
func addNodesToMapping(root Node, parent Node, children map[string]Node) (Node, bool) {
	if root == parent {
		rootImplCopy := *root.(*nodeImpl)
		oldChildren := rootImplCopy.value.(map[string]Node)
		newChildren := make(map[string]Node, len(oldChildren)+len(children))
		for k, c := range oldChildren {
			newChildren[k] = c
		}
		for k, c := range children {
			newChildren[k] = c
		}
		rootImplCopy.value = newChildren
		return Node(&rootImplCopy), true
	}

	switch root.Kind() {
	case ScalarKind:
		return nil, false
	case SequenceKind:
		oldChildren := root.Value().([]Node)
		for i, c := range oldChildren {
			n, added := addNodesToMapping(c, parent, children)
			if added {
				newChildren := append([]Node(nil), oldChildren...)
				newChildren[i] = n
				rootImplCopy := *root.(*nodeImpl)
				rootImplCopy.value = newChildren
				return Node(&rootImplCopy), true
			}
		}
	case MappingKind:
		oldChildren := root.Value().(map[string]Node)
		for k, c := range oldChildren {
			n, added := addNodesToMapping(c, parent, children)
			if added {
				newChildren := make(map[string]Node, len(oldChildren)+1)
				for kk, cc := range oldChildren {
					newChildren[kk] = cc
				}
				newChildren[k] = n
				rootImplCopy := *root.(*nodeImpl)
				rootImplCopy.value = newChildren
				return Node(&rootImplCopy), true
			}
		}
	}

	// Didn't find parent.
	return root, false
}

// AddNodeToSequence returns the result of adding children to a sequence node
// in a tree of the type that ReadYaml generates. It takes the first argument
// as the tree's root and returns the root of the tree that results from adding
// deep copies of all of the nodes in children to parent, in order, starting at
// the given index. The index must be between zero and the current length of
// the parent sequence, inclusive, and existing children are shifted as needed
// in order to accommodate the new children. It prepends the source field of
// referrer to the referrer lists of all of the new child copies if referrer is
// not nil. It returns nil and a non-nil error if child copies' referrer fields
// are set to referrer's source field. This function returns nil and an error
// if (1) parent is not a descendant of root, (2) parent is not a sequence node,
// (3) index is out of range, or (4) any of the Node inputs are of foreign Node
// implementations. Any error value returned contains a *NodeError.
//
// AddNodeToSequence does not mutate any of its arguments. The returned tree
// shares as much of the original tree's state as possible.
func AddNodesToSequence(root Node, parent Node, children []Node, index int, referrer Node) (Node, error) {
	if len(children) == 0 {
		return root, nil
	}

	for _, node := range []Node{root, parent, referrer} {
		if node != nil {
			if _, ok := node.(*nodeImpl); !ok {
				return nil, NodeErrorf(node, "cannot add sequence child: unsupported Node implementation: %T", node)
			}
		}
	}
	for _, child := range children {
		if _, ok := child.(*nodeImpl); !ok {
			return nil, NodeErrorf(child, "cannot add sequence child: unsupported Node implementation: %T", child)
		}
	}

	if parent.Kind() != SequenceKind {
		return nil, NodeErrorf(parent, "intended parent not a sequence node")
	}

	if index < 0 || index > len(parent.Value().([]Node)) {
		return nil, NodeErrorf(parent, "intended new child index %d out of range [0, %d]", index, len(parent.Value().([]Node)))
	}

	childrenCopies := make([]Node, len(children))
	for key, child := range children {
		childCopy := deepCopy(child)
		childCopyImpl := childCopy.(*nodeImpl)
		if referrer != nil {
			if len(childCopyImpl.referrers) == 0 {
				childCopyImpl.referrers = []*NodeSource{}
			}
			if s := referrer.(*nodeImpl).source; s != nil {
				refSourceCopy := *s
				childCopyImpl.referrers = append([]*NodeSource{&refSourceCopy}, childCopyImpl.referrers...)
			}
		}
		childrenCopies[key] = childCopy
	}

	newRoot, added := addNodesToSequence(root, parent, childrenCopies, index)
	if !added {
		return nil, NodeErrorf(parent, "intended parent node not found in tree")
	}

	return newRoot, nil
}

// Attempts to add children to a sequence parent in a tree, returns new root
// and a bool equal to true iff the children were added. Assumes parent is a
// sequence node and index is valid.
func addNodesToSequence(root Node, parent Node, children []Node, index int) (Node, bool) {
	if root == parent {
		rootImplCopy := *root.(*nodeImpl)
		oldChildren := rootImplCopy.value.([]Node)
		newChildren := make([]Node, len(oldChildren)+len(children))
		copy(newChildren[:index], oldChildren[:index])
		copy(newChildren[index:], children)
		copy(newChildren[index+len(children):], oldChildren[index:])
		rootImplCopy.value = newChildren
		return Node(&rootImplCopy), true
	}

	switch root.Kind() {
	case ScalarKind:
		return nil, false
	case SequenceKind:
		oldChildren := root.Value().([]Node)
		for i, c := range oldChildren {
			n, added := addNodesToSequence(c, parent, children, index)
			if added {
				newChildren := append([]Node(nil), oldChildren...)
				newChildren[i] = n
				rootImplCopy := *root.(*nodeImpl)
				rootImplCopy.value = newChildren
				return Node(&rootImplCopy), true
			}
		}
	case MappingKind:
		oldChildren := root.Value().(map[string]Node)
		for k, c := range oldChildren {
			n, added := addNodesToSequence(c, parent, children, index)
			if added {
				newChildren := make(map[string]Node, len(oldChildren)+1)
				for kk, cc := range oldChildren {
					newChildren[kk] = cc
				}
				newChildren[k] = n
				rootImplCopy := *root.(*nodeImpl)
				rootImplCopy.value = newChildren
				return Node(&rootImplCopy), true
			}
		}
	}

	// Didn't find parent.
	return root, false
}

// Returns a deep copy of the tree rooted by the argument.
func deepCopy(root Node) Node {
	rootImpl := *root.(*nodeImpl)

	copyImpl := rootImpl

	if rootImpl.source != nil {
		sourceCopy := *rootImpl.source
		copyImpl.source = &sourceCopy
	}
	if rootImpl.referrers != nil {
		copyImpl.referrers = make([]*NodeSource, len(rootImpl.referrers))
		for i, r := range rootImpl.referrers {
			refCopy := *r
			copyImpl.referrers[i] = &refCopy
		}
	}

	switch rootImpl.kind {
	case SequenceKind:
		rootChildren := rootImpl.value.([]Node)
		copyChildren := make([]Node, len(rootChildren))
		for i, child := range rootChildren {
			copyChildren[i] = deepCopy(child)
		}
		copyImpl.value = copyChildren
	case MappingKind:
		rootChildren := rootImpl.value.(map[string]Node)
		copyChildren := make(map[string]Node, len(rootChildren))
		for key, child := range rootChildren {
			copyChildren[key] = deepCopy(child)
		}
		copyImpl.value = copyChildren
	}

	return Node(&copyImpl)
}

// PathFrom returns a path from one Node to another in a tree. It returns
// nil if last is neither first nor a descendant of first. Otherwise it returns
// a slice of Node in which first and last are the first and last elements and
// each element is a child of the previous element.
func PathFrom(first Node, last Node) []Node {
	if first != nil && last != nil {
		if last == first {
			return []Node{first}
		}
		switch first.Kind() {
		case SequenceKind:
			for _, child := range first.Value().([]Node) {
				p := PathFrom(child, last)
				if p != nil {
					return append([]Node{first}, p...)
				}
			}
		case MappingKind:
			for _, child := range first.Value().(map[string]Node) {
				p := PathFrom(child, last)
				if p != nil {
					return append([]Node{first}, p...)
				}
			}
		}
	}
	return nil
}

// TreesEquivalent returns true if and only if the trees rooted by node1 and
// node2 are equivalent. Here equivalence means that the two trees have
// identical structure and equal string values at their leaf nodes. It does
// not require the Source method to return the same value for corresponding
// nodes of the two trees. Thus TreesEquivalent reports deep equality ignoring
// node origins.
func TreesEquivalent(root1 Node, root2 Node) bool {
	if root1.Kind() != root2.Kind() {
		return false
	}
	switch root1.Kind() {
	case ScalarKind:
		return root1.Value() == root2.Value()
	case SequenceKind:
		children1 := root1.Value().([]Node)
		children2 := root2.Value().([]Node)
		if len(children1) != len(children2) {
			return false
		}
		for i, child1 := range children1 {
			child2 := children2[i]
			if !TreesEquivalent(child1, child2) {
				return false
			}
		}
		return true
	case MappingKind:
		children1 := root1.Value().(map[string]Node)
		children2 := root2.Value().(map[string]Node)
		if len(children1) != len(children2) {
			return false
		}
		for key, child1 := range children1 {
			child2 := children2[key]
			if !TreesEquivalent(child1, child2) {
				return false
			}
		}
		return true
	}
	return false // "can't happen"
}

// NativeTree creates a representation of a Node tree of that type created by
// ReadYaml that uses only native go types instead of Node. Each node in the
// new tree is represented by a value of static type interface{}. For leaf
// nodes the dynamic type is derived from type information recorded or inferred
// at parse time. For sequence or mapping nodes the dynamic type is
// []interface{} or map[string]interface{}, respectively. The root of the tree
// is returned.
//
// The dynamic types of leaf node values in the returned structure are bool for
// booleans, int64 for integers, float64 for floats, and string for other
// non-null values. Null values are represented by nil.
//
// A panic occurs if any node under root is of a foreign Node implementation.
func NativeTree(root Node) interface{} {
	rootImpl, ok := root.(*nodeImpl)
	if !ok {
		panic("ERROR: " + NodeErrorf(root, "invalid Node implementation: %T", root).Error())
	}
	switch root.Kind() {
	case ScalarKind:
		val, err := decodeScalarNodeValue(rootImpl)
		if err == nil {
			return val
		} else {
			return rootImpl.value // string
		}
	case SequenceKind:
		elements := []interface{}{}
		for _, v := range root.Value().([]Node) {
			elements = append(elements, NativeTree(v))
		}
		return elements
	case MappingKind:
		children := map[string]interface{}{}
		for k, v := range root.Value().(map[string]Node) {
			children[k] = NativeTree(v)
		}
		return children
	default:
		panic("ERROR: " + NodeErrorf(root, "invalid node kind: %s", root.Kind().String()).Error())
	}
}

// Returns the result of decoding a scalar node's value according to its tag.
// On success returns concrete nil, bool, int64, float64, or string for tag
// values of "!!null", "!!bool", "!!int", "!!float", or anything else,
// respectively. Returns an error if a conversion fails or if the argument
// is not a scalar node.
func decodeScalarNodeValue(node *nodeImpl) (interface{}, error) {
	switch node.kind {
	case ScalarKind:
		strval := node.value.(string)
		switch node.tag {
		case "!!null":
			return nil, nil
		case "!!int":
			if i, err := strconv.ParseInt(strval, 10, 64); err != nil {
				return nil, NodeErrorf(node, "failed to decode as int64: %q", strval)
			} else {
				return i, nil
			}
		case "!!float":
			if f, err := strconv.ParseFloat(strval, 64); err != nil {
				return nil, NodeErrorf(node, "failed to decode as float64: %q", strval)
			} else {
				return f, nil
			}
		case "!!bool":
			if b, err := strconv.ParseBool(strval); err != nil {
				return nil, NodeErrorf(node, "failed to decode as bool: %q", strval)
			} else {
				return b, nil
			}
		default: // "!!str" or other
			return strval, nil
		}
	default:
		return nil, NodeErrorf(node, "cannot decode non-scalar node value")
	}
}
