package pp

import (
	"fmt"
	"sort"
	"strings"

	"zpr.org/vsx/zpl/doc"
	yt "zpr.org/vsx/zpl/pp/yamltree"
)

var (
	// A pattern that matches all paths to leaf nodes whose values are strings
	// that start with '$':
	valueContextDollarRefPathPattern = yt.NewPathPatternOk(`@@$'^\$'`)

	// A pattern that matches all paths to leaf nodes mapped to keys whose names
	// start with '$':
	keyContextDollarRefPathPattern = yt.NewPathPatternOk(`@@.'^\$'$`)
)

// Processes "defines" references in a policy YAML tree. Argument is root of
// input tree. On success returns root of new tree equivalent to input tree
// but with all references ($<id>) replaced by their definitions and all
// "defines" blocks removed. On failure returns nil and an error.
func ProcessDefines(root yt.Node) (yt.Node, error) {
	// Resolve any $<ident> references against "defines" sections.
	root, err := resolveDefinesReferences(root, ".")
	if err != nil {
		return nil, err
	}
	return removeDefines(root)
}

// Resolves $<id> references to definitions in "defines" sections in part of
// a document tree. Restricts work to the subtree(s) identified by the path
// expression pathExpr under root. Searches each subtree for "defines" blocks
// and uses their contents to replace any $id references in the subtree. On
// success returns the root of a new tree with substitutions made.
func resolveDefinesReferences(root yt.Node, pathExpr string) (yt.Node, error) {
	pathPattern, err := yt.NewPathPattern(pathExpr)
	if err != nil {
		return nil, err
	}
	for _, path := range yt.MatchingPaths(root, pathPattern) {
		root, err = resolveDefinesReferencesInSubtree(root, path)
		if err != nil {
			return nil, err
		}
	}
	return root, nil
}

// Does work of resolveDefinesReferences for one subtree.
func resolveDefinesReferencesInSubtree(root yt.Node, pathToSubtree []yt.Node) (yt.Node, error) {
	// Get paths from root to all "defines" nodes under the subtree. (Paths all
	// the way from the root make for better error messages.)
	defsPaths := [][]yt.Node{}
	subtreeRoot := lastNode(pathToSubtree)
	for _, path := range yt.MatchingPaths(subtreeRoot, yt.NewPathPatternOk("@@.defines")) {
		defsPath := yt.AppendToPathCopy(pathToSubtree, path[1:]...)
		defsPaths = append(defsPaths, defsPath)
	}

	// Each "defines" node is the child of a mapping node, and its definitions
	// should affect all of its siblings (and their descendants). But if the
	// "defines" node is an only child and the grandchild of a sequence node,
	// then the definitions should affect all of its parent's siblings as well.
	// Figure out the "scope node" (parent or grandparent) for each "defines"
	// node, and record a mapping from each scope node to the corresponding
	// definition content in the form of a map of definition IDs to the roots
	// of the associated content subtrees. Just store the original content for
	// now. Any needed "$" resolution within the original content will happen
	// shortly.
	type defsContent struct {
		path     []yt.Node          // path to "defines" block root
		original map[string]yt.Node // def ID -> original def content root
		resolved map[string]yt.Node // def ID -> "$"-resolved def content root
	}
	scopeMap := make(map[yt.Node]*defsContent) // scope node -> content
	for _, defsPath := range defsPaths {
		defsNode := lastNode(defsPath) // a "defines" node
		if err := validateNodeKind(defsNode, yt.MappingKind); err != nil {
			return nil, yt.PathErrorf(defsPath, `invalid "defines" block: %w`, err)
		}
		defsMap := make(map[string]yt.Node) // definition ID -> root of definition

		// The defines block is a mapping. Each top-level key names a "define".
		defPath := append(defsPath, defsNode)
		for defId, defContent := range defsNode.Value().(map[string]yt.Node) {
			// An individual definition. It must be a one-key mapping.
			if err := doc.AssertValidDefine(defId); err != nil {
				return nil, yt.PathErrorf(defPath, `invalid "defines" entry: %w`, err)
			}
			defsMap[defId] = defContent
		}
		defsParent := defsPath[len(defsPath)-2]
		scopeRoot := defsParent
		if len(defsParent.Value().(map[string]yt.Node)) == 1 {
			if len(defsPath) >= 3 {
				defsGrandparent := defsPath[len(defsPath)-3]
				if defsGrandparent.Kind() == yt.SequenceKind {
					scopeRoot = defsGrandparent
				}
			}
		}
		scopeMap[scopeRoot] = &defsContent{path: defsPath, original: defsMap, resolved: nil}
	}

	// Now resolve any "$" references within the definitions in each "defines"
	// block content. For each path to a "defines" node, walk down from the
	// root, populating the resolved content maps of any relevant "defines"
	// nodes along the way with the last-write-wins integration of all
	// definitions that come into scope, all with any "$" references resolved.
	for _, defsPath := range defsPaths {
		integDefsMap := make(map[string]yt.Node) // ID -> definition
		for _, node := range defsPath {
			if content, exists := scopeMap[node]; exists {
				// This node is the resolution scope root for a "defines" node,
				// and content has all its definitions. If content hasn't had
				// its "$" references resolved yet, do it now.
				if content.resolved == nil {
					// Populate the resolved content map with definitions for
					// all IDs defined in the original content map. Follow
					// dependency ordering so that everything an ID references
					// is resolved by the time the ID itself is evaluated.
					// Definitions in a single "defines" block are allowed to
					// depend on one another as long as there are no cyclic
					// dependencies.
					content.resolved = make(map[string]yt.Node, len(content.original))
					allIds, err := idsInEvaluationOrder(content.original)
					if err != nil {
						return nil, yt.PathErrorf(content.path, `cannot resolve definitions in "defines" block: %w`, err)
					}
					for _, id := range allIds {
						if origDef, ok := content.original[id]; ok {
							newDef, err := resolveReferencesUsingMap(origDef, integDefsMap, true)
							if err != nil {
								pathError := err.(*yt.PathError)
								pathError.Path = append(yt.PathFrom(root, origDef), pathError.Path[1:]...)
								return nil, err
							}
							content.resolved[id] = newDef
							integDefsMap[id] = newDef
						}
					}
				}
				// Update the integrated definition map.
				for id, def := range content.resolved {
					integDefsMap[id] = def
				}
			}
		}
	}

	// Finally, resolve all "$" references under the resolution scope roots
	// using the appropriate definitions. To do this, process the "defines"
	// paths in order of decreasing length, and walk up each one from the
	// bottom, looking up the appropriate definitions map for each along the
	// way. Since some original scope roots are likely to get replaced once
	// "$" references start getting resolved, keep track of things using path
	// expressions instead of Node values.
	sort.Slice(defsPaths, func(i, j int) bool { return len(defsPaths[i]) > len(defsPaths[j]) })
	// An instruction for a "$" reference resolving operation in a subtree.
	type resolution struct {
		pathExpr string             // path expr of a resolution scope root
		defMap   map[string]yt.Node // def ID -> "$"-resolved def content root
	}
	resolutions := []resolution{}
	for _, defsPath := range defsPaths {
		for i := len(defsPath) - 1; i >= 0; i-- {
			node := defsPath[i]
			if content, exists := scopeMap[node]; exists {
				// This node is a resolution scope root for a "defines" block.
				// Build a resolution instruction for it.
				scopePath := yt.PathFrom(root, node)
				scopePathExpr := yt.PathExpressionOk(scopePath)
				resolutions = append(resolutions, resolution{scopePathExpr, content.resolved})
			}
		}
	}
	for _, resolution := range resolutions {
		scopePath := yt.MatchingPaths(root, yt.NewPathPatternOk(resolution.pathExpr))[0]
		scopeNode := lastNode(scopePath)
		var err error
		// There may be "$" references for identifiers that are only defined
		// in an outer scope, so don't require that all references be resolved
		// here. We'll check for unresolved IDs at the end.
		newScopeNode, err := resolveReferencesUsingMap(scopeNode, resolution.defMap, false)
		if err != nil {
			pathError := err.(*yt.PathError)
			pathError.Path = append(yt.PathFrom(root, scopeNode), pathError.Path[1:]...)
			return nil, err
		}
		root, err = yt.ReplaceNode(root, scopeNode, newScopeNode, nil)
		if err != nil {
			return nil, err // "can't happen"
		}
	}

	// And _finally_ finally, make sure there are no "$" references left over.
	// If there are, it means we found no relevant "defines" blocks to resolve
	// them against.
	_, err := resolveReferencesUsingMap(root, map[string]yt.Node{}, true)
	if err != nil {
		return nil, err
	}

	return root, nil
}

// Resolves "defines" references in the (sub)tree under root using the given
// definitions map. Replaces any $<id> references using the value at <id> in
// definesMap. On success returns a new root under which all substitutions
// have been made. On failure returns an error that contains a *PathError
// relative to root. Possible failures include references to nodes of invalid
// type in key context and, if requireDefs is true, references to identifiers
// with no entry in definesMap.
func resolveReferencesUsingMap(root yt.Node, definesMap map[string]yt.Node, requireDefs bool) (yt.Node, error) {
	// First resolve value-context references. This requires replacing leaf
	// nodes only, so we can find all of the target nodes once and then step
	// through the list making replacements (and getting a new root) without
	// worrying about invalidating any of the remaining target nodes.
	for _, path := range yt.MatchingPaths(root, valueContextDollarRefPathPattern) {
		node := lastNode(path)
		nodeText := node.Value().(string)
		id := nodeText[1:] // skip the "$"
		replacementNode, defined := definesMap[id]
		if defined {
			var err error
			root, err = yt.ReplaceNode(root, node, replacementNode, node)
			if err != nil {
				return nil, err // "can't happen"
			}
		} else if requireDefs {
			return nil, yt.PathErrorf(path, "cannot resolve %q: no definition for %q", nodeText, id)
		}
	}

	// Now resolve key-context references. This time we are removing leaf nodes
	// and adding new children to their (mapping) parents. Because this causes
	// those parent nodes to be replaced, it won't work to find all the target
	// parents once and then iterate through them. So instead we save path
	// expressions, which don't change.
	targetPaths := yt.MatchingPaths(root, keyContextDollarRefPathPattern)
	targetPathExprs := make([]string, len(targetPaths))
	for i, path := range targetPaths {
		targetPathExprs[i] = yt.PathExpressionOk(path)
	}
	for _, pathExpr := range targetPathExprs {
		paths := yt.MatchingPaths(root, yt.NewPathPatternOk(pathExpr))
		// Normally there will be exactly one matching path. But there can be
		// none in the case where a mapping node with multiple children gets
		// replaced by a sequence node (see below).
		if len(paths) == 0 {
			continue
		}
		path := paths[0]
		node := path[len(path)-1]
		parent := path[len(path)-2]
		siblingMap := parent.Value().(map[string]yt.Node)

		// This is a leaf node mapped to a key of the form $<id> in its parent.
		// Find the id.
		nodeKey := ""
		for key, child := range siblingMap {
			if child == node {
				nodeKey = key
				break
			}
		}
		id := nodeKey[1:]

		// Find the node that is supposed to donate its children to the current
		// node's parent.
		donor, defined := definesMap[id]
		if !defined {
			if requireDefs {
				return nil, yt.PathErrorf(path, "cannot resolve %q: no definition for %q", nodeKey, id)
			}
		} else {
			switch donor.Kind() {
			case yt.MappingKind:
				// The donor node is a mapping. Arrange for all its children
				// to be adopted (or at least copies of them) by the current
				// node's parent, then delete the current node.
				var err error
				root, err = yt.AddNodesToMapping(root, parent, donor.Value().(map[string]yt.Node), node)
				if err != nil {
					return nil, err // "can't happen"
				}
				root, err = yt.RemoveNode(root, node)
				if err != nil {
					return nil, err // "can't happen"
				}
			case yt.SequenceKind:
				// The donor node is a sequence. The current node's parent is
				// a mapping (we're processing a key context reference), so
				// this doesn't seem to make sense. But we allow it if the
				// current node and all of its siblings are mapped under keys
				// that are "$" references to sequences. In that case we
				// replace the current node's parent by a sequence containing
				// the concatenation of all of the referenced sequences, with
				// source file ordering preserved.
				siblingKeys := []string{}
				for siblingKey, sibling := range siblingMap {
					siblingPath := yt.AppendToPathCopy(path[:len(path)-1], sibling)
					if !strings.HasPrefix(siblingKey, "$") {
						return nil, yt.PathErrorf(siblingPath, "cannot resolve %q: value is sequence, but parent mapping has other keys (e.g., %q)", nodeKey, siblingKey)
					} else if siblingDonor, defined := definesMap[siblingKey[1:]]; !defined {
						return nil, yt.PathErrorf(siblingPath, "cannot resolve %q: no definition for %q", siblingKey, siblingKey[1:])
					} else if siblingDonor.Kind() != yt.SequenceKind {
						return nil, yt.PathErrorf(siblingPath, "cannot resolve %q: a sequence can only be interpolated in key context alone or with other sequences", nodeKey)
					} else {
						siblingKeys = append(siblingKeys, siblingKey)
					}
				}
				newChildren := []yt.Node{}
				for _, siblingKey := range yt.MappingKeysInSourceOrder(parent) {
					newChildren = append(newChildren, definesMap[siblingKey[1:]].Value().([]yt.Node)...)
				}
				newParent, err := yt.ReplaceNodeValue(parent, newChildren)
				if err != nil {
					return nil, err // "can't happen"
				}
				root, err = yt.ReplaceNode(root, parent, newParent, parent)
				if err != nil {
					return nil, err // "can't happen"
				}
			default:
				return nil, yt.PathErrorf(path, "cannot resolve %q: scalar invalid in mapping key context: %v", nodeKey, donor.Value())
			}
		}
	}

	return root, nil
}

// Returns a slice containing all definition IDs that appear in the argument
// map, either as keys or in "$" references in definitions. The IDs are ordered
// such that each one appears after all other IDs it depends on, directly or
// indirectly, through "$" references. An error is returned if the argument map
// contains any dependency cycles.
func idsInEvaluationOrder(definitions map[string]yt.Node) ([]string, error) {
	dependencies := make([]SymbolDependency, 0, len(definitions))
	allIds := make(map[string]bool, len(definitions))
	for id, defRoot := range definitions {
		allIds[id] = true
		for _, path := range yt.MatchingPaths(defRoot, valueContextDollarRefPathPattern) {
			dependeeId := lastNode(path).Value().(string)[1:] // drop leading '$'
			dependencies = append(dependencies, NewSymbolDependency(id, dependeeId))
			allIds[dependeeId] = true
		}
		for _, path := range yt.MatchingPaths(defRoot, keyContextDollarRefPathPattern) {
			lastMapping := path[len(path)-2]
			for key, _ := range lastMapping.Value().(map[string]yt.Node) {
				if strings.HasPrefix(key, "$") {
					dependeeId := key[1:] // drop leading '$'
					dependencies = append(dependencies, NewSymbolDependency(id, dependeeId))
					allIds[dependeeId] = true
				}
			}
		}
	}
	if idsInDependencyOrder, err := SortSymbolDependencies(dependencies); err != nil {
		return nil, err
	} else {
		result := make([]string, len(idsInDependencyOrder))
		for i, id := range idsInDependencyOrder {
			result[len(idsInDependencyOrder)-1-i] = id
			delete(allIds, id)
		}
		// Append any IDs that don't depend on anything.
		for id, _ := range allIds {
			result = append(result, id)
		}
		return result, nil
	}
}

// A symbol (or ID) dependency record.
type SymbolDependency struct {
	depender string
	dependee string
}

func NewSymbolDependency(depender string, dependee string) SymbolDependency {
	return SymbolDependency{depender, dependee}
}

// Does a topological sort of a collection of symbol (or ID) dependencies. On
// success, returns a slice that contains one element for every symbols that
// is named in the argument slice and in which symbol s1 appears before symbol
// s2 if s1 depends on s2. Returns nil and an error if the input slice contains
// any cyclic dependencies. The argument slice may be empty or contain duplicate
// dependencies.
func SortSymbolDependencies(dependencies []SymbolDependency) ([]string, error) {
	sortedIds := make([]string, 0)

	// Use Kahn's algorithm. Start by building a set of IDs that are not
	// dependees of any others.
	dependees := make(map[string]bool)
	for _, d := range dependencies {
		dependees[d.dependee] = true
	}
	nonDependees := make(map[string]bool)
	for _, d := range dependencies {
		id := d.depender
		if _, isDependee := dependees[id]; !isDependee {
			nonDependees[id] = true
		}
	}

	// For each non-dependee ID, append it to the sorted ID list, remove it
	// from the non-dependee set and the dependencies list, then add any of
	// its dependees that are not also dependees of any other IDs to the
	// non-dependee set and repeat. If there are no cyclic dependencies, then
	// eventually both the non-dependee set and the dependency list will become
	// empty, and the sorted ID list will contain a topological sort of all IDs
	// appearing in the dependencies list.
	for len(nonDependees) > 0 {
		var id string
		for id, _ = range nonDependees {
			break // just get the first
		}
		sortedIds = append(sortedIds, id)
		delete(nonDependees, id)
		newDependencies := dependencies[:0] // may as well reuse the storage
		for _, d := range dependencies {
			if d.depender != id {
				newDependencies = append(newDependencies, d)
			} else {
				dependeeHasOtherDependers := false
				for _, dd := range dependencies {
					if dd.dependee == d.dependee && dd.depender != d.depender {
						dependeeHasOtherDependers = true
						break
					}
				}
				if !dependeeHasOtherDependers {
					nonDependees[d.dependee] = true
				}
			}
		}
		dependencies = newDependencies
	}

	// Return an informative error if there are any cycles.
	if len(dependencies) != 0 {
		var buf strings.Builder
		buf.WriteString("dependency cycle(s) found: ")
		for i, d := range dependencies {
			if i != 0 {
				buf.WriteString(", ")
			}
			buf.WriteString(fmt.Sprintf("%s -> %s", d.depender, d.dependee))
		}
		return nil, fmt.Errorf(buf.String())
	} else {
		return sortedIds, nil
	}
}

// Removes all "defines" sections from the YAML tree rooted at the argument
// node, returns the root of the modified tree.
func removeDefines(root yt.Node) (yt.Node, error) {
	// Removing a node replaces all ancestor nodes up to the root, so just
	// keep searching for and removing "defines" subtrees until none remain.
	var err error
	for {
		definesPaths := yt.MatchingPaths(root, yt.NewPathPatternOk("@@.defines"))
		if len(definesPaths) == 0 {
			break
		}
		defines := lastNode(definesPaths[0])
		if root, err = yt.RemoveNode(root, defines); err != nil {
			return nil, err
		}
	}
	return root, nil
}
