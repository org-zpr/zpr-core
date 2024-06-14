package pp

import (
	"fmt"
	"regexp"
	"strings"

	"zpr.org/vsx/zpl/fs"
	yt "zpr.org/vsx/zpl/pp/yamltree"
)

const (
	KW_Import = "$import"
)

// Processes import directives in a YAML document tree. Parameters are root
// of input tree and file store to read files from. Returns root of new tree
// equivalent to input tree with all imports resolved.
func ProcessImports(root yt.Node, store fs.FileStore) (yt.Node, error) {
	file, err := store.Abs(root.Source().File)
	if err != nil {
		return nil, yt.NodeErrorf(root, "%q: %w", err)
	}
	visited := map[string]bool{file: true}
	return processImports(root, store, store.GetCWD(), visited)
}

// Helper for ProcessImports. Resolves filenames relative to basedir. Uses
// (updates) visited map to prevent import cycles.
func processImports(root yt.Node, store fs.FileStore, basedir string, visited map[string]bool) (yt.Node, error) {
	root1, err := processValueContextImports(root, store, basedir, visited)
	if err != nil {
		return nil, err
	}

	root2, err := processKeyContextImports(root1, store, basedir, visited)
	if err != nil {
		return nil, err
	}

	return root2, nil
}

// Processes value-context imports, i.e., those that occur as leaf (scalar)
// values of the form "<import-keyword>[<filename>]". Arguments are as for
// processImports.
func processValueContextImports(root yt.Node, store fs.FileStore, basedir string, visited map[string]bool) (yt.Node, error) {
	valueContextImportPathPattern := yt.NewPathPatternOk(`@@$'^` + regexp.QuoteMeta(KW_Import) + `'`)
	pathsToImportNodes := yt.MatchingPaths(root, valueContextImportPathPattern)
	for _, path := range pathsToImportNodes {
		node := path[len(path)-1]
		nodeString := node.Value().(string) // KW_Import...

		i := len(KW_Import)
		j := len(nodeString) - 1
		if i >= j-1 || nodeString[i] != '[' || nodeString[j] != ']' {
			return nil, yt.PathErrorf(path, `syntax error: expected "%s[<file>]"`, KW_Import)
		}
		file := strings.TrimSpace(nodeString[i+1 : j])

		imported, err := importFile(path, file, store, basedir, visited)
		if err != nil {
			return nil, yt.PathErrorf(path, "import failed: %w", err)
		}

		newRoot, err := yt.ReplaceNode(root, node, imported, node)
		if err != nil {
			return nil, yt.PathErrorf(path, "import failed: %w", err)
		}

		root = newRoot
	}

	return root, nil
}

// Processes key-context imports, i.e., those that occur as mapping entries of
// the form "<import-keyword>: filename". In this case the root of the imported
// tree donatees its children to the import node's parent (and the import node
// is removed). Arguments are as for processImports.
func processKeyContextImports(root yt.Node, store fs.FileStore, basedir string, visited map[string]bool) (yt.Node, error) {
	// Unlike when processing value-context imports, processing a key-context
	// import can affect the path to other key-context imports, so we just
	// repeat the whole search until we've processed them all.
	importKeyRegexp := `^` + regexp.QuoteMeta(KW_Import) + `(\[.*\])?$`
	importPattern := yt.NewPathPatternOk("@@.'" + importKeyRegexp + "'$")
	for {
		pathsToImportNodes := yt.MatchingPaths(root, importPattern)
		if len(pathsToImportNodes) == 0 {
			return root, nil
		}

		path := pathsToImportNodes[0]
		node := path[len(path)-1]
		parent := path[len(path)-2]
		parentMap := parent.Value().(map[string]yt.Node)

		extractFilename := func(importNode yt.Node, importNodeParent yt.Node) string {
			for key, child := range importNodeParent.Value().(map[string]yt.Node) {
				if child == importNode {
					if key == KW_Import {
						return strings.TrimSpace(importNode.Value().(string))
					} else {
						return strings.TrimSpace(key[len(KW_Import)+1 : len(key)-1])
					}
				}
			}
			panic(fmt.Sprintf("node %v not a child of node %v", importNode, importNodeParent))
		}

		file := extractFilename(node, parent)

		donor, err := importFile(path, file, store, basedir, visited)
		if err != nil {
			return nil, err
		}
		switch donor.Kind() {
		case yt.ScalarKind:
			return nil, yt.PathErrorf(path, "cannot import top-level scalar in key context: %q", file)
		case yt.MappingKind:
			donorMap := donor.Value().(map[string]yt.Node)
			for k, _ := range donorMap {
				if _, exists := parentMap[k]; exists {
					return nil, yt.PathErrorf(path, "import of %q attempts to overwrite key %q", file, k)
				}
			}
			root, _ = yt.AddNodesToMapping(root, parent, donorMap, node)
			root, _ = yt.RemoveNode(root, node) // lose the "import" node
		case yt.SequenceKind:
			// The imported content has a sequence at the top level, while the
			// current node's parent, which is supposed to receive the sequence
			// elements as children, is clearly a mapping. We nevertheless allow
			// the import, replacing the parent with a sequence, but only if all
			// of the current node's siblings are also imports of top-level
			// sequences. In that case we concatenate all the imported sequence
			// elements to form the new sequence.
			//
			// Note that this procedure does not allow one to mix imports and
			// defines of top-level sequences in key-context. This is because
			// imports are completely processed before defines are processed.
			// So if, while processing imports, we find a key-context import of
			// a sequence, and the import node has a sibling node that is a
			// key-context reference to a defined symbol, then there is no way
			// to check whether the definition is also a sequence. To allow
			// arbitrary mixing of imports and defines, we would either have to
			// process imports and defines together or else do something like
			// rework the import processing to replace "$import:" keys by
			// "$<symbol>" keys and return the definitions of the (synthesized)
			// symbols so they can be forwarded to the defines processing, which
			// would do the actual substitutions. Since the restriction we're
			// talking about only applies to the mixing of _key-context_ imports
			// and defines, which arguably seems unlikely to come up much in
			// practice, removing it doesn't seem worth the hassle right now.
			siblingKeys := make([]string, 0)
			siblingDonors := make(map[string]yt.Node)
			for siblingKey, sibling := range parentMap {
				siblingPath := yt.AppendToPathCopy(path[:len(path)-1], sibling)
				if !regexp.MustCompile(importKeyRegexp).MatchString(siblingKey) {
					return nil, yt.PathErrorf(siblingPath, "cannot import %q: value is sequence, but parent mapping has other keys (e.g., %q)", file, siblingKey)
				}
				siblingFile := extractFilename(sibling, parent)
				if siblingDonor, err := importFile(siblingPath, siblingFile, store, basedir, visited); err != nil {
					return nil, err
				} else if siblingDonor.Kind() != yt.SequenceKind {
					return nil, yt.PathErrorf(siblingPath, "cannot mix sequence-valued import %q with non-sequence-valued sibling import %q", file, siblingFile)
				} else {
					siblingKeys = append(siblingKeys, siblingKey)
					siblingDonors[siblingKey] = siblingDonor
				}
			}

			newChildren := []yt.Node{}
			for _, siblingKey := range yt.MappingKeysInSourceOrder(parent) {
				newChildren = append(newChildren, siblingDonors[siblingKey].Value().([]yt.Node)...)
			}
			newParent, _ := yt.ReplaceNodeValue(parent, []yt.Node(nil))
			newParent, _ = yt.AddNodesToSequence(newParent, newParent, newChildren, 0, node)
			root, _ = yt.ReplaceNode(root, parent, newParent, nil)
		}
	}
}

// Imports a file, resolves any nested imports, and returns the root of the
// resulting node tree. On failure returns an error value containing a
// *yt.PathError. The first argument is only used to provide context in
// errors. Remaining arguments are as for processImports.
func importFile(path []yt.Node, file string, store fs.FileStore, basedir string, visited map[string]bool) (yt.Node, error) {
	absfile, err := store.Abs2(file, basedir)
	if err != nil {
		return nil, yt.PathErrorf(path, "import failed for %q: %w", file, err)
	}
	if !store.Exists(absfile) {
		return nil, yt.PathErrorf(path, "import failed for %q: no such file", file)
	}

	if visited[absfile] {
		return nil, yt.PathErrorf(path, "circular import attempted")
	}
	visited[absfile] = true
	defer delete(visited, absfile)

	if regexp.MustCompile("(?i)ya?ml$").MatchString(absfile) {
		// Assume it's a YAML file. Read it and process any neested imports.
		node0, err := LoadYamlTree(absfile, store)
		if err != nil {
			return nil, err
		}
		node1, err := processImports(node0, store, store.Dir(absfile), visited)
		if err != nil {
			return nil, err
		}
		return node1, nil
	} else {
		// Some other data file. Create a scalar node with its contents.
		data, err := store.ReadFile(absfile)
		if err != nil {
			return nil, yt.PathErrorf(path, "import failed for %q: %w", file, err)
		}
		node, _ := yt.ReadYamlFromString("replace this", absfile)
		node, _ = yt.ReplaceNodeValue(node, string(data))
		return node, nil
	}

}
