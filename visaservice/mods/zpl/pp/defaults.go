package pp

import (
	yt "zpr.org/vsx/zpl/pp/yamltree"
)

var (
	defaultableServiceKeys = []string{"provider", "auth"}
	defaultablePolicyKeys  = []string{"scope", "conditions", "constraints"}
)

// ProcessDefaults applies system defaults in a policy YAML tree. Argument
// is root of input tree. On success returns root of new tree equivalent to
// input tree but with defaults values (subtrees) inserted into system
// configurations where corresponding values are left unspecified and with
// default definitions removed. Returns a non-nil error on failure.
func ProcessDefaults(root yt.Node) (yt.Node, error) {
	// Make sure the "communications" node exists.
	commsPathExpr := "communications"
	if len(yt.MatchingPaths(root, yt.NewPathPatternOk(commsPathExpr))) == 0 {
		return nil, yt.NodeErrorf(root, `"communications" block not found`)
	}

	// Get the hierarchy names ("systems" aliases) if defined.
	hierNames := []string{}
	for _, namePath := range yt.MatchingPaths(root, yt.NewPathPatternOk(commsPathExpr+".hierarchy[*]$")) {
		hierNames = append(hierNames, lastNode(namePath).Value().(string))
	}

	// Recursively apply defaults, starting with systems immediately under
	// "communications".
	root, err := applyDefaultsInAllSystems(root, commsPathExpr, hierNames, map[string]yt.Node{})
	if err != nil {
		return nil, err
	}

	return root, nil
}

// Applies defaults in all systems under the node identified by parentPathExpr
// ("communications" for the top level). Looks for systems under the "systems"
// key unless the hierarchy name list is nonempty, in which case the first
// name in the list is used instead of "systems". First argument must be root
// of YAML node tree, and the path expression parentPathExpr must be relative
// to that root.
func applyDefaultsInAllSystems(root yt.Node, parentPathExpr string, hierarchy []string, defaults map[string]yt.Node) (yt.Node, error) {
	// Get a path expression for all system blocks at the current level.
	var allSysPathExpr string
	var hierarchyTail []string
	if len(hierarchy) == 0 {
		allSysPathExpr = parentPathExpr + ".systems.*"
		hierarchyTail = []string{}
	} else {
		allSysPathExpr = parentPathExpr + "." + pathExpressionKeyDisjunction("systems", hierarchy[0]) + ".*"
		hierarchyTail = hierarchy[1:]
	}

	// Apply defaults in each matching system.
	var err error
	for _, sysPath := range yt.MatchingPaths(root, yt.NewPathPatternOk(allSysPathExpr)) {
		sysPathExpr := yt.PathExpressionOk(sysPath)
		root, err = applyDefaultsInSingleSystem(root, sysPathExpr, hierarchyTail, defaults)
		if err != nil {
			return nil, err
		}
	}

	return root, nil
}

// Applies defaults in system identified by the path expression sysPathExpr.
// Removes any default definitions from the system and its services after
// applying them.
func applyDefaultsInSingleSystem(root yt.Node, sysPathExpr string, hierarchy []string, defaults map[string]yt.Node) (yt.Node, error) {
	// Set up a defaults map for this system. Start with any defaults inherited
	// from the parent system, then add in the contents of the local "defaults"
	// block if there is one.
	sysDefaults := copyDefaultsMap(defaults)
	for _, defPath := range yt.MatchingPaths(root, yt.NewPathPatternOk(sysPathExpr+".defaults.*")) {
		if err := validateLastNodeKind(defPath, yt.MappingKind); err != nil {
			return nil, err
		}
		defMapping := lastNode(defPath).Value().(map[string]yt.Node)
		if _, exists := defMapping["desc"]; !exists {
			return nil, yt.PathErrorf(defPath, `missing required description`)
		} else if valueNode, exists := defMapping["value"]; !exists {
			return nil, yt.PathErrorf(defPath, `missing required value`)
		} else {
			sysDefaults[lastNodeKey(defPath)] = valueNode
		}
	}

	// Apply defaults in each of this system's services.
	for _, svcPath := range yt.MatchingPaths(root, yt.NewPathPatternOk(sysPathExpr+".components.*")) {
		svcPathExpr := yt.PathExpressionOk(svcPath)
		svcNode := lastNode(svcPath)

		// Add key/value pairs to the tree for any defaulted (and defaultable)
		// service-level keys.
		newSvcChildren := map[string]yt.Node{}
		for _, key := range defaultableServiceKeys {
			if len(yt.MatchingPaths(root, yt.NewPathPatternOk(svcPathExpr+"."+yt.QuoteKeyMeta(key)))) == 0 {
				if node, exists := sysDefaults[key]; exists {
					newSvcChildren[key] = node
				}
			}
		}
		root, _ = yt.AddNodesToMapping(root, svcNode, newSvcChildren, svcNode)

		// Set up a policy defaults map for this service. Start with the
		// enclosing system's defaults, and then add in any "implicit" policy
		// defaults defined under the service.
		svcDefaults := copyDefaultsMap(sysDefaults)
		for _, path := range yt.MatchingPaths(root, yt.NewPathPatternOk(svcPathExpr+"."+pathExpressionKeyDisjunction(defaultablePolicyKeys...))) {
			svcDefaults[lastNodeKey(path)] = lastNode(path)
		}

		// Apply defaults in each of this service's policies. Collect all the
		// policy path expressions first, since the paths themselves will change
		// as insertions are made in the node tree.
		polPathExprs := []string{}
		for _, path := range yt.MatchingPaths(root, yt.NewPathPatternOk(svcPathExpr+".policies[*]")) {
			polPathExprs = append(polPathExprs, yt.PathExpressionOk(path))
		}
		for _, polPathExpr := range polPathExprs {
			polNode := lastNode(yt.MatchingPaths(root, yt.NewPathPatternOk(polPathExpr))[0])

			// Add key/value pairs to the tree for any defaulted (and defaultable)
			// policy-level keys.
			newPolValues := map[string]yt.Node{}
			for _, key := range defaultablePolicyKeys {
				if len(yt.MatchingPaths(root, yt.NewPathPatternOk(polPathExpr+"."+yt.QuoteKeyMeta(key)))) == 0 {
					if node, exists := svcDefaults[key]; exists {
						newPolValues[key] = node
					}
				}
			}
			root, _ = yt.AddNodesToMapping(root, polNode, newPolValues, polNode)
		}
	}

	// Apply defaults in any subsystems of this system.
	root, err := applyDefaultsInAllSystems(root, sysPathExpr, hierarchy, sysDefaults)
	if err != nil {
		return nil, err
	}

	// Remove any defaults block from this system.
	if paths := yt.MatchingPaths(root, yt.NewPathPatternOk(sysPathExpr+".defaults.*")); len(paths) != 0 {
		root, _ = yt.RemoveNode(root, lastNode(paths[0]))
	}

	// Remove any "implicit" default definitions from this system's services.
	for {
		pathExpr := sysPathExpr + ".components.*." + pathExpressionKeyDisjunction(defaultablePolicyKeys...)
		if paths := yt.MatchingPaths(root, yt.NewPathPatternOk(pathExpr)); len(paths) != 0 {
			root, _ = yt.RemoveNode(root, lastNode(paths[0]))
		} else {
			break
		}
	}

	return root, nil
}

// Returns a shallow copy of a defaults map.
func copyDefaultsMap(defaults map[string]yt.Node) map[string]yt.Node {
	defaultsCopy := make(map[string]yt.Node, len(defaults))
	for k, v := range defaults {
		defaultsCopy[k] = v
	}
	return defaultsCopy
}
