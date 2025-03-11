package testfw

import (
	"sort"
	"strings"
)

type Registration struct {
	test  Tester
	order Order
}

var Registry = make(map[string]*Registration)

func Register(t Tester) {
	Registry[t.Name()] = &Registration{test: t, order: t.Order()}
}

func ParseTestName(name string) (Tester, bool) {
	name = strings.ToLower(name)
	for k, t := range Registry {
		if strings.ToLower(k) == name {
			return t.test, true
		}
	}
	return nil, false
}

// Not in order
func TestNames() []string {
	var names []string
	for k := range Registry {
		names = append(names, k)
	}
	return names
}

func AllTests() []Tester {
	var entries []*Registration
	for _, r := range Registry {
		entries = append(entries, r)
	}
	// Sort by order
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].order < entries[j].order
	})
	var tests []Tester
	for _, t := range entries {
		tests = append(tests, t.test)
	}
	return tests
}
