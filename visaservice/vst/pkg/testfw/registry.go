package testfw

import "strings"

var Registry = make(map[string]Tester)

func Register(t Tester) {
	Registry[t.Name()] = t
}

func ParseTestName(name string) (Tester, bool) {
	name = strings.ToLower(name)
	for k, t := range Registry {
		if strings.ToLower(k) == name {
			return t, true
		}
	}
	return nil, false
}

func TestNames() []string {
	var names []string
	for k := range Registry {
		names = append(names, k)
	}
	return names
}

func AllTests() []Tester {
	var tests []Tester
	for _, t := range Registry {
		tests = append(tests, t)
	}
	return tests
}
