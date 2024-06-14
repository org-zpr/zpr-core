package yamltree

// This file contains definitions that make some unexported functions available
// to testing code. (It declares the main package, not the test package, but
// its filename should end in "_test.go", which should exclude it from package
// builds.)

var (
	ParseSingleQuoteString = parseSingleQuoteString
	ParseDoubleQuoteString = parseDoubleQuoteString
	Snippet                = snippet
)
