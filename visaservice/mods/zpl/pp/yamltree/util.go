package yamltree

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Attempts to parse a string enclosed in single quotes from input beginning at
// byte offset pos. Recognizes single quote escaping by doubling. On success
// returns the text within the outermost quotes (with any escaping removed) and
// the total number of bytes processed from the input (including the outermost
// quotes). Returns an empty string and zero if the first character in input is
// not a single quote. Returns an error if no matching quote is found in input.
func parseSingleQuoteString(input string, pos int) (string, int, error) {
	// It's safe to step through bytes since the special one we need to check
	// for (single quote) can never occur within a multi-byte UTF-8 code point.
	if pos < len(input) && input[pos] == '\'' {
		content := strings.Builder{}
		for i := pos + 1; i < len(input); {
			switch b := input[i]; b {
			case '\'':
				if i < len(input)-1 && input[i+1] == '\'' {
					content.WriteByte(b)
					i += 2
				} else {
					return content.String(), i + 1 - pos, nil
				}
			default:
				content.WriteByte(b)
				i++
			}
		}
		return "", 0, fmt.Errorf("no matching single quote: %s", snippet(input, pos, 20))
	}
	return "", 0, nil
}

// Attempts to parse a string enclosed in double quotes from input beginning at
// byte offset pos. Recognizes simple backslash escaping: a backslash preceding
// any character means that character. On sucess returns the text within the
// outermost quotes (with any escaping removed) and the total number of bytes
// processed from the input (including the outermost quotes). Returns an empty
// string and zero if the first character in input is not a double quote.
// Returns an error if no matching quote is found in input or if an incomplete
// escape sequence is found.
func parseDoubleQuoteString(input string, pos int) (string, int, error) {
	// It's safe to step through bytes since the special ones we need to check
	// for ('"', '\') can never occur within a multi-byte UTF-8 code point.
	if pos < len(input) && input[pos] == '"' {
		content := strings.Builder{}
		for i := pos + 1; i < len(input); {
			switch b := input[i]; b {
			case '"':
				return content.String(), i + 1 - pos, nil
			case '\\':
				if i >= len(input)-1 {
					return "", 0, fmt.Errorf("incomplete escape sequence")
				}
				content.WriteByte(input[i+1])
				i += 2
			default:
				content.WriteByte(b)
				i++
			}
		}
		return "", 0, fmt.Errorf("no matching double quote: %s", snippet(input, pos, 20))
	}
	return "", 0, nil
}

// Returns part of the input string beginning at the specified byte offset.
// Prepends "..." if offset > 0, and truncates and appends "..." as needed
// to make the result fit contain no more than maxWidth characters. Panics
// if maxWidth is too small to fit any characters from input into the output.
func snippet(input string, offset int, maxWidth int) string {
	text := input[offset:]
	var textCharsToInclude int
	if offset == 0 {
		if len(text) <= maxWidth {
			textCharsToInclude = len(text)
		} else {
			textCharsToInclude = maxWidth - 3
		}
	} else {
		if len(text) <= maxWidth-3 {
			textCharsToInclude = len(text)
		} else {
			textCharsToInclude = maxWidth - 6
		}
	}
	if textCharsToInclude < 0 {
		panic("not enough room for snippet!")
	}

	chars := []rune{}
	if offset > 0 {
		chars = append(chars, '.', '.', '.')
	}

	for i, w := 0, 0; i < textCharsToInclude; i += w {
		char, width := utf8.DecodeRuneInString(text[i:])
		chars = append(chars, char)
		w = width
	}

	if textCharsToInclude < len(text) {
		chars = append(chars, '.', '.', '.')
	}

	return string(chars)
}
