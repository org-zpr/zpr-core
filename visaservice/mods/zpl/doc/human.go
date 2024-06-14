package doc

import (
	"fmt"
	"regexp"
	"strconv"
)

var (
	// Matches a nonnegative number. Generates no submatches.
	numRe = regexp.MustCompile(`(?:\d[\d_]*(?:\.(?:\d[\d_]*)?)?|\.\d[\d_]*)(?:[eE][+-]?\d[\d_]*)?`)

	// Matches a metrix prefix. Generates no submatches.
	pfxRe = regexp.MustCompile(`[kMGTPEZY]`)

	// Matches a time unit. Generates no submatches.
	tunitRe = regexp.MustCompile(`[smhd]`)

	// Matches a bandwidth_type value at start of input. Submatches: $1 = num, $2 = pfx, $3 = dunit
	bandwidthTypeRe = regexp.MustCompile(`^\s*(` + numRe.String() + `)(` + pfxRe.String() + `)?([bB])ps\b`)

	// Matches a capacity_type value at start of input. Submatches: $1 = dnum, $2 = pfx, $3 = dunit, $4 = tnum, $5 = tunit
	capacityTypeRe = regexp.MustCompile(`^\s*(` + numRe.String() + `)(` + pfxRe.String() + `)?([bB])/(` + numRe.String() + `)?(` + tunitRe.String() + `)\b`)

	// Matches a duration_type value at start of input. Submatches: $1 = tnum, $2 = tunit
	durationTypeRe = regexp.MustCompile(`^\s*(` + numRe.String() + `)(` + tunitRe.String() + `)\b`)

	// Metric prefix map: name -> multiplier.
	pfxMap = map[string]float64{"": 1, "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18, "Z": 1e21, "Y": 1e24}

	// Data unit map: name -> bits.
	dunitMap = map[string]float64{"b": 1, "B": 8}

	// Time unit map: name -> seconds.
	tunitMap = map[string]float64{"s": 1, "m": 60, "h": 60 * 60, "d": 24 * 60 * 60}
)

// ParseBandwidthType parses a ZPL bandwidth_type value. It expects the argument
// to be a string of the form <num><pfx><dunit>ps, where <num> is a nonnegative
// number, <pfx> is one of the standard metric prefixes k, M, G, etc., and
// <dunit> (data unit) is either B or b. It ignores any leading whitespace as
// well as any any text that follows the bandwidth_type value (e.g., a grouping
// key). It returns zero and a non-nil error on invalid syntax.
func ParseBandwidthType(s string) (float64, error) {
	if match := bandwidthTypeRe.FindStringSubmatch(s); match == nil {
		return 0, fmt.Errorf("not a valid bandwidth_type value (<number><prefix><dataunit>ps): %q", s)
	} else {
		dnum, pfx, dunit := match[1], match[2], match[3]
		if dnumf, err := parseFloat64(dnum); err != nil {
			return 0, fmt.Errorf("invalid magnitude in bandwidth_type: %w", err)
		} else {
			return dnumf * pfxMap[pfx] * dunitMap[dunit], nil
		}
	}
}

// ParseCapacityType parses a ZPL capacity_type value. It expects the argument
// to be a string of the form <num><pfx><dunit>/<num><tunit>, where <num> is a
// nonnegative number, <pfx> is one of the standard metric prefixes k, M, G,
// etc., <dunit> (data unit) is either B or b, and <tunit> (time unit) is s, m,
// h, or d. It ignores any leading whitespace as well as any any text that
// follows the capacity_type value (e.g., a grouping key). It returns zeros and
// a non-nil error on invalid syntax.
func ParseCapacityType(s string) (float64, float64, error) {
	if match := capacityTypeRe.FindStringSubmatch(s); match == nil {
		return 0, 0, fmt.Errorf("not a valid capacity_type value (<number><prefix><dataunit>/<number><timeunit>): %q", s)
	} else {
		dnum, pfx, dunit, tnum, tunit := match[1], match[2], match[3], match[4], match[5]
		if tnum == "" {
			tnum = "1"
		}
		if dnumf, err := parseFloat64(dnum); err != nil {
			return 0, 0, fmt.Errorf("invalid data magnitude in capacity_type: %w", err)
		} else if tnumf, err := parseFloat64(tnum); err != nil {
			return 0, 0, fmt.Errorf("invalid time magnitude in capacity_type: %w", err)
		} else {
			return dnumf * pfxMap[pfx] * dunitMap[dunit], tnumf * tunitMap[tunit], nil
		}
	}
}

// ParseDurationType parses a ZPL duration_type value. It expects the argument
// to be a string of the form <num><tunit>, where <num> is a nonnegative number
// and <tunit> is s, m, h, or d. It ignores any leading whites[ace as well as
// any text that follows the duration_type (e.g., a grouping key). It returns
// zero and a non-nil error on invalid syntax.
func ParseDurationType(s string) (float64, error) {
	if match := durationTypeRe.FindStringSubmatch(s); match == nil {
		return 0, fmt.Errorf("not a valid duration_type value (<number><timeunit>): %q", s)
	} else {
		tnum, tunit := match[1], match[2]
		if tnumf, err := parseFloat64(tnum); err != nil {
			return 0, fmt.Errorf("invalid magnitude in duration_type: %w", err)
		} else {
			return tnumf * tunitMap[tunit], nil
		}
	}
}

func parseFloat64(s string) (float64, error) {
	if f, err := strconv.ParseFloat(s, 64); err != nil {
		return 0, fmt.Errorf("%w: %s", err.(*strconv.NumError).Err, s)
	} else {
		return f, nil
	}
}
