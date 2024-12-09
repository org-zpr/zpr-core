package doc

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

const (
	SystemsReservedWords = "hierarchy name desc defines defaults asserts services"
	NoiseKeyLen          = 32 // bytes
)

var (
	IDTypeRegex         = regexp.MustCompile(`^[A-Za-z0-9_\\.]+$`)
	HierarchyTypeRegex  = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	DefineTypeRegex     = regexp.MustCompile(`^[A-Za-z0-9_\.\-\:]+$`)
	AuthPrefixTypeRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_\.\-\:]+$`)
	IPv4TypeRegex       = regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1-3}`)
	PortTypeSingleRegex = regexp.MustCompile(`\d{1,5}`)
	PortTypeRangeRegex  = regexp.MustCompile(`\d{1,5}\-\d{1,5}`)
	HostnameRegex       = regexp.MustCompile(`^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$`)
	AttrOpRegex         = regexp.MustCompile(`^(` + strings.Join(AllAttrExprOps(), `|`) + `)$`) // (assumes no regex metas in op strings)
)

var (
	ErrPortSpecNumOutOfRange = errors.New("port-spec value out of range")
	ErrInvalidPortRange      = errors.New("invalid port-spec range")
)

type PortRange struct {
	Min int // exclusive
	Max int // inclusive
}

var RangeTcpUdp = PortRange{0, 65535}
var RangeICMP = PortRange{-1, 255}

func AssertValidID(id string) error {
	if !IDTypeRegex.MatchString(id) {
		return fmt.Errorf("invalid ID type: '%v'", id)
	}
	return nil
}

func AssertValidRevision(rev string) error {
	if !IDTypeRegex.MatchString(rev) {
		return fmt.Errorf("invalid revision value: '%v'", rev)
	}
	return nil
}

func AssertValidHierarchy(term string) error {
	if !HierarchyTypeRegex.MatchString(term) {
		return fmt.Errorf("invalid value for hierarchy: '%v'", term)
	}
	if strings.Contains(SystemsReservedWords, term) {
		return fmt.Errorf("invalid hierarchy name; is reserved word: %v", term)
	}
	return nil
}

func AssertValidDefine(defname string) error {
	if !DefineTypeRegex.MatchString(defname) {
		return fmt.Errorf("invalid value for a define name: '%v'", defname)
	}
	return nil
}

func AssertPositiveInteger(n int, desc string) error {
	if n <= 0 {
		return fmt.Errorf("%v must be a positive integer", desc)
	}
	return nil
}

func AssertValidIPv6CIDR(cidr string) error {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("not an IPv6 CIDR: %v", err)
	}
	if ip.To4() != nil {
		return fmt.Errorf("must be an IPv6 network")
	}
	return nil
}

func AssertValidAttrExpr(e *AttrExpr) error {
	if e == nil {
		return fmt.Errorf("nil attribute expression")
	}
	if e.Key.Value() == nil {
		return fmt.Errorf("missing attribute expression key")
	}
	if e.Op.Value() == nil {
		return fmt.Errorf("missing attribute expression operator")
	} else if !AttrOpRegex.MatchString(e.Op.String()) {
		return fmt.Errorf("invalid attribute expression operator: %q", e.Op.String())
	}
	if e.Value.Value() == nil {
		return fmt.Errorf("missing attribute expression value")
	}
	return nil
}

func AssertValidAuthPrefix(p string) error {
	if p == "" {
		return fmt.Errorf("auth prefix must not be empty")
	}
	if !AuthPrefixTypeRegex.MatchString(p) {
		return fmt.Errorf("invalid value for an auth prefix: '%v'", p)
	}
	return nil
}

// AssertValidNetAddr checks for HOST:PORT
func AssertValidNetAddr(a string) error {
	h, p, err := net.SplitHostPort(a)
	if err != nil {
		return err
	}
	if port, err := strconv.Atoi(p); err != nil {
		return fmt.Errorf("invalid port: %w", err)
	} else {
		if port < 0 || port > 65535 {
			return fmt.Errorf("invalid port: %d", port)
		}
	}
	return AssertValidHostRef(h)
}

// AssertValidHostRef accepts strings that are IPv4 addresses, or hostnames
func AssertValidHostRef(h string) error {
	if IPv4TypeRegex.MatchString(h) {
		ip4 := net.ParseIP(h)
		if ip4 == nil || ip4.IsUnspecified() {
			return fmt.Errorf("not a valid IPv4 address: '%v'", h)
		}
		return nil
	}
	// We do not check the hostname very thoroughly here
	if h == "" {
		return fmt.Errorf("hostname/address must not be empty")
	}
	return nil
}

// AssertValidPortType checks for the ZPL port type which is:
// a port number, a range of port numbers N-M, or a comma separated list of either.
func AssertValidTcpUdpPortType(p string) error {
	return assertValidPortSpecType(p, RangeTcpUdp)
}

func AssertValidIcmpType(p string) error {
	return assertValidPortSpecType(p, RangeICMP)
}

func assertValidPortSpecType(p string, r PortRange) error {
	if p == "" {
		return fmt.Errorf("port spec cannot be empty")
	}
	for _, atom := range strings.Split(p, ",") {
		atom = strings.TrimSpace(atom)
		if PortTypeRangeRegex.MatchString(atom) {
			ports := strings.Split(atom, "-")
			low, err := strconv.Atoi(strings.TrimSpace(ports[0]))
			if err != nil {
				return err
			}
			high, err := strconv.Atoi(strings.TrimSpace(ports[1]))
			if err != nil {
				return err
			}
			for _, pn := range []int{low, high} {
				if pn <= r.Min || pn > r.Max {
					return ErrPortSpecNumOutOfRange
				}
			}
			if high < low {
				return ErrInvalidPortRange
			}
			continue
		}
		if PortTypeSingleRegex.MatchString(atom) {
			if pn, err := strconv.Atoi(atom); err != nil {
				return err
			} else {
				if pn <= r.Min || pn > r.Max {
					return ErrPortSpecNumOutOfRange
				}
			}
			continue
		}
		return fmt.Errorf("invalid port-type string: '%v'", p)
	}
	return nil
}

// AssertValidZPRADdress checks for IPv6 address or a hostname.
func AssertValidZPRAddress(a string) error {
	if strings.Index(a, ":") > 0 {
		ip := net.ParseIP(a)
		if ip == nil {
			return fmt.Errorf("not an IPv6 address: '%v'", a)
		}
		// If it is really an IPv6 address, it won't convert to 4 bytes.
		if ip.To4() != nil {
			return fmt.Errorf("not an IPv6 address: '%v'", a)
		}
		return nil
	}
	if HostnameRegex.MatchString(a) {
		return nil
	}
	return fmt.Errorf("invalid ZPR address: %v", a)
}

// AssertValidDSAPISpec checks the datasource API spec value to ensure it is
// valid.  Valid format is <API_NAME>/<VERSION>[;<DSAPI_SPEC>[;...]]
func AssertValidDSAPISpec(s string) error {
	specs := strings.Split(s, ";")
	if len(specs) > 2 {
		// Only allow two declarations
		return fmt.Errorf("datasource API spec can have at most two declarations, found %d", len(specs))
	}
	for _, spec := range specs {
		if !strings.Contains(spec, "/") {
			return fmt.Errorf("missing '/<VERSION>'")
		}
		namver := strings.Split(spec, "/")
		if len(namver) != 2 {
			return fmt.Errorf("datasource API spec part must be of form API_NAME/VERSION")
		}
		switch strings.TrimSpace(namver[0]) {
		case "validation", "query": // ok
		default:
			return fmt.Errorf("not a valid datasource API name: %v", namver[0])
		}
		if n, err := strconv.Atoi(strings.TrimSpace(namver[1])); err != nil || n <= 0 {
			return fmt.Errorf("datasource api version must be a positive integer, not: %v", namver[1])
		}
	}
	return nil
}

func AssertValidNoisePK(pkhex string) error {
	pkhex = strings.TrimSpace(pkhex)
	if len(pkhex) != NoiseKeyLen*2 {
		return fmt.Errorf("noise PK hex string is too short, must be exactly %d characters", NoiseKeyLen*2)
	}
	pk, err := hex.DecodeString(pkhex)
	if err != nil {
		return fmt.Errorf("noise PK not valid HEX string: %w", err)
	}
	if len(pk) != NoiseKeyLen {
		return fmt.Errorf("noise PK not %d bytes", NoiseKeyLen)
	}
	return nil
}
