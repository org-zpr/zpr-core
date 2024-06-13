package ip

// Ported from snpb/ip/endpoint.

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// A bunch of overwrought cruft for dealing with strings and structs that
// specify a protcol and a port.  Eg, "tcp/80".

// endpointStr format is "tcp/80"
type EndpointStr string

type Endpoint struct {
	Protocol Protocol
	Port     uint16
}

func NewEndpoint(prot Protocol, port uint16) *Endpoint {
	return &Endpoint{
		Protocol: prot,
		Port:     port,
	}
}

// ParseEndpoint parses string like "tcp/80" into an Endpoint struct.
func ParseEndpoint(s string) (*Endpoint, error) {
	eps, err := EndpointStrFromString(s)
	if err != nil {
		return nil, err
	}
	return endpointFromEndpointStr(eps), nil
}

func (e *Endpoint) Equal(other *Endpoint) bool {
	if e == nil && other == nil {
		return true
	}
	if other == nil {
		return false
	}
	return e.Protocol.Equal(other.Protocol) && e.Port == other.Port
}

func (e *Endpoint) String() string {
	// TODO: Should this return EndpointStr?
	return fmt.Sprintf("%v/%d", e.Protocol.String(), e.Port)
}

func (e *Endpoint) ToEndpointStr() EndpointStr {
	return EndpointStr(fmt.Sprintf("%v/%d", e.Protocol.String(), e.Port))
}

func (pp EndpointStr) Split() (string, int) {
	b := strings.Split(string(pp), "/")
	if len(b) != 2 {
		panic(fmt.Sprintf("not a valid ProtPort: %v", pp.String()))
	}
	prt, err := strconv.Atoi(b[1])
	if err != nil {
		panic(fmt.Sprintf("not a valid port: %v", pp.String()))
	}
	return b[0], prt
}

func (pp EndpointStr) Port() int {
	_, port := pp.Split()
	return port
}

func (pp EndpointStr) Proto() string {
	proto, _ := pp.Split()
	return proto
}

func (pp EndpointStr) String() string {
	return string(pp)
}

// EndpointStrFromString parse a string like "tcp/80" into the rather convoluted
// EndpointStr type. ICMP is allowed too, in that case the port number value is
// interpreted as a icmp message type.
func EndpointStrFromString(s string) (EndpointStr, error) {
	re := regexp.MustCompile(`(tcp|udp|icmp|icmp6)/(\d+)$`)
	matched := re.FindStringSubmatch(strings.ToLower(s))
	if matched == nil || len(matched) != 3 {
		return "", fmt.Errorf("invalid Prot/Port value: %v", s)
	}
	intArgName := "port"
	if strings.HasPrefix(strings.ToLower(matched[1]), "icmp") {
		intArgName = "messageType"
	}
	prt, err := strconv.Atoi(matched[2])
	if err != nil {
		return "", fmt.Errorf("invalid %s: %v", intArgName, s)
	}
	return NewEndpointStr(matched[1], prt)
}

func NewEndpointStr(prot string, port int) (EndpointStr, error) {
	protl := strings.ToLower(prot)
	switch protl {
	case "icmp", "icmp6":
		if port < 0 || port > 255 {
			return "", fmt.Errorf("message type out of range: %v", port)
		}
	case "tcp", "udp":
		if port < 0 || port > 65535 {
			return "", fmt.Errorf("port out of range: %v", port)
		}
	default:
		return "", fmt.Errorf("invalid protocol: %v", protl)
	}
	return EndpointStr(fmt.Sprintf("%v/%d", prot, port)), nil
}

func (pp EndpointStr) ToEndpoint() *Endpoint {
	return endpointFromEndpointStr(pp)
}

func endpointFromEndpointStr(pp EndpointStr) *Endpoint {
	prot, _ := ProtocolFromString(pp.Proto()) // note: error ignored
	return &Endpoint{
		Protocol: prot,
		Port:     uint16(pp.Port()),
	}
}
