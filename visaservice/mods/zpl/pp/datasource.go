package pp

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"zpr.org/vsx/snio/zds"
)

// DataSourceProxy defines an interface for querying external data sources for
// information needed to evaluate dynamic assertions, i.e., standard-language
// assertions with count predicates or internal-language assertions that invoke
// the permitted_access_count function. Each DataSourceProxy interacts with one
// data source.
type DataSourceProxy interface {
	// ActorIds returns the IDs of all actors whose attributes satisfy a set of
	// expressions according to the data source. An actor's ID is included in
	// the returned slice if and only if its attributes satisfy all of the
	// expressions in attrExprs. Actor IDs are expected to be unique across all
	// data sources in a ZPR network. A nil slice and a non-nil error are
	// returned if the actor query fails.
	//
	// TODO: Should take a context
	ActorIds(attrExprs []AttributeExpression) ([]string, error)
}

// A DataSourceProxy implementation that wraps another DataSourceProxy and
// provides local query result caching. The cache is extremely simple: it
// never evicts and is not thread-safe. Instances are intended to be discarded
// after being used to evaluate a batch of assertions.
type cachingDataSourceProxy struct {
	proxy DataSourceProxy     // wrapped proxy
	cache map[string][]string // attrExprs -> IDs
}

type DSProxImpl struct {
	desc *DSDesc
}

// DSDesc is a datasource descriptor.
type DSDesc struct {
	Prefix   string
	TLSCert  credentials.TransportCredentials // loaded from cert
	certPath string
	DNSName  string // from cert
	Addr     net.IP
	Port     uint16
}

// ParseDSDesc parse the string format.
// The format is <PREFIX>:<KEY_PATH>@<ADDR>:<PORT>
func ParseDSDesc(dsd string) (*DSDesc, error) {
	ab := strings.Split(dsd, "@")
	if len(ab) != 2 {
		return nil, fmt.Errorf("unparseable: %v", dsd)
	}
	pk := strings.Split(ab[0], ":")
	if len(pk) != 2 {
		return nil, fmt.Errorf("should start with <PREFIX>:<KEYPATH>: %v", dsd)
	}
	desc := &DSDesc{
		Prefix:   strings.TrimSpace(pk[0]),
		certPath: strings.TrimSpace(pk[1]),
	}

	creds, err := credentials.NewClientTLSFromFile(desc.certPath, "")
	if err != nil {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}
	dsname, err := getDNSNameFromCert(desc.certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to extract DNS name from cert: %w", err)
	}
	desc.DNSName = dsname
	if err := creds.OverrideServerName(dsname); err != nil {
		return nil, fmt.Errorf("failed to override servername: %w", err)
	}
	desc.TLSCert = creds

	hostname, portnum, err := net.SplitHostPort(ab[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse <HOST>:<PORT>: %w", err)
	}
	if strings.Contains(hostname, ".") || strings.Contains(hostname, ":") {
		desc.Addr = net.ParseIP(hostname)
	} else {
		if addrs, err := net.DefaultResolver.LookupHost(context.Background(), hostname); err != nil {
			return nil, fmt.Errorf("failed to resolve hostname: %w", err)
		} else {
			desc.Addr = net.ParseIP(addrs[0]) // if there are other addresses, they are ignored.
		}
	}
	if desc.Addr.IsUnspecified() {
		return nil, fmt.Errorf("failed to resolve data source host: %v", dsd)
	}
	if pn, err := strconv.Atoi(portnum); err != nil {
		return nil, fmt.Errorf("invalid port: %v", dsd)
	} else {
		desc.Port = uint16(pn)
	}
	return desc, nil
}

func (d *DSDesc) String() string {
	return fmt.Sprintf("%v:%v@%v:%v", d.Prefix, d.certPath, d.Addr, d.Port)
}

// Extract the DNS/TLS name from the certificate.
// Copied from cmd/dsq/root.go
func getDNSNameFromCert(certfile string) (string, error) {
	pembuf, err := os.ReadFile(certfile)
	if err != nil {
		return "", fmt.Errorf("cert read error: %w", err)
	}
	derblk, _ := pem.Decode(pembuf)
	if derblk.Type != "CERTIFICATE" {
		return "", fmt.Errorf("expected a certifitcate, not %v", derblk.Type)
	}
	cdata, err := x509.ParseCertificate(derblk.Bytes)
	if err != nil {
		return "", fmt.Errorf("cert parse errorr: %w", err)
	}
	if len(cdata.DNSNames) < 1 {
		return "", errors.New("no DNS names found in cert")
	}
	return cdata.DNSNames[0], nil
}

// createDSProxies createst the DataSourceProxy impls from the descriptions.
// These are non-caching proxies.
func createDSProxies(dsds []*DSDesc) (map[string]DataSourceProxy, error) {
	proxies := make(map[string]DataSourceProxy)
	for _, dsd := range dsds {
		if _, ok := proxies[dsd.Prefix]; ok {
			return nil, fmt.Errorf("data source defined multiple times: %v", dsd.Prefix)
		}
		cli, err := newDSProxImpl(dsd)
		if err != nil {
			return nil, fmt.Errorf("failed to create data source client for %v: %w", dsd.Prefix, err)
		}
		proxies[dsd.Prefix] = cli
	}
	return proxies, nil
}

// Returns a new cachingDataSourceProxy implementation that wraps a given proxy.
func newCachingDataSourceProxy(proxy DataSourceProxy) DataSourceProxy {
	return &cachingDataSourceProxy{proxy, make(map[string][]string)}
}

func (p *cachingDataSourceProxy) ActorIds(attrExprs []AttributeExpression) ([]string, error) {
	// Build a cache key from the set of attribute expressions.
	exprStrings := make([]string, len(attrExprs))
	for i, expr := range attrExprs {
		exprStrings[i] = fmt.Sprintf("%s,%s,%s", expr.Name, expr.Operator, expr.Value)
	}
	sort.Strings(exprStrings)
	exprKey := strings.Join(exprStrings, "|")

	// Returned cached results if possible, else query the data source.
	if cachedVal, inCache := p.cache[exprKey]; inCache {
		return cachedVal, nil
	} else {
		if actorIds, err := p.proxy.ActorIds(attrExprs); err != nil {
			return nil, err
		} else {
			p.cache[exprKey] = actorIds
			return actorIds, nil
		}
	}
}

// newDSProxImpl "create" a DataSourceProxy implementation from a description.
// Really all you need is the description, but this is here in case we need to
// add more state.
func newDSProxImpl(dsd *DSDesc) (*DSProxImpl, error) {
	i := &DSProxImpl{
		desc: dsd,
	}
	return i, nil
}

// ActorIds implements DataSourceProxy.ActorIds.
//
// This will open a GRPC connection to the datasource and send a `DSatisfy` call.
//
// Note that the prefix has been stripped from the query. Is that OK? Does the caller
// ensure that only attributes for this data source are queried here?
func (ds *DSProxImpl) ActorIds(attrExprs []AttributeExpression) ([]string, error) {
	exp, err := convertAttrExpr(attrExprs)
	if err != nil {
		return nil, fmt.Errorf("invalid attribute expression: %w", err)
	}
	if len(exp) == 0 {
		return nil, fmt.Errorf("no attributes passed in actor-ids query") // programming error?
	}
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(ds.desc.TLSCert),
	}
	var cstr string
	if ds.desc.Addr.To16() != nil {
		cstr = fmt.Sprintf("[%v]:%d", ds.desc.Addr, ds.desc.Port)
	} else {
		cstr = fmt.Sprintf("%v:%d", ds.desc.Addr, ds.desc.Port)
	}
	conn, err := grpc.Dial(cstr, opts...)
	if err != nil {
		return nil, fmt.Errorf("connect to data source failed: %w", err)
	}
	cli := zds.NewZDSClient(conn)
	defer conn.Close()
	sreq := &zds.SatisfyRequest{
		QueryExp: exp,
	}
	resp, err := cli.DSatisfy(context.Background(), sreq)
	if err != nil {
		if e, ok := status.FromError(err); ok {
			switch e.Code() {
			case codes.Unimplemented:
				return nil, fmt.Errorf("DS functions not supported on %v: %v", ds.desc.Prefix, e.Message())
			default:
				return nil, fmt.Errorf("GRPC call failed with code %d and error: %v", e.Code(), e.Message())
			}
		}
		return nil, err
	}
	return resp.GetSubjects(), nil
}

// convertAttrExpr convert from the ds AttributeExpression form into
// the zds form of the same thing.
func convertAttrExpr(attrs []AttributeExpression) ([]*zds.AttributeExpression, error) {
	var exp []*zds.AttributeExpression
	for _, ae := range attrs {
		zae := &zds.AttributeExpression{
			Key: ae.Name,
			Val: ae.Value,
		}
		switch ae.Operator {
		case "eq":
			zae.Op = zds.AttributeExpression_EQ
		case "ne":
			zae.Op = zds.AttributeExpression_NEQ
		case "has":
			zae.Op = zds.AttributeExpression_HAS
		case "excludes":
			zae.Op = zds.AttributeExpression_EXCLUDES
		default:
			return nil, fmt.Errorf("invalid attribute operator passed: %v", ae.String())
		}
		exp = append(exp, zae)
	}
	return exp, nil
}
