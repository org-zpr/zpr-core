package compiler

import (
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"zpr.org/vsx/polio"
	"zpr.org/vsx/zpl/doc"
)

// setCerts copies certificates into the policy.
func (c *Compilation) setCerts(d *doc.Doc) error {
	if err := c.setInternalCerts(d); err != nil {
		return err
	}
	return c.setExternalCerts(d)
}

// TODO: This only works for global ZPR datasources.
func (c *Compilation) setExternalCerts(d *doc.Doc) error {
	var pending []*doc.System
	var cur *doc.System
	for _, k := range sortedSystemsMapKeys(d.Communications.Systems) {
		ss, _ := d.Communications.Systems[k]
		pending = append(pending, ss)
	}
	for len(pending) > 0 {
		cur, pending = pending[0], pending[1:]
		if cur.Systems != nil {
			for _, k := range sortedSystemsMapKeys(cur.Systems) {
				ss := cur.Systems[k]
				pending = append(pending, ss)
			}
		}
		for _, k := range sortedComponentsMapKeys(cur.Components) {
			svc, _ := cur.Components[k]
			if pfx := svc.Auth.String(); pfx != "" {
				ds := d.Zpr.Datasources[pfx]
				if ds == nil {
					ds = d.Communications.NestedDatasources[pfx]
					if ds == nil {
						// Impossible I say!
						return doc.ZplScalarErrorf(svc.Auth, "auth service references unknown prefix")
					}
				}
				if ds.Endpoint != nil { // is external
					if ds.Endpoint.TlsCert == nil {
						return doc.ZplScalarErrorf(svc.ZplRef, "auth service with no certificate block: %v", svc.ID)
					}
					cdata, hexFp, err := loadCertAndFinger(ds.Endpoint.TlsCert)
					if err != nil {
						return doc.ZplScalarErrorf(svc.ZplRef, "cert processing failed for auth service %v: %w", svc.ID, err)
					}
					if err := c.AddUniqueKeyFingerprint(hexFp, fmt.Sprintf("key for datasource: %v", pfx)); err != nil {
						return doc.ZplScalarErrorf(ds.Endpoint.TlsCert.CertData, fmt.Sprintf("key violation: %v", err))
					}
					cert := &polio.Cert{
						ID:       uint32(len(c.policy.Certificates) + 1),
						Asn1Data: cdata,
						Name:     pfx,
					}
					c.infof("[certificate %d.%v] %v", cert.ID, cert.Name, hexFp)
					c.policy.Certificates = append(c.policy.Certificates, cert)
				}
			}
		}
	}
	return nil
}

func sortedSystemsMapKeys(m map[string]*doc.System) []string {
	keys := make([]string, 0, len(m))
	for k, _ := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedComponentsMapKeys(m map[string]*doc.Component) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// setInternalCerts loads up the certs (actually pretty sure there can be at most one)
// defined on "internal" type global ZPR datasources.
func (c *Compilation) setInternalCerts(d *doc.Doc) error {
	for pfx, ds := range d.Zpr.Datasources {
		if ds.Authority != nil {
			certdata, hexFp, err := loadCertAndFinger(ds.Authority)
			if err != nil {
				return doc.ZplScalarErrorf(ds.Authority.ZplRef, "failed to process cert: %w", err)
			}
			if err := c.AddUniqueKeyFingerprint(hexFp, fmt.Sprintf("key for datasource %v", pfx)); err != nil {
				return doc.ZplScalarErrorf(ds.Authority.CertData, fmt.Sprintf("key violation: %v", err))
			}
			cert := &polio.Cert{
				ID:       uint32(len(c.policy.Certificates) + 1),
				Asn1Data: certdata,
				Name:     pfx,
			}
			c.infof("[certificate %d.%v] %v", cert.ID, cert.Name, hexFp)
			c.policy.Certificates = append(c.policy.Certificates, cert)
		}
	}
	return nil
}

func loadCertAndFinger(cb *doc.Certificate) ([]byte, string, error) {
	certdata, err := loadCertificate(cb)
	if err != nil {
		return nil, "", err
	}
	fp, err := sha1Fingerprint(certdata)
	if err != nil {
		return nil, "", doc.ZplScalarErrorf(cb.ZplRef, "failed to fingerprint cert: %w", err)
	}
	return certdata, fp, nil
}

func loadCertificate(cb *doc.Certificate) ([]byte, error) {
	if strings.ToLower(cb.Encoding.String()) != "pem" {
		return nil, doc.ZplScalarErrorf(cb.Encoding, "unsupported certificate encoding: %v", cb.Encoding)
	} else if blk, _ := pem.Decode([]byte(linePadRe.ReplaceAllString(cb.CertData.String(), ""))); blk == nil {
		return nil, doc.ZplScalarErrorf(cb.CertData, "pem decode of certificate failed")
	} else {
		return blk.Bytes, nil
	}
}

var (
	linePadRe = regexp.MustCompile(`(?m)(^\s+|\s+$)`) // space at starts and ends of lines
)

func sha1Fingerprint(asn1data []byte) (string, error) {
	cert, err := x509.ParseCertificate(asn1data)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %v", err)
	}
	fbuf := sha1.Sum(cert.Raw)
	return hex.EncodeToString(fbuf[:]), nil
}
