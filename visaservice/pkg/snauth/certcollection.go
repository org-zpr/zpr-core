package snauth

import "crypto/x509"

type CertCollection struct {
	certs map[string]*x509.Certificate
}

func NewCertCollection() *CertCollection {
	return &CertCollection{
		certs: make(map[string]*x509.Certificate),
	}
}

func (cc *CertCollection) AddCert(name string, c *x509.Certificate) {
	cc.certs[name] = c
}

func (cc *CertCollection) CertFor(name string) *x509.Certificate {
	return cc.certs[name]
}

func (cc *CertCollection) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range cc.certs {
		pool.AddCert(c)
	}
	return pool
}

func (cc *CertCollection) List() []*x509.Certificate {
	var res []*x509.Certificate
	for _, c := range cc.certs {
		res = append(res, c)
	}
	return res
}
