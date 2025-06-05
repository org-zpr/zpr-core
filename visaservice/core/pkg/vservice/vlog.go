package vservice

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	snip "zpr.org/vs/pkg/ip"
	"zpr.org/vs/pkg/libvisa"
	"zpr.org/vsapi"
)

type Vlog struct {
	out io.WriteCloser
}

func NewVlogToFile(fname string) (*Vlog, error) {
	fout, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	fout.Write([]byte(fmt.Sprintf("\n# log started %s\n\n", time.Now().Format(time.RFC3339))))
	return &Vlog{out: fout}, nil
}

func NewVlog(out io.WriteCloser) *Vlog {
	return &Vlog{out: out}
}

func (v *Vlog) Close() error {
	return v.out.Close()
}

func (v *Vlog) LogVisaCreated(visa *vsapi.Visa, pkt *snip.Traffic, explainer string, requestor netip.Addr) {
	entry := newPermit(visa, pkt, explainer, requestor)
	v.out.Write([]byte(entry))
}

func (v *Vlog) LogVisaRevoked(visaId uint64, configId uint64) {
	var b strings.Builder

	b.WriteString(time.Now().Format(time.RFC3339))
	b.WriteString("  ")
	b.WriteString("REVOKE  ")
	fmt.Fprintf(&b, "c:%d  ", configId)
	fmt.Fprintf(&b, "id:%d\n\n", visaId)

	v.out.Write([]byte(b.String()))
}

func (v *Vlog) LogVisaDenied(configID uint64, pkt *snip.Traffic, reason string, requestor netip.Addr) {
	entry := newDeny(configID, pkt, reason, requestor)
	v.out.Write([]byte(entry))
}

func newPermit(visa *vsapi.Visa, pkt *snip.Traffic, explainer string, requestor netip.Addr) string {

	var b strings.Builder

	b.WriteString(time.Now().Format(time.RFC3339))
	b.WriteString("  ")
	b.WriteString("PERMIT  ")
	fmt.Fprintf(&b, "c:%d  ", visa.Configuration)
	fmt.Fprintf(&b, "id:%d\n", visa.IssuerID)

	fmt.Fprintf(&b, "   %s -> %s\n", net.IP(visa.SourceContact).String(), net.IP(visa.DestContact).String())

	exptime := libvisa.VToTime(visa.Expires)
	fmt.Fprintf(&b, "   %v exp %v (%v) [%v]\n", pkt.Flow(), exptime.Format(time.RFC3339), time.Until(exptime), explainer)

	fmt.Fprintf(&b, "   requestor %v\n\n", requestor)

	return b.String()
}

func newDeny(configID uint64, pkt *snip.Traffic, reason string, requestor netip.Addr) string {
	var b strings.Builder

	b.WriteString(time.Now().Format(time.RFC3339))
	b.WriteString("  ")
	b.WriteString("DENY    ")
	fmt.Fprintf(&b, "c:%d\n", configID)

	fmt.Fprintf(&b, "   %s -> %s\n", pkt.SrcAddr, pkt.DstAddr)
	fmt.Fprintf(&b, "   %v  \"%s\"\n", pkt.Flow(), reason)

	fmt.Fprintf(&b, "   requestor %v\n\n", requestor)

	return b.String()
}
