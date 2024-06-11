package vsio

import (
	"fmt"
	"net"
	"strings"
)

func (a *Agent) ToString() string {
	var sb strings.Builder
	sb.WriteString("Agent{")
	sb.WriteString(fmt.Sprintf("authenticated:%v", a.Authenticated))
	sb.WriteString(fmt.Sprintf(", auth_addr: [%s]", net.IP(a.AuthAddr).String()))
	sb.WriteString(fmt.Sprintf(", tether_addr: [%s]", net.IP(a.TetherAddr).String()))
	sb.WriteString(", authed_claims: [")
	for k, v := range a.AuthClaims {
		sb.WriteString(fmt.Sprintf("%s=%s,", k, v.Cval)) // omitting expiration
	}
	sb.WriteString("], provides=[")
	sb.WriteString(strings.Join(a.Provides, ","))
	sb.WriteString("], auth_ids=[")
	sb.WriteString(strings.Join(a.AuthIds, ","))
	sb.WriteString("], auth_tokens=[")
	sb.WriteString(strings.Join(a.AuthTokens, ","))
	sb.WriteString("]")
	sb.WriteString(fmt.Sprintf(", auth_expires=%v", a.AuthExpires))
	sb.WriteString(", unsub_claims: [")
	for k, v := range a.UnsubClaims {
		sb.WriteString(fmt.Sprintf("%s=%s,", k, v))
	}
	sb.WriteString("]")
	sb.WriteString(fmt.Sprintf(", hashval=%s", a.Hashval))
	sb.WriteString(fmt.Sprintf(", ident=%s", a.Ident))
	sb.WriteString(fmt.Sprintf(", config_id=%d", a.ConfigId))
	sb.WriteString("}")
	return sb.String()
}
