package libvisa

type ExpFlag uint8 // Visa expiration derivation indicators

const (
	ExpFBump        ExpFlag = 1 << iota // .... ...B    reauth bump time was added
	ExpFJitter                          // .... ..J.    jitter was added
	ExpFDataCap                         // .... .T..    limited by data cap time range
	ExpFPolicy                          // .... C...    limited by policy constraint
	ExpFMaxLifetime                     // ...P ....    limited by policy max visa lifetime
	ExpFDestCreds                       // ..D. ....    limited by destination creds expiration
	ExpFSrcCreds                        // .S.. ....    limited by source creds expiration
	ExpFMinDur                          // M... ....    min duration override
)

func (x ExpFlag) String() string {
	expl := []byte("MSDPCTJB")
	for i, mask := range []ExpFlag{ExpFMinDur, ExpFSrcCreds, ExpFDestCreds, ExpFMaxLifetime, ExpFPolicy, ExpFDataCap, ExpFJitter, ExpFBump} {
		if x&mask == 0 {
			expl[i] = '.' // unset
		}
	}
	return string(expl)
}

// explainBigEndian return description of flag at bit offset `i` in Big Endian order
func ExplainBigEndian(i uint8) string {
	switch i {
	case 0:
		return "override by [M]in duration setting"
	case 1:
		return "limited by [S]ource credentials expiration"
	case 2:
		return "limited by [D]estination credentials expiration"
	case 3:
		return "limited by policy [M]ax visa lifetime"
	case 4:
		return "limited by policy [C]onstraint"
	case 5:
		return "limited by data cap [T]ime range"
	case 6:
		return "[J]itter was added"
	case 7:
		return "reauth [B]ump time was added"
	default:
		return "unknown"
	}
}
