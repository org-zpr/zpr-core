package tsapi

// This "protocol" module contains defintiions that used to be defined in
// protocol buffers for the old gRPC data source APIs.

type Challenge struct {
	Spec      string
	Timestamp string
	Nonce     []byte
	Data      []byte
}

type RawChallengeResp struct {
	Data []byte
}

type U2FChallengeResp struct {
	SigR    []byte
	SigS    []byte
	Counter uint32
}

type ChallengeResponse struct {
	ChalSpec    string
	RespSpec    string
	NonceOffset uint32
	NonceLen    uint32
	Result      interface{} // is-a RawChalResp or a U2FChalResp
	Certificate []byte
}

type Attribute struct {
	Key string
	Val string
	Exp int64 // unix time seconds
}

type QueryResponse struct {
	Attrs []*Attribute
	Ttl   uint32 // seconds
}

func (qr *QueryResponse) GetAttrs() []*Attribute {
	return qr.Attrs
}

type QueryRequest struct {
	TokenList [][]byte // list of JWT tokens
	AttrKeys  []string
}
