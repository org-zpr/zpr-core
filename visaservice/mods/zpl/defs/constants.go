package defs

// Well known attribute names.
const (
	KAttrRole       = "zpr.role"
	KAttrEPID       = "zpr.addr"
	KAttrAuthority  = "zpr.authority"
	KAttrConnectVia = "zpr.connect_via"
)

const (
	DefaultPMCTLPort              = 8182 // TCP
	DefaultVisaServiceAddress     = "fd5a:5052::1"
	DefaultVisaSupportServicePort = 8183 // TCP
	DefaultVisaServicePort        = 5002 // TCP
	DefaultTetherBaseAddress      = "fc00:3002::0"
	DefaultCredIDBaseAddress      = "fc00:3001::0"
)

const (
	ProtocolICMP6 uint8 = 58
	ProtocolTCP   uint8 = 0x6
	ProtocolUDP   uint8 = 0x11
)

const (
	VisaServiceName          = "$$zpr/visaservice"
	SerialVersion            = 42
	ConfKeyCIDR              = "cidr"
	NoProc                   = uint32(0xFFFFFFFF)
	CKMaxVisaLifetimeSeconds = uint32(1)
)
