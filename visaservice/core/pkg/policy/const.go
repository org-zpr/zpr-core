package policy

const (
	ContainerVersion = uint32(1121)
	SerialVersion    = 43 // Written to pol.Policy.SerialVersion
	ConfKeyCIDR      = "cidr"
	NoProc           = uint32(0xFFFFFFFF)
	NoHash           = uint32(0xFFFFFFFF)
	AuthProtocol     = 0x6   // TCP (gRPC protocol to auth services)
	AuthProtocolName = "TCP" // TCP (gRPC protocol to auth services)
)

const (
	VisaServiceName = "$$zpr/visaservice"
)
