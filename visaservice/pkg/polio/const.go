package polio

import (
	snip "zpr.org/vs/pkg/ip"
)

const (
	ContainerVersion = uint32(1121)
	SerialVersion    = 41 // Written to pol.Policy.SerialVersion
	ConfKeyCIDR      = "cidr"
	NoProc           = uint32(0xFFFFFFFF)
	NoHash           = uint32(0xFFFFFFFF)
	AuthProtocol     = snip.ProtocolTCP // gRPC protocol to auth services
)

const (
	VisaServiceName = "$$zpr/visaservice"
)
