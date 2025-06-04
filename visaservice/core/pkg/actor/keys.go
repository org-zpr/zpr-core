package actor

// Well known actor attribute keys in ZPR namespace
const (
	KAttrEPID               = "zpr.addr"                 // ZPR contact address (was Endpoint ID) required for nodes and services
	KAttrAuthority          = "zpr.authority"            // authority identifier
	KAttrConnectVia         = "zpr.connect_via"          // connect-via
	KAttrRole               = "zpr.role"                 // role, eg "node"
	KAttrVisaServiceAdapter = "zpr.visa_service_adapter" // true or false
	KAttrHash               = "zpr.hash"
	KAttrConfigID           = "zpr.config_id"
	KAttrCN                 = "device.zpr.adapter.cn"
)

const (
	KAttrActorAuthority = "authority" // Actor requested authority
)

type Namespace int

const (
	NsUser Namespace = iota + 1
	NsDevice
	NsService
)

func (n Namespace) String() string {
	switch n {
	case NsUser:
		return "user"
	case NsDevice:
		return "device"
	case NsService:
		return "service"
	default:
		return "unknown"
	}
}

func ParseNamespace(s string) (Namespace, bool) {
	switch s {
	case "user":
		return NsUser, true
	case "device":
		return NsDevice, true
	case "service":
		return NsService, true
	default:
		return 0, false
	}
}
