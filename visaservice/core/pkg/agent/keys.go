package agent

// Well known agent attribute keys in ZPR namespace
const (
	KAttrEPID               = "zpr.addr"                 // ZPR contact address (was Endpoint ID) required for nodes and services
	KAttrAuthority          = "zpr.authority"            // authority identifier
	KAttrConnectVia         = "zpr.connect_via"          // connect-via
	KAttrRole               = "zpr.role"                 // role, eg "node"
	KAttrVisaServiceAdapter = "zpr.visa_service_adapter" // true or false
	KAttrHash               = "zpr.hash"
	KAttrConfigID           = "zpr.config_id"
	KAttrCN                 = "zpr.adapter.cn"
)

const (
	KAttrAgentAuthority = "authority" // Agent requested authority
)
