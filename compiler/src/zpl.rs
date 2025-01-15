pub const DEF_CLASS_SERVICE_NAME: &str = "service";
pub const DEF_CLASS_SERVICE_AKA: &str = "services";
pub const DEF_CLASS_USER_NAME: &str = "user";
pub const DEF_CLASS_USER_AKA: &str = "users";
pub const DEF_CLASS_ENDPOINT_NAME: &str = "endpoint";
pub const DEF_CLASS_ENDPOINT_AKA: &str = "endpoints";

pub const DEFAULT_TRUSTED_SERVICE_ID: &str = "default";
pub const DEFAULT_TRUSTED_SERVICE_API: &str = "validation/1";

pub const ICMP_INTERACION_REQUEST_RESPONSE: &str = "request-response";
pub const ICMP_INTERACTION_ONESHOT: &str = "oneshot";

pub const VISA_SERVICE_CN: &str = "vs.zpr";
pub const ZPR_ADDR_ATTR: &str = "zpr.addr";

pub const DEFAULT_TS_PREFIX: &str = "zpr.adapter";
pub const DEFAULT_ATTR: &str = "cn";
pub const ADAPTER_CN_ATTR: &str = "zpr.adapter.cn";

// TODO: Check this is ok. I think in prototype is it '/zpr/$$zpr/visaservice'.  But that seems odd.
pub const VS_SERVICE_NAME: &str = "/zpr/visaservice";

pub const KATTR_ROLE: &str = "role";

// For nodes to talk to VS
pub const VISA_SERVICE_PORT: u16 = 5002; // TCP

// For VS to talk to nodes
pub const VISA_SUPPORT_SEVICE_PORT: u16 = 8183; // TCP

// For admin to control the visa service (eg, install a policy)
#[allow(dead_code)]
pub const VISA_SERVICE_ADMIN_PORT: u16 = 8182; // TCP