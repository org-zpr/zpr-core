pub const DEF_CLASS_SERVICE_NAME: &str = "service";
pub const DEF_CLASS_SERVICE_AKA: &str = "services";

pub const DEF_CLASS_USER_NAME: &str = "user";
pub const DEF_CLASS_USER_AKA: &str = "users";

pub const DEF_CLASS_DEVICE_NAME: &str = "device";
pub const DEF_CLASS_DEVICE_AKA: &str = "devices";

pub const DEFAULT_TRUSTED_SERVICE_ID: &str = "default";
pub const DEFAULT_TRUSTED_SERVICE_API: &str = "validation/1";

pub const ICMP_INTERACION_REQUEST_RESPONSE: &str = "request-response";
pub const ICMP_INTERACTION_ONESHOT: &str = "oneshot";

pub const VISA_SERVICE_CN: &str = "vs.zpr";
pub const ZPR_ADDR_ATTR: &str = "zpr.addr";

pub const DEFAULT_TS_PREFIX: &str = "zpr.adapter";
pub const DEFAULT_ATTR: &str = "cn";
pub const ADAPTER_CN_ATTR: &str = "zpr.adapter.cn";

// TODO: What is up with this odd name? Why not '/zpr/visaservice'?
pub const VS_SERVICE_NAME: &str = "/zpr/$$zpr/visaservice";

pub const KATTR_ROLE: &str = "zpr.role";

// For nodes to talk to VS
pub const VISA_SERVICE_PORT: u16 = 5002; // TCP

// For VS to talk to nodes
pub const VISA_SUPPORT_SEVICE_PORT: u16 = 8183; // TCP

// For admin to control the visa service (eg, install a policy)
#[allow(dead_code)]
pub const VISA_SERVICE_ADMIN_PORT: u16 = 8182; // TCP

// Only known config setting (see policy.proto)
pub const CONFIG_KEY_MAX_VISA_LIFETIME: u32 = 1; // value is time in seconds
