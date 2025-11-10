pub mod error;
pub mod logging;
pub mod pki;
pub mod vsapi; // old, auto-generated THRIFT code - deprecated
pub mod vsconn;

// Deprecated - copied form libbode so we can build ph.
pub mod claims {
    pub const KATTR_EPID: &str = "zpr.addr";
    pub const KATTR_CN: &str = "endpoint.zpr.adapter.cn";
    pub const KATTR_AAA_NET: &str = "endpoint.zpr.node.aaa_net";
}

// Not yet implemented for libnode2
pub mod vss {

    use std::net::SocketAddr;
    use tokio::sync::mpsc::Sender;

    pub const DEFAULT_VSS_PORT: u16 = 8183;

    pub enum VSSMsg {
        /// Indicates a policy has been installed.
        PolicyInstall(crate::vsapi::PolicyInfo),

        /// Pushed visas from the visa service.
        PushedVisa(crate::vsapi::VisaHop),

        /// Pushed visa revokcations from the visa service.
        PushedRevocation(crate::vsapi::VisaRevocation),

        /// Pushed list of services. For now will be just Actor Authentication services.
        PushedServices(crate::vsapi::ServicesList),
    }

    pub fn start_vss_server(_tx_chan: Sender<VSSMsg>, _listen_addr: SocketAddr) {
        unimplemented!()
    }
}
