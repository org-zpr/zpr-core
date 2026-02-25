//! CLI argument definitions and derived configuration for lntest.

use clap::Parser;
use std::net::IpAddr;
use std::path::PathBuf;

/// lntest: test tool for libnode2
///
/// This will attempt to register as a node to the visa service.
///
#[derive(Parser, Debug)]
#[command(name = "lntest")]
#[command(version, verbatim_doc_comment)]
pub struct Args {
    /// Address of the visa service VS-API endpoint in 'HOST:PORT' format.
    #[arg(short = 'a', long, default_value = "[fd5a:5052::1]:5002")]
    pub vs_addr: String,

    /// Value to present to visa service as the node's common name.
    #[arg(short, long)]
    pub node_cn: String,

    /// Path to the nodes private key.
    #[arg(short, long)]
    pub private_key: PathBuf,

    /// Nodes ZPR address to present to the visa service.
    #[arg(long, default_value = "fd5a:5052:90de::1")]
    pub self_addr: String,

    /// Node AAA prefix to present to the visa service.
    #[arg(long, default_value = "fd5a:5052:90de:0::/64")]
    pub aaa_prefix: String,
}

/// Runtime configuration derived from parsed CLI arguments.
pub struct Config {
    pub node_zpr_addr: IpAddr,
}
