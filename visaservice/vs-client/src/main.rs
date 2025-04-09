use clap::{Parser, Subcommand};
use std::net::{IpAddr, SocketAddr};
pub mod traffic_parser;
pub mod vsclient;
mod vssd;

use crate::traffic_parser::{parse_traffic, Protocol};

const DEFAULT_SERVICE: &str = "[fd5a:5052::1]:5002";
const DEFAULT_VSS_PORT: u16 = 8183;

#[derive(Parser)]
#[command(version, about = "Visa Service THRIFT API Client", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Call the visa service hello function
    #[command()]
    Hello {
        #[arg(short, long, value_name = "HOST:PORT", default_value_t = String::from(DEFAULT_SERVICE))]
        service: String,
    },
    /// Call the visa service authenticate function, returns an API key
    #[command()]
    Authenticate {
        #[arg(short, long, value_name = "HOST:PORT", default_value_t = String::from(DEFAULT_SERVICE))]
        service: String,

        #[arg(
            short,
            long,
            value_name = "KEY=VALUE",
            help = "use multiple times to set multiple claims"
        )]
        claim: Vec<String>,

        #[arg(
            long,
            value_name = "FILE",
            help = "path to PEM encoded (noise) certificate"
        )]
        cert: String,

        #[arg(long, value_name = "ADDR", help = "nodes ZPR address")]
        zpr_addr: IpAddr,

        #[arg(long, value_name = "NAME", help = "node name (must match ZPL)")]
        node_name: String,

        #[arg(long, value_name = "PORT", default_value_t = DEFAULT_VSS_PORT)]
        vss_port: u16,
    },
    /// Call the visa service de_register function, requires an API key
    #[command()]
    Deregister {
        #[arg(short, long, value_name = "HOST:PORT", default_value_t = String::from(DEFAULT_SERVICE))]
        service: String,

        #[arg(short, long, value_name = "APIKEY")]
        apikey: String,
    },
    /// Call the visa service authorize_connect function, requires an API key
    #[command()]
    AuthorizeConnect {
        #[arg(short, long, value_name = "HOST:PORT", default_value_t = String::from(DEFAULT_SERVICE))]
        service: String,

        #[arg(short, long, value_name = "APIKEY")]
        apikey: String,

        /// The nodes ZPR address.
        #[arg(long, value_name = "ADDR")]
        node_zpr_addr: IpAddr,

        /// Claims to send with the request. Use multiple times to set multiple claims.
        /// Required claims: "zpr.addr" and "zpr.adapter.cn"
        #[arg(short, long, value_name = "KEY=VALUE")]
        claim: Vec<String>,
    },
    /// Call the visa service actor_disconnect function, requires an API key
    #[command()]
    Disconnect {
        #[arg(short, long, value_name = "HOST:PORT", default_value_t = String::from(DEFAULT_SERVICE))]
        service: String,

        #[arg(short, long, value_name = "APIKEY")]
        apikey: String,

        #[arg(long, value_name = "ADDR", help = "IPv4 or IPv6 address")]
        addr: String,
    },
    /// Call the visa service ping function, requires an API key
    #[command()]
    Ping {
        #[arg(short, long, value_name = "HOST:PORT", default_value_t = String::from(DEFAULT_SERVICE))]
        service: String,

        #[arg(short, long, value_name = "APIKEY")]
        apikey: String,
    },
    /// Call the visa service visa-request function
    #[command()]
    Requestvisa {
        #[arg(short, long, value_name = "HOST:PORT", default_value_t = String::from(DEFAULT_SERVICE))]
        service: String,

        #[arg(short, long, value_name = "APIKEY")]
        apikey: String,

        #[arg(
            short,
            long,
            value_name = "TRAFFIC",
            group = "protocol",
            help = "TCP traffic description (see `cli helptraffic`)"
        )]
        tcp: Option<String>,

        #[arg(
            short,
            long,
            value_name = "TRAFFIC",
            group = "protocol",
            help = "UDP traffic description (see `cli helptraffic`)"
        )]
        udp: Option<String>,
    },
    /// Start a visa support service server in the foreground
    #[command()]
    Runvss {
        #[arg(
            long,
            value_name = "ADDR",
            help = "nodes ZPR address (should be same as passed to authenticate)"
        )]
        zpr_addr: IpAddr,

        #[arg(long, value_name = "PORT", default_value_t = DEFAULT_VSS_PORT)]
        vss_port: u16,
    },
    /// View syntax for traffic format used when requesting a visa
    #[command()]
    Helptraffic {},
}

fn main() {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Some(Commands::Hello { service }) => match vsclient::hello(&service) {
            Ok(_) => {
                println!("Hello command executed successfully");
            }
            Err(e) => {
                println!("Error: {:?}", e);
            }
        },
        Some(Commands::Authenticate {
            service,
            claim,
            cert,
            zpr_addr,
            node_name,
            vss_port,
        }) => match vsclient::authenticate(&service, claim, &cert, &zpr_addr, &node_name, vss_port)
        {
            Ok(_) => {
                println!("Authenticate command executed successfully");
            }
            Err(e) => {
                println!("Error: {:?}", e);
            }
        },
        Some(Commands::Deregister { service, apikey }) => {
            match vsclient::deregister(&service, &apikey) {
                Ok(_) => {
                    println!("Deregister command executed successfully");
                }
                Err(e) => {
                    println!("Error: {:?}", e);
                }
            }
        }
        Some(Commands::AuthorizeConnect {
            service,
            apikey,
            node_zpr_addr,
            claim,
        }) => match vsclient::authorize_connect(&service, &apikey, &node_zpr_addr, claim) {
            Ok(_) => {
                println!("AuthorizeConnect command executed successfully");
            }
            Err(e) => {
                println!("Error: {:?}", e);
            }
        },
        Some(Commands::Disconnect {
            service,
            apikey,
            addr,
        }) => match vsclient::actor_disconnect(&service, &apikey, &addr) {
            Ok(_) => {
                println!("Disconnect command executed successfully");
            }
            Err(e) => {
                println!("Error: {:?}", e);
            }
        },
        Some(Commands::Ping { service, apikey }) => match vsclient::ping(&service, &apikey) {
            Ok(_) => {
                println!("Poll command executed successfully");
            }
            Err(e) => {
                println!("Error: {:?}", e);
            }
        },
        Some(Commands::Helptraffic {}) => {
            println!("Traffic format syntax:");
            println!();
            println!("   SRC_ADDR [ ':' SRC_PORT ] '>' DST_ADDR ':' DST_PORT [ '[' FLAGS ']' ]");
            println!();
            println!("   - IPv6 addresses should be enclosed in square brackets.");
            println!("   - Flags are optional, and can be 'S' for SYN, 'A' for ACK, or both.");
            println!("   - Source port is optional, and if omitted a high number port is randomly chosen.");
            println!();
            println!("   Note that the protocol is set by using the --tcp or --udp arg in the requestvisa command.");
            println!();
            println!("   Examples:");
            println!();
            println!("       --tcp 192.168.0.1:42300>192.168.0.99:22[S]");
            println!("       --tcp [fc00:3001::99]>[fc00:3001::1]:443[S]");
            println!();
        }
        Some(Commands::Requestvisa {
            service,
            apikey,
            tcp,
            udp,
        }) => match (tcp, udp) {
            (Some(tcp), None) => match parse_traffic(&tcp, Protocol::TCP) {
                Ok(traffic) => match vsclient::request_visa(&service, &apikey, &traffic) {
                    Ok(_) => {
                        println!("Requestvisa command executed successfully");
                    }
                    Err(e) => {
                        println!("Error: {:?}", e);
                    }
                },
                Err(e) => {
                    println!("Error: {:?}", e);
                }
            },
            (None, Some(udp)) => match parse_traffic(&udp, Protocol::UDP) {
                Ok(traffic) => match vsclient::request_visa(&service, &apikey, &traffic) {
                    Ok(_) => {
                        println!("Requestvisa command executed successfully");
                    }
                    Err(e) => {
                        println!("Error: {:?}", e);
                    }
                },
                Err(e) => {
                    println!("Error: {:?}", e);
                }
            },
            _ => {
                println!("Either TCP or UDP traffic description must be provided");
            }
        },
        Some(Commands::Runvss { zpr_addr, vss_port }) => {
            match vssd::run_vss(SocketAddr::new(zpr_addr, vss_port)) {
                Ok(_) => {
                    println!("Runvss command executed successfully");
                }
                Err(e) => {
                    println!("Error: {:?}", e);
                }
            }
        }
        None => {
            println!("No command provided");
        }
    }
}
