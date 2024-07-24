use clap::{Parser, Subcommand};
use std::net::Ipv6Addr;

pub mod traffic_parser;
pub mod vsapi;
pub mod vsclient;

use crate::traffic_parser::{parse_traffic, Protocol};

#[derive(Parser)]
#[command(version, about = "Visa Service THRIFT API Client", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    #[command(about = "Call the hello function")]
    Hello {
        #[arg(short, long, value_name = "HOST:PORT")]
        service: String,
    },
    #[command(about = "Call the authenticate function, returns an API key")]
    Authenticate {
        #[arg(short, long, value_name = "HOST:PORT")]
        service: String,

        #[arg(
            short,
            long,
            value_name = "KEY=VALUE",
            help = "use multiple times to set multiple claims"
        )]
        claim: Vec<String>,

        #[arg(long, value_name = "FILE", help = "path to PEM encoded certificate")]
        cert: String,

        #[arg(long, value_name = "FILE", help = "path to PEM encoded private key")]
        key: String, // private key
    },
    #[command(about = "Call the de_register function, requires an API key")]
    Deregister {
        #[arg(short, long, value_name = "HOST:PORT")]
        service: String,

        #[arg(short, long, value_name = "APIKEY")]
        apikey: String,
    },
    #[command(about = "Call the agent_disconnect function, requires an API key")]
    Disconnect {
        #[arg(short, long, value_name = "HOST:PORT")]
        service: String,

        #[arg(short, long, value_name = "APIKEY")]
        apikey: String,

        #[arg(long, value_name = "ADDR", help = "IPv4 or IPv6 address")]
        addr: String,
    },
    #[command(about = "Call the ping function, requires an API key")]
    Ping {
        #[arg(short, long, value_name = "HOST:PORT")]
        service: String,

        #[arg(short, long, value_name = "APIKEY")]
        apikey: String,
    },
    Requestvisa {
        #[arg(short, long, value_name = "HOST:PORT")]
        service: String,

        #[arg(short, long, value_name = "APIKEY")]
        apikey: String,

        #[arg(long, value_name = "IPv6_ADDR", help = "source tether address")]
        tether_addr: String,

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
    #[command(about = "View syntax for traffic format when requesting a visa")]
    Helptraffic {},
}

fn main() {
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
            key,
        }) => match vsclient::authenticate(&service, claim, &cert, &key) {
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
        Some(Commands::Disconnect {
            service,
            apikey,
            addr,
        }) => match vsclient::disconnect(&service, &apikey, &addr) {
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
            tether_addr,
            tcp,
            udp,
        }) => {
            let taddr = match tether_addr.parse::<Ipv6Addr>() {
                Ok(addr) => addr,
                Err(_) => {
                    println!("Invalid tether address");
                    return;
                }
            };
            match (tcp, udp) {
                (Some(tcp), None) => match parse_traffic(&tcp, Protocol::TCP) {
                    Ok(traffic) => {
                        match vsclient::request_visa(&service, &apikey, taddr, &traffic) {
                            Ok(_) => {
                                println!("Requestvisa command executed successfully");
                            }
                            Err(e) => {
                                println!("Error: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("Error: {:?}", e);
                    }
                },
                (None, Some(udp)) => match parse_traffic(&udp, Protocol::UDP) {
                    Ok(traffic) => {
                        match vsclient::request_visa(&service, &apikey, taddr, &traffic) {
                            Ok(_) => {
                                println!("Requestvisa command executed successfully");
                            }
                            Err(e) => {
                                println!("Error: {:?}", e);
                            }
                        }
                    }
                    Err(e) => {
                        println!("Error: {:?}", e);
                    }
                },
                _ => {
                    println!("Either TCP or UDP traffic description must be provided");
                }
            }
        }
        None => {
            println!("No command provided");
        }
    }
}
