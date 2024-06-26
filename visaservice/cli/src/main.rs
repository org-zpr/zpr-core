use clap::{Parser, Subcommand};

pub mod vsapi;
pub mod vsclient;

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
    #[command(about = "Call the poll function, requires an API key")]
    Poll {
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
    #[command(about = "Call the poll function, requires an API key")]
    Poll {
        #[arg(short, long, value_name = "HOST:PORT")]
        service: String,

        #[arg(short, long, value_name = "APIKEY")]
        apikey: String,
    },
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
        Some(Commands::Poll { service, apikey }) => match vsclient::poll(&service, &apikey) {
            Ok(_) => {
                println!("Poll command executed successfully");
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
        Some(Commands::Poll { service, apikey }) => match vsclient::poll(&service, &apikey) {
            Ok(_) => {
                println!("Poll command executed successfully");
            }
            Err(e) => {
                println!("Error: {:?}", e);
            }
        },
        None => {
            println!("No command provided");
        }
    }
}
