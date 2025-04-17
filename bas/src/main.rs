mod fsdb;
mod server;
mod token;

use std::path::{Path, PathBuf};
use clap::{Parser, Subcommand, Args};
use tracing_subscriber;

use fsdb::FsDb;
use server::start_server;

const DEFAULT_DB_PATH: &str = "./db";



#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<CliCommand>,
}

#[derive(Subcommand)]
enum CliCommand {
    /// Create a new actor record.
    Create(CreateArgs),

    /// Delete an existing actor record.
    Delete(DeleteArgs),

    /// Display the public key of an actor in PEM format.
    Pubkey(PubKeyArgs),

    /// List the database contents.
    List(ListArgs),

    /// Add attributes to an actor.
    AddAttribute(AddAttributeArgs),

    /// Start the authentication server.
    Serve(ServeArgs),
}

#[derive(Args)]
struct CreateArgs {
    /// CN for the new actor
    cn: String,
}

#[derive(Args)]
struct DeleteArgs {
    /// CN of the actor to delete
    cn: String,
}

#[derive(Args)]
struct PubKeyArgs {
    /// CN of the actor whose public key to retrieve
    cn: String,
}

#[derive(Args)]
struct ListArgs {

    /// Also list any attributes
    #[arg(long, short)]
    attrs: bool,

    /// Include tokens too
    #[arg(long, short)]
    tokens: bool,

    /// Only list actors matching this CN pattern
    cn: Option<String>,
}

#[derive(Args)]
struct AddAttributeArgs {
    /// CN of the actor to add attributes to
    cn: String,
    /// Attributes to add for is 'name:value', 'name:value1,value2' or just 'name' for a tag.
    attrs: Vec<String>
}

#[derive(Args)]
struct ServeArgs {
    /// Path to the TLS key file
    #[arg(long, short)]
    key: PathBuf,

    /// Path to the TLS certificate file
    #[arg(long, short)]
    cert: PathBuf,
}


fn main() {
    let cli = Cli::parse();
    match cli.command {
        Some(CliCommand::Create(args)) => {
            let db = init_db(Path::new(DEFAULT_DB_PATH));
            let created = db.create_actor(&args.cn).unwrap_or_else(|e| {
                eprintln!("Error creating actor: {}", e);
                std::process::exit(1);
            });
            println!("created: {}", created);
        }
        Some(CliCommand::Delete(args)) => {
            let db = init_db(Path::new(DEFAULT_DB_PATH));
            let deleted = db.delete_actor(&args.cn).unwrap_or_else(|e| {
                eprintln!("Error deleting actor: {}", e);
                std::process::exit(1);
            });
            println!("deleted: {}", deleted);
        }
        Some(CliCommand::Pubkey(args)) => {
            let db = init_db(Path::new(DEFAULT_DB_PATH));
            println!("{}", db.get_pub_key(&args.cn).unwrap_or_else(|e| {
                eprintln!("Error retrieving public key: {}", e);
                std::process::exit(1);
            }));
        }
        Some(CliCommand::List(args)) => {
            let db = init_db(Path::new(DEFAULT_DB_PATH));
            db.print(&args.cn, args.attrs, args.tokens).unwrap_or_else(|e| {
                eprintln!("error listing database {}", e);
                std::process::exit(1);
            });
        }
        Some(CliCommand::AddAttribute(args)) => {
            let db = init_db(Path::new(DEFAULT_DB_PATH));
            let cn = db.add_attributes(&args.cn, &args.attrs).unwrap_or_else(|e| {
                eprintln!("Error adding attributes: {}", e);
                std::process::exit(1);
            });
            println!("added attributes to: {}", cn);
        }
        Some(CliCommand::Serve(args)) => {
            let rt = tokio::runtime::Runtime::new().unwrap();
            tracing_subscriber::fmt::init();
            rt.block_on(async {
                start_server(&args.key, &args.cert, init_db(Path::new(DEFAULT_DB_PATH))).await;
            });
        }
        None => {
            println!("No command provided. Use --help for more information.");
        }
    }
}


fn init_db(root: &Path) -> FsDb {
    match FsDb::new(root) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Error initializing database: {}", e);
            std::process::exit(1);
        }
    }
}