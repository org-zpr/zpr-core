use clap::Parser;

use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::Path;
use std::process;

use daemonize::Daemonize;

mod config;
mod core;

pub mod vsapi;
pub mod zdp;

const LOG_DIR: &str = "/var/run/zpr";
const PID_DIR: &str = "/var/run/zpr";

#[derive(Parser)]
#[command(version, about = "ZPR node")]
struct Cli {
    #[arg(
        short,
        long,
        value_name = "FILE",
        help = "path to the configuration file"
    )]
    config: String,

    #[arg(short, long, help = "run in foreground")]
    foreground: bool,

    #[arg(
        long,
        value_name = "ADDR:PORT",
        help = "DEBUG - force immediate visa service connect"
    )]
    vsforceconnect: Option<String>,

    #[arg(
        long,
        value_name = "ADDR:PORT",
        help = "DEBUG - override default visa-support-service listening address"
    )]
    vssforcelisten: Option<String>,
}

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    let config = match config::load_configuration(Path::new(&cli.config)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load configuration: {}", e);
            process::exit(1);
        }
    };

    let mut opts = core::CoreOpts::new();

    if let Some(hostport) = cli.vsforceconnect.as_deref() {
        opts.set_vsforceconnect(hostport)
    }
    if let Some(hostport) = cli.vssforcelisten.as_deref() {
        opts.set_vssforcelisten(hostport)
    }

    if cli.foreground {
        return core::tokio_main(config, opts);
    }

    // Else we go into background.

    let logpath = Path::new(LOG_DIR);
    std::fs::create_dir_all(logpath).expect("failed to create log directory");

    let pidpath = Path::new(PID_DIR);
    std::fs::create_dir_all(pidpath).expect("failed to create PID directory");

    let mut stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .truncate(false)
        .open(format!("{}/node.out", LOG_DIR))?;
    writeln!(
        stdout,
        "=============== node restarts at {} ==============",
        chrono::Local::now()
    )?;
    let mut stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .truncate(false)
        .open(format!("{}/node.err", LOG_DIR))?;
    writeln!(
        stderr,
        "=============== node restarts at {} ==============",
        chrono::Local::now()
    )?;

    let daemonize = Daemonize::new()
        .pid_file(format!("{}/node.pid", PID_DIR))
        .stdout(stdout)
        .stderr(stderr);

    match daemonize.start() {
        Ok(_) => println!("node launching in background..."),
        Err(e) => eprintln!("failed to launch: {}", e),
    }
    core::tokio_main(config, opts)
}
