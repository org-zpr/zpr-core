use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::path::Path;
use std::{env, process};

use daemonize::Daemonize;

const LOG_DIR: &str = "/var/run/zpr";
const PID_DIR: &str = "/var/run/zpr";

#[rustfmt::skip]
fn usage() {
    println!("Usage: node [OPTIONS]");
    println!("Start a ZPR node\n");
    println!("Options:");
    println!("  -f | --foreground Run in the foreground.");
    println!("                    Will run in the background by default logging to {}.", LOG_DIR);
    println!("  -h | --help       Print this help message.");
    println!("  -v | --version    Print the version.");
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let config = Config::build(&args).unwrap_or_else(|err| {
        eprintln!("argument error: {}", err);
        process::exit(1);
    });
    if config.help {
        usage();
        return Ok(());
    }

    if config.version {
        println!("ZPR node v{}", node::VERSION);
        return Ok(());
    }

    if config.foreground {
        return node::tokio_main();
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
    node::tokio_main()
}

struct Config {
    help: bool,
    version: bool,
    foreground: bool,
}

impl Config {
    fn build(args: &[String]) -> Result<Config, &'static str> {
        let mut config = Config {
            help: false,
            version: false,
            foreground: false,
        };
        for arg in args.iter() {
            match arg.as_str() {
                "-h" | "--help" => config.help = true,
                "-v" | "--version" => config.version = true,
                "-f" | "--foreground" => config.foreground = true,
                _ => (),
            }
        }
        Ok(config)
    }
}
