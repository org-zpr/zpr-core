#![cfg_attr(feature = "ci", deny(warnings))]
use daemonize::Daemonize;
use std::env;
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
use std::path::Path;
use std::sync::Arc;

pub mod cd;

const LOG_DIR: &str = "/var/run/zpr";
const PID_DIR: &str = "/var/run/zpr";

fn usage() -> io::Result<()> {
    println!("Usage: cd [-f|--foreground]");
    println!("ZPR Connection Daemon\n");
    println!("Unless the foreground option is provided, the daemon will run in the");
    println!(
        "background, logging to {}/cd.out and {}/cd.err.",
        LOG_DIR, LOG_DIR
    );
    println!();

    Ok(())
}

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.contains(&String::from("-h")) || args.contains(&String::from("--help")) {
        return usage();
    }
    let foreground = if args.len() > 1 {
        args[1] == "-f" || args[1] == "--foreground"
    } else {
        false
    };

    let config = Arc::new(cd::Config {
        socket_path: String::from("/var/run/zpr/cd.sock"),
    });

    if foreground {
        return cd::tokio_main(config.clone());
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
        .open(format!("{}/cd.out", LOG_DIR))?;
    writeln!(
        stdout,
        "=============== cd restarts at {} ==============",
        chrono::Local::now()
    )?;
    let mut stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .truncate(false)
        .open(format!("{}/cd.err", LOG_DIR))?;
    writeln!(
        stderr,
        "=============== cd restarts at {} ==============",
        chrono::Local::now()
    )?;

    let daemonize = Daemonize::new()
        .pid_file(format!("{}/cd.pid", PID_DIR))
        .stdout(stdout)
        .stderr(stderr);

    match daemonize.start() {
        Ok(_) => println!("cd launching in background..."),
        Err(e) => eprintln!("failed to launch CD: {}", e),
    }
    cd::tokio_main(config.clone())
}
