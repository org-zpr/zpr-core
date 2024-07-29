#![cfg_attr(feature = "ci", deny(warnings))]
use daemonize::Daemonize;
use std::env;
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;

pub mod cd;


fn usage() -> io::Result<()> {
    println!("Usage: cd [-f|--foreground]");
    println!("ZPR Connection Daemon\n");
    println!("Unless the foreground option is provided, the daemon will run in the");
    let data_home = get_data_home();
    println!(
        "background, logging to {}/cd.out and {}/cd.err.",
        data_home.to_str().unwrap(), data_home.to_str().unwrap()
    );
    println!();

    Ok(())
}

fn get_data_home() -> PathBuf {
    let mut dh = match env::var("XDG_DATA_HOME") {
        Ok(val) => PathBuf::from(val),
        Err(_) => {
            match env::var("HOME") {
                Ok(val) => {
                    let mut pb = PathBuf::from(val);
                    pb.push(".local/share");
                    pb
                },
                Err(_) => PathBuf::from("/var/run"),
            }
        }
    };
    dh.push("zpr");
    dh
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

    std::fs::create_dir_all(get_data_home()).expect("failed to create ZPR data directory");
    let mut sock_path = get_data_home();
    sock_path.push("cd");
    sock_path.set_extension("sock");
    let config = Arc::new(cd::Config {
        socket_path: sock_path,
    });

    if foreground {
        return cd::tokio_main(config.clone());
    }
    // Else we go into background.

    let mut stdout_path = get_data_home();
    stdout_path.push("cd");
    stdout_path.set_extension("out");
    let mut stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .truncate(false)
        .open(stdout_path)?;
    writeln!(
        stdout,
        "=============== cd restarts at {} ==============",
        chrono::Local::now()
    )?;
    let mut stderr_path = get_data_home();
    stderr_path.push("cd");
    stderr_path.set_extension("err");
    let mut stderr = OpenOptions::new()
        .create(true)
        .append(true)
        .truncate(false)
        .open(stderr_path)?;
    writeln!(
        stderr,
        "=============== cd restarts at {} ==============",
        chrono::Local::now()
    )?;

    let mut pid_file_path = get_data_home();
    pid_file_path.push("cd");
    pid_file_path.set_extension(".pid");
    let daemonize = Daemonize::new()
        .pid_file(pid_file_path)
        .stdout(stdout)
        .stderr(stderr);

    match daemonize.start() {
        Ok(_) => println!("cd launching in background..."),
        Err(e) => eprintln!("failed to launch CD: {}", e),
    }
    cd::tokio_main(config.clone())
}
