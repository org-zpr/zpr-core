// Tool to help debug PH 
// Note: at this moment the program can only handle one-word commands, so 
// when a command is multiple words, this program assumes the spaces are replaced
// with a '-' on the command line

use clap::Parser;
use std::os::unix::net::UnixStream;
// use std::fs;
// use std::io::ErrorKind;
use std::io::prelude::*;
use std::net::Shutdown;

// Struct made for use with clap parsing 
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    command: String,

    #[arg(short, long)]
    port: String
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let command = args.command;
    let port    = args.port;

    handle_commands(command, port)?;

    Ok(())
}

// Determines which command to execute
// Opens and closes UnixStream
fn handle_commands(command: String, port: String) -> std::io::Result<()> {
    println!("{command}, {port}");
    // fs::remove_file(&port).or_else(|e| if e.kind() == ErrorKind::NotFound { Ok(()) } else { Err(e) }).unwrap();
    let stream =  Box::leak(Box::new(UnixStream::connect(port).unwrap())); //TODO not sure if this needs the Box leak wrapper

    match command.as_str() {
        "ECHO" => basic_call_response("ECHO\n".to_string(), stream)?,
        "COUNTERS" => basic_call_response("COUNTERS\n".to_string(), stream)?,
        "COUNTERS-RESET" => basic_call_response("COUNTERS RESET\n".to_string(), stream)?,   
        _ => {eprintln!("Command '{command}' not recognized");},
    };

    stream.shutdown(Shutdown::Both)?;

    Ok(())
}

// Handles basic call and response command where all the program has to do 
// is write one command to the PH and await a response 
fn basic_call_response(comm: String, stream: &mut UnixStream) -> std::io::Result<()> {
    stream.write_all(comm.as_bytes())?;
    stream.flush()?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    println!("{response}");

    Ok(())
}