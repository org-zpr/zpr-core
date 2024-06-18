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
use std::thread::sleep;
use std::time::Duration;

// Struct made for use with clap parsing 
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    command: String,

    #[arg(short, long)]
    port: String,

    #[arg(short, long, default_value_t = 2)]
    time: u64,
}


fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let command = args.command;
    let port    = args.port;
    let time    = args.time;
    
    handle_commands(command, time, port)?;

    Ok(())
}

// Determines which command to execute
fn handle_commands(command: String, time: u64, port: String) -> std::io::Result<()> {
    println!("{command}, {port}");
    // fs::remove_file(&port).or_else(|e| if e.kind() == ErrorKind::NotFound { Ok(()) } else { Err(e) }).unwrap();

    match command.as_str() {
        "ECHO" => basic_call_response("ECHO\n".to_string(), port)?,
        "COUNTERS" => basic_call_response("COUNTERS\n".to_string(), port)?,
        "COUNTERS-RESET" => basic_call_response("COUNTERS RESET\n".to_string(), port)?,
        "WATCH" => handle_watch(time, port)?,
        _ => {eprintln!("Command '{command}' not recognized");},
    };


    Ok(())
}

// Handles basic call and response command where all the program has to do 
// is write one command to the PH and await a response 
// Opens and closes UnixStream
//
// TODO could rewrite this to return a string, then print in handle_commands
// also could use in handle_watch - however would lose error checking capabilities
fn basic_call_response(comm: String, port: String) -> std::io::Result<()> {
    let stream =  Box::leak(Box::new(UnixStream::connect(port).unwrap())); //TODO not sure if this needs the Box leak wrapper
    stream.write_all(comm.as_bytes())?;
    stream.flush()?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    println!("{response}");

    Ok(())
}

fn handle_watch(time: u64, port: String) -> std::io::Result<()> {
    let mut values: [u64; 6] = [0; 6];
    let sleep_time = Duration::new(time, 0);

    loop {
        let stream =  Box::leak(Box::new(UnixStream::connect(port.clone()).unwrap())); //TODO not sure if this needs the Box leak wrapper
        stream.write_all(b"COUNTERS\n")?;
        stream.flush()?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        stream.shutdown(Shutdown::Both)?;

        // Split up the long string with all the counts and words into a vector
        // with each line as a different index of the vector 
        let counts: Vec<&str> = response.split('\n').collect(); // Split the messages

        // TODO error checking, make sure actually got a message back, and that it's the correct message
        for n in 1..7 {
            // split up the individual lines to get the count from the end and convert to u64
            let one_line: Vec<&str> = counts[n].split(':').collect();
            let mut num: String = one_line[1].to_string();
            num.remove(0);
            let num_packets: u64 = num.parse().unwrap(); 

            // calculate difference
            let difference = num_packets - values[n - 1];

            println!("{} increased by: {}", one_line[0], difference);
            values[n - 1] = num_packets; // store new packet counts
        }

        sleep(sleep_time);
    }
}
