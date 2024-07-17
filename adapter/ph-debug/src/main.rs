// Tool to help debug PH
// Note: at this moment the program can only handle one-word commands, so
// when a command is multiple words, this program assumes the spaces are replaced
// with a '-' on the command line

use clap::Parser;
use std::io::prelude::*;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
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

    #[arg(long, default_value_t = 2)]
    time: u64,

    #[arg(long, default_value_t = 1)]
    duration: u64,

    #[arg(long, default_value_t = 1)]
    frequency: u64,

    #[arg(long, default_value = "cap_file.txt")]
    file_path: String,

    #[arg(long)]
    program: Option<String>,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let command = args.command;
    let port = args.port;

    match command.as_str() {
        "ECHO" => basic_call_response("ECHO\n".to_string(), port)?,
        "COUNTERS" => basic_call_response("COUNTERS\n".to_string(), port)?,
        "COUNTERS-RESET" => basic_call_response("COUNTERS-RESET\n".to_string(), port)?,
        "WATCH" => handle_watch(args.time, port)?,
        "PERF-SAMPLE" => handle_perf_sample(args.duration, args.frequency, port)?,
        "SET-CAPTURE" => handle_set_capture(args.file_path, port)?,
        "FLUSH-CAPTURE" => basic_call_response("FLUSH-CAPTURE\n".to_string(), port)?,
        "CLOSE-CAPTURE" => basic_call_response("CLOSE-CAPTURE\n".to_string(), port)?,
        "SET-PROGRAM" => handle_set_program(args.program, port)?,
        "DELETE-PROGRAM" => basic_call_response("DELETE-PROGRAM\n".to_string(), port)?,
        "CAPTURE-SEQUENCE" => {
            handle_capture_sequence(args.file_path, args.time, args.program, port)?
        }
        _ => {
            eprintln!("Command '{command}' not recognized");
        }
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
    let stream = &mut UnixStream::connect(port).unwrap();
    stream.write_all(comm.as_bytes())?;
    stream.flush()?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    println!("{response}");

    Ok(())
}

// Performs actions associated with watch command, repeatedly opens UnixStream to make
// connection with PH, requests COUNTERS data, and prints the differences
fn handle_watch(time: u64, port: String) -> std::io::Result<()> {
    println!("time {}", time);
    let mut values: [u64; 6] = [0; 6];
    let sleep_time = Duration::new(time, 0);

    loop {
        let stream = &mut UnixStream::connect(port.clone()).unwrap();
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

fn handle_perf_sample(duration: u64, frequency: u64, port: String) -> std::io::Result<()> {
    let command = "PERF-SAMPLE".to_string()
        + " "
        + duration.to_string().as_str()
        + " "
        + frequency.to_string().as_str()
        + "\n";
    basic_call_response(command, port)?;

    Ok(())
}

fn handle_set_capture(file_path: String, port: String) -> std::io::Result<()> {
    let command = "SET-CAPTURE".to_string() + " " + file_path.as_str() + "\n";
    println!("{}", command);
    basic_call_response(command, port)?;

    Ok(())
}

fn handle_capture_sequence(
    file_path: String,
    time: u64,
    program: Option<String>,
    port: String,
) -> std::io::Result<()> {
    let sleep_time = Duration::new(time, 0);
    handle_set_capture(file_path, port.clone())?;
    handle_set_program(program, port.clone())?;
    sleep(sleep_time); // TODO implement handling for Ctrl+C
                       // See 'signal handling' in the rust book, crate::ctrlc, crate::nix
    basic_call_response("CLOSE-CAPTURE\n".to_string(), port.clone())?;

    Ok(())
}

fn handle_set_program(program: Option<String>, port: String) -> std::io::Result<()> {
    match program {
        Some(program) => {
            let command = "SET-PROGRAM".to_string() + " " + program.as_str() + "\n";
            basic_call_response(command, port)?;
        }
        None => (),
    };

    Ok(())
}
