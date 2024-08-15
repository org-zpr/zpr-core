//! Tool to help debug PH
//! Note: at this moment the program can only handle one-word commands, so
//! when a command is multiple words, this program assumes the spaces are replaced
//! with a '-' on the command line

use cbpf_rs;
use clap::Parser;
use ctrlc;
use pcap::{Capture, Linktype};
use std::borrow::Borrow;
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::io::{BufReader, Error, IoSlice};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::sleep;
use std::time::Duration;
use zpr_ext::std::os::unix::net::{SocketAncillary, UnixStreamExt};
const ANCILLARY_BUFFER_SIZE: usize = 128;

#[derive(Parser, Debug)]
#[command(version, about = "This program controls the RPC calls to the ZPR Packet Handler", long_about = None)]
/// Two help messages when running the program, -h gives succinct information, --help gives
/// list of all the commands
struct Args {
    #[arg(
        short,
        long,
        help = "Re-run with '--help' for list of commands",
        long_help = "ECHO\n\
                     COUNTERS\n\
                     COUNTERS-RESET\n\
                     FLUSH-CAPTURE\n\
                     CLOSE-CAPTURE\n\
                     DELETE-CAPTURE-PROGRAM\n\
                     WATCH <frequency>\n\
                     PERF-SAMPLE <duration> <frequency>\n\
                     SET-CAPTURE <file-path>\n\
                     CAPTURE-SEQUENCE <file-path> <duration> <program>\n\
                     SET-CAPTURE-PROGRAM <program>"
    )]
    command: String,

    #[arg(short, long)]
    port: String,

    #[arg(long, default_value_t = 1)]
    duration: u64,

    #[arg(long, default_value_t = 1)]
    frequency: u64, // TODO make another argument, I don't like that in WATCH freq is how many seconds to wait between samples, whereas in PERF-SAMPLE it's samples per second

    #[arg(long, default_value = "cap_file.txt")]
    file_path: String,

    #[arg(
        long,
        help = "",
        long_help = "This option has no default, if no program is provided for a command that \
                            needs a program, no program will be set"
    )]
    program: Option<String>,
}

fn main() -> std::io::Result<()> {
    let args = Args::parse();

    let command = args.command + "\n";
    let port = args.port;

    match command.as_str() {
        "ECHO\n"
        | "COUNTERS\n"
        | "COUNTERS-RESET\n"
        | "FLUSH-CAPTURE\n"
        | "CLOSE-CAPTURE\n"
        | "DELETE-CAPTURE-PROGRAM\n" => basic_call_response(&command, &port)?,
        "WATCH\n" => handle_watch(args.frequency, &port)?,
        "PERF-SAMPLE\n" => handle_perf_sample(args.duration, args.frequency, &port)?,
        "SET-CAPTURE\n" => handle_set_capture(args.file_path, &port)?,
        "CAPTURE-SEQUENCE\n" => {
            handle_capture_sequence(args.file_path, args.duration, args.program, &port)?
        }
        "SET-CAPTURE-PROGRAM\n" => handle_set_capture_program(args.program, &port)?,
        _ => {
            eprintln!("Command '{command}' not recognized");
        }
    };

    Ok(())
}

/// Handles basic call and response with the rpc_worker in the ph. Sends a string
/// to the specified port, reads and prints the response
/// Opens and closes UnixStream
/// Can be used directly in main for commands that don't have to send any additional data
/// with the command, and can be invoked in helper functions for commands that require
/// extra information to be send once a string with all the information to be sent is created.
fn basic_call_response(comm: &str, port: &str) -> std::io::Result<()> {
    let stream = &mut UnixStream::connect(port).unwrap();
    stream.write_all(comm.as_bytes())?;
    stream.flush()?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    println!("{response}");

    Ok(())
}

/// Repeatedly opens UnixStream to make connection with PH, requests COUNTERS data,
/// and prints the differences between the counts currently and the counts at the
/// last sample
/// Requires how many seconds to wait between samples
// TODO should we also be handling ctrl+c in this function?
fn handle_watch(frequency: u64, port: &str) -> std::io::Result<()> {
    let mut values: Vec<u64> = Vec::new();
    let sleep_time = Duration::new(frequency, 0);
    let mut first_run = true;

    loop {
        let stream = &mut UnixStream::connect(port).unwrap();
        stream.write_all(b"COUNTERS\n")?;
        stream.flush()?;
        let mut response = String::new();
        stream.read_to_string(&mut response)?;
        stream.shutdown(Shutdown::Both)?;

        // Split up the long string with all the counts and words into a vector
        // with each line as a different index of the vector
        let counts: Vec<&str> = response.split('\n').collect(); // Split the messages

        if first_run {
            values.resize(counts.len(), 0);
        }

        // TODO error checking, make sure actually got a message back, and that it's the correct message
        for (n, count) in counts[1..].iter().enumerate() {
            // split up the individual lines to get the count from the end and convert to u64
            let one_line: Vec<&str> = count.split(':').collect();
            if one_line[0] == "OK" {
                break;
            }
            let mut num: String = one_line[1].to_string();
            num.remove(0);
            let num_packets: u64 = num.parse().unwrap();

            // calculate difference between current pkt nums and previous pkt nums
            let difference = num_packets - values[n];

            println!("{} increased by: {}", one_line[0], difference);
            values[n] = num_packets; // store new packet counts
        }

        first_run = false;
        sleep(sleep_time);
    }
}

fn handle_perf_sample(duration: u64, frequency: u64, port: &str) -> std::io::Result<()> {
    let command = format!("PERF-SAMPLE {} {}\n", duration, frequency);

    basic_call_response(&command, port)?;

    Ok(())
}

fn handle_set_capture(file_path: String, port: &str) -> std::io::Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(file_path)
        .unwrap();

    let mut ancillary_buffer = [0; ANCILLARY_BUFFER_SIZE];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);
    ancillary.add_fds(&[file.as_fd()]);

    let buf = [1; 1]; // Must send some data with the ancillary data
    let bufs = &mut [IoSlice::new(&buf)];

    // Establish connection with RPC worker, send command
    let stream = &mut UnixStream::connect(port).unwrap();
    stream.write_all("SET-CAPTURE\n".as_bytes())?;
    stream.flush()?;

    // Receive response from RPC worker, ensure that it sent the correct response and
    // is expecting the file descriptor
    let mut confirmation = String::new();
    let mut buf_reader = BufReader::new(stream.try_clone().unwrap());
    buf_reader.read_line(&mut confirmation)?;
    buf_reader.read_line(&mut confirmation)?;
    if confirmation != "Message Received\nSEND ANCILLARY\n" {
        return Err(Error::other("Incorrect Message Received"));
    }
    confirmation.pop(); // Removes \n at end of message, simply makes output look nicer
    println!("{confirmation}");

    // Create fd, ancillary buffer, data buffer, and send ancillary data
    #[allow(unstable_name_collisions)]
    stream.send_vectored_with_ancillary(bufs, &mut ancillary)?;

    // Read response from
    let mut response = String::new();
    stream.read_to_string(&mut response)?; // Read rest of response
    println!("{response}");

    Ok(())
}

fn handle_capture_sequence(
    file_path: String,
    time: u64,
    program: Option<String>,
    port: &str,
) -> std::io::Result<()> {
    let sleep_time = Duration::new(time, 0);
    handle_set_capture(file_path, port)?;
    handle_set_capture_program(program, port)?;

    let handler = Arc::new(CtrlcHandle::new());
    let ctrlc_handler = handler.clone();
    // Will set wait to false in CtrlcHandler if ctrl+c is pressed
    ctrlc::set_handler(move || ctrlc_handler.set_false()).unwrap();
    handler.timed_wait(sleep_time);

    basic_call_response("DELETE-CAPTURE-PROGRAM\n", port)?;
    basic_call_response("CLOSE-CAPTURE\n", port)?;

    Ok(())
}

/// Converts capture program into serialized format so that the RPC worker doesn't
/// need to use the pcap library, and can just have knowledge of the serialized
/// format and use exclusively cbpf-rs
fn handle_set_capture_program(program: Option<String>, port: &str) -> std::io::Result<()> {
    // Ensures that a program has properly been provided before sending message because
    // there is no default program
    match program {
        Some(program) => {
            let serialized_program = serialize(&program);
            let command = format!("SET-CAPTURE-PROGRAM {}\n", serialized_program);
            basic_call_response(&command, &port)?;
        }
        None => (),
    };

    Ok(())
}

/// Uses combination of pcap and cbpf-rs libraries to serialize program
/// into the following format:
/// <number of instructions>,code1 jt1 jf1 k1,code2 jt2 jf2 k2,...,coden jtn jfn kn
fn serialize(program: &str) -> String {
    use std::fmt::Write;

    let capture = Capture::dead(Linktype::USER0).unwrap();
    let program = capture.compile(program, true).unwrap();
    let instructions: &[pcap::BpfInstruction] = program.get_instructions();
    let mut serialized_program = format!("{},", instructions.len());

    for instruction in instructions {
        let insn: &cbpf_rs::BpfInsn = instruction.borrow();
        let _ = write!(
            &mut serialized_program,
            "{} {} {} {},",
            insn.code, insn.jt, insn.jf, insn.k
        );
    }
    let _ = serialized_program.pop(); // removes trailing comma at end of string
    serialized_program
}

struct CtrlcHandle {
    wait: Mutex<bool>,
    cv: Condvar,
}

impl CtrlcHandle {
    pub fn new() -> Self {
        Self {
            wait: Mutex::new(true),
            cv: Condvar::new(),
        }
    }

    pub fn set_false(&self) {
        *self.wait.lock().unwrap() = false;
        self.cv.notify_one();
    }

    // Waits for a specified duration, but the timeout can be interrupted if wait becomes
    // false
    pub fn timed_wait(&self, dur: Duration) -> bool {
        let (mut guard, _) = self
            .cv
            .wait_timeout_while(self.wait.lock().unwrap(), dur, |&mut wait| wait)
            .unwrap();
        let wait = *guard;
        *guard = true;
        wait
    }
}
