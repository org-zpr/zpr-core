#![feature(unix_socket_ancillary_data)]

// Tool to help debug PH
// Note: at this moment the program can only handle one-word commands, so
// when a command is multiple words, this program assumes the spaces are replaced
// with a '-' on the command line

use cbpf_rs;
use clap::Parser;
use ctrlc;
use pcap::{Capture, Linktype};
use std::borrow::Borrow;
use std::io::prelude::*;
use std::net::Shutdown;
use std::os::unix::net::{UnixStream, SocketAncillary};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::sleep;
use std::time::Duration;
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::io::IoSlice;

const ANCILLARY_BUFFER_SIZE: usize = 128;

#[derive(Parser, Debug)]
#[command(version, about = "This program controls the RPC calls to the ZPR Packet Handler", long_about = None)]
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
    frequency: u64,

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
            capture_sequence(args.file_path, args.duration, args.program, &port)?
        }
        "SET-CAPTURE-PROGRAM\n" => handle_set_capture_program(args.program, &port)?,
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
fn basic_call_response(comm: &str, port: &str) -> std::io::Result<()> {
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
fn handle_watch(time: u64, port: &str) -> std::io::Result<()> {
    println!("time {}", time);
    let mut values: [u64; 6] = [0; 6];
    let sleep_time = Duration::new(time, 0);

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

fn handle_perf_sample(duration: u64, frequency: u64, port: &str) -> std::io::Result<()> {
    let command = format!("PERF-SAMPLE {} {}\n", duration, frequency);

    basic_call_response(&command, port)?;

    Ok(())
}

fn handle_set_capture(file_path: String, port: &str) -> std::io::Result<()> {
    let file_descriptor = OpenOptions::new().read(true).write(true).create(true).open(file_path).unwrap().as_raw_fd();
    let mut ancillary_buffer = [0; ANCILLARY_BUFFER_SIZE];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);
    ancillary.add_fds(&[file_descriptor]);

    let buf = [1; 8];
    let bufs = &mut [IoSlice::new(&buf)];

    let stream = &mut UnixStream::connect(port).unwrap();
    stream.write_all("SET-CAPTURE\n".as_bytes())?;
    stream.send_vectored_with_ancillary(bufs, &mut ancillary)?;
    stream.flush()?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    println!("{response}");

    Ok(())
}

fn capture_sequence(
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
    ctrlc::set_handler(move || ctrlc_handler.set_false()).unwrap();
    handler.timed_wait(sleep_time);

    basic_call_response("DELETE-CAPTURE-PROGRAM\n", port)?;
    basic_call_response("CLOSE-CAPTURE\n", port)?;

    Ok(())
}

fn handle_set_capture_program(program: Option<String>, port: &str) -> std::io::Result<()> {
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
    let _ = serialized_program.pop();
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
