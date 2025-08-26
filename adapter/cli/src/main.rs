//! Tool to help debug PH
//! Note: at this moment the program can only handle one-word commands, so
//! when a command is multiple words, this program assumes the spaces are replaced
//! with a '-' on the command line

use cbpf_rs;
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::{generate, shells::Shell};
use ctrlc;
use pcap::{Capture, Linktype};
use std::borrow::Borrow;
use std::fs::{File, OpenOptions};
use std::io;
use std::io::prelude::*;
use std::io::{BufReader, BufWriter, Error, IoSlice};
use std::net::Shutdown;
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::sleep;
use std::time::Duration;
use zpr::rpc_commands::RpcCommands;
use zpr_ext::std::os::unix::net::{SocketAncillary, UnixStreamExt};

const ANCILLARY_BUFFER_SIZE: usize = 128;

macro_rules! basic_command {
    ($comm:expr, $socket:ident) => {
        basic_call_response_0($comm, $socket)
    };
    ($comm:expr, $socket:ident, $arg:tt) => {
        basic_call_response_1($comm, $socket, $arg)
    };
    ($comm:expr, $socket:ident, $arg1:tt, $arg2:tt) => {
        basic_call_response_2($comm, $socket, $arg1, $arg2)
    };
}

#[derive(Parser, Debug)]
#[command(version, about = "This program controls the RPC calls to the ZPR Packet Handler\nRun without a command to enter CLI mode", long_about = None)]
struct CmdlineArgs {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to the Packet Handler's management socket
    #[arg(long, short = 'p', default_value = "/var/run/zpr/ph.sock")]
    socket: String,

    // Path to the generations file you want to create
    #[arg(long, short = 'g')]
    generate: bool,
}

#[derive(Parser, Debug)]
#[command(multicall = true)]
struct CliCommand {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Echo,
    /// Display or reset counters
    Counters {
        #[arg(long, short = 'r')]
        /// Reset counters
        reset: bool,
    },
    #[command(arg_required_else_help = true)]
    /// Connect to the Packet Handler for periodic counter updates
    Watch {
        #[arg(required = true)]
        /// How frequently to receive updates
        interval: u64,
    },
    #[command(arg_required_else_help = true)]
    /// Start performance sampling (currently not functional)
    PerfSample {
        #[arg(required = true)]
        /// How long the sampling should run
        duration: u64,

        #[arg(required = true)]
        /// How frequently packets should be injected
        frequency: u64,
    },
    /// Set up or tear down packet captures
    Capture(CaptureArgs),
    /// Change link state
    Link(LinkArgs),
    /// Change the log level of a node or adapter
    Logging {
        #[arg(required = true)]
        logs: Vec<String>,
    },
    /// Exit the CLI
    Quit,
}

#[derive(Debug, Args)]
#[command(flatten_help = true)]
struct CaptureArgs {
    #[command(subcommand)]
    command: CaptureCommands,
}

#[derive(Debug, Subcommand)]
enum CaptureCommands {
    #[command(arg_required_else_help = true)]
    /// Set a capture file
    SetFile { file_path: String },
    /// Close a capture file
    CloseFile,
    /// Set a BPF to filter captured packets
    SetProgram { program: Option<String> },
    /// Delete any set BPF
    DeleteProgram,
    /// Flush any outstanding packets to the capture file
    FlushFile,
    #[command(arg_required_else_help = true)]
    /// Create a temporary packet capture
    Sequence {
        file_path: String,
        duration: u64,
        program: Option<String>,
    },
}

#[derive(Debug, Args)]
#[command(flatten_help = true)]
struct LinkArgs {
    #[command(subcommand)]
    command: LinkCommands,
}

#[derive(Debug, Subcommand)]
enum LinkCommands {
    /// Show a link's status
    Show { id: Option<u32> },
    /// Configure a link
    Configure { id: u32 },
    /// Start a link
    Start { id: u32 },
    /// Stop a link
    Stop { id: u32 },
    /// Reset a link.  It will require a configure before starting again
    Reset { id: u32 },
}

fn main() -> std::io::Result<()> {
    let args = CmdlineArgs::parse();
    let socket = args.socket.clone();

    if args.generate {
        return generate_completion();
    }

    if let Some(command) = args.command {
        process_command(command, &socket).map(|_| {})
    } else {
        run_cli(&socket)
    }
}

fn run_cli(socket: &str) -> std::io::Result<()> {
    loop {
        print!("> ");
        io::stdout().flush()?;
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => {
                println!("Goodbye!");
                return Ok(());
            }
            Err(e) => return Err(e),
            Ok(_) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                match parse_and_exec(line, socket) {
                    Ok(quit) => {
                        if quit {
                            return Ok(());
                        }
                    }
                    Err(err) => {
                        println!("Failed to parse command \"{}\".  Error: {}", line, err);
                    }
                }
            }
        }
    }
}

fn parse_and_exec(line: &str, socket: &str) -> std::io::Result<bool> {
    let args = shlex::split(line).ok_or(Error::other("Invalid quoting"))?;
    let cli = CliCommand::try_parse_from(args).map_err(|e| Error::other(e.to_string()))?;

    process_command(cli.command, socket)
}

fn process_command(command: Commands, socket: &str) -> std::io::Result<bool> {
    // Commands that don't need any additional data can be sent right here, those
    // with extra info get sent in their handler funcs
    match command {
        Commands::Echo => basic_command!(RpcCommands::Echo, socket)?,
        Commands::Counters { reset } => {
            if reset {
                basic_command!(RpcCommands::CountersReset, socket)?
            } else {
                basic_command!(RpcCommands::Counters, socket)?
            }
        }
        Commands::Capture(capture) => match capture.command {
            CaptureCommands::SetFile { file_path } => handle_set_capture_file(file_path, socket)?,
            CaptureCommands::CloseFile => basic_command!(RpcCommands::CloseCaptureFile, socket)?,
            CaptureCommands::FlushFile => basic_command!(RpcCommands::FlushCaptureFile, socket)?,
            CaptureCommands::SetProgram { program } => handle_set_capture_program(program, socket)?,
            CaptureCommands::DeleteProgram => {
                basic_command!(RpcCommands::DeleteCaptureProgram, socket)?
            }
            CaptureCommands::Sequence {
                file_path,
                duration,
                program,
            } => handle_capture_sequence(file_path, duration, program, &socket)?,
        },
        Commands::Watch { interval } => handle_watch(interval, &socket)?,
        Commands::PerfSample {
            duration,
            frequency,
        } => handle_perf_sample(duration, frequency, &socket)?,
        Commands::Link(link) => handle_link_command(link, &socket)?,
        Commands::Logging { logs } => handle_logging(logs, &socket)?,
        Commands::Quit => return Ok(true),
    }

    Ok(false)
}

fn basic_call_response_0(comm: RpcCommands, socket: &str) -> std::io::Result<()> {
    let command_str = format!("{}\n", comm);
    basic_call_response_impl(&command_str, socket)
}

fn basic_call_response_1<T: std::fmt::Display>(
    comm: RpcCommands,
    socket: &str,
    arg: T,
) -> std::io::Result<()> {
    let command_str = format!("{} {}\n", comm, arg);
    basic_call_response_impl(&command_str, socket)
}

fn basic_call_response_2<T1: std::fmt::Display, T2: std::fmt::Display>(
    comm: RpcCommands,
    socket: &str,
    arg1: T1,
    arg2: T2,
) -> std::io::Result<()> {
    let command_str = format!("{} {} {}\n", comm, arg1, arg2);
    basic_call_response_impl(&command_str, socket)
}

/// Handles basic call and response with the rpc_worker in the ph. Sends a string
/// to the specified socket, reads and prints the response
/// Opens and closes UnixStream
/// Can be used directly in main for commands that don't have to send any additional data
/// with the command, and can be invoked in helper functions for commands that require
/// extra information to be send once a string with all the information to be sent is created.
fn basic_call_response_impl(comm: &str, socket: &str) -> std::io::Result<()> {
    let terminated_comm = comm.to_owned() + "\n";
    let stream = &mut UnixStream::connect(socket).unwrap();
    stream.write_all(terminated_comm.as_bytes())?;
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
fn handle_watch(interval: u64, socket: &str) -> std::io::Result<()> {
    let mut values: Vec<u64> = Vec::new();
    let sleep_time = Duration::new(interval, 0);
    let mut first_run = true;

    loop {
        let stream = &mut UnixStream::connect(socket).unwrap();
        stream.write_all(format!("{}\n", RpcCommands::Counters).as_bytes())?;
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
            match one_line[0] {
                "OK" => break,
                "Uptime" => println!("Uptime: {}", one_line[1]),
                _ => {
                    let mut num: String = one_line[1].to_string();
                    num.remove(0);
                    let num_packets: u64 = num.parse().unwrap();

                    // calculate difference between current pkt nums and previous pkt nums
                    let difference = num_packets - values[n];

                    println!("{} increased by: {}", one_line[0], difference);
                    values[n] = num_packets; // store new packet counts
                }
            }
        }

        first_run = false;
        sleep(sleep_time);
    }
}

fn handle_perf_sample(duration: u64, frequency: u64, socket: &str) -> std::io::Result<()> {
    basic_command!(RpcCommands::PerfSample, socket, duration, frequency)?;

    Ok(())
}

/// Opens a capture file, sends a message to the RPC worker to prepare to receive
/// the file descriptor, upon receiving correct response, sends the fd as
/// ancillary data, and awaits response again.
fn handle_set_capture_file(file_path: String, socket: &str) -> std::io::Result<()> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(file_path)
        .unwrap();

    let mut ancillary_buffer = [0; ANCILLARY_BUFFER_SIZE];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);
    ancillary.add_fds(&[file.as_fd()]);

    let buf = [1; 1]; // Must send some data with the ancillary data
    let bufs = &mut [IoSlice::new(&buf)];

    // Establish connection with RPC worker, send command
    let stream = &mut UnixStream::connect(socket).unwrap();
    stream.write_all(format!("{}\n", RpcCommands::SetCaptureFile).as_bytes())?;
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

/// Opens capture file, sets appropriate capture program, waits a designated
/// amount of time, then closes the capture file (which also deletes the program)
fn handle_capture_sequence(
    file_path: String,
    time: u64,
    program: Option<String>,
    socket: &str,
) -> std::io::Result<()> {
    let sleep_time = Duration::new(time, 0);
    handle_set_capture_file(file_path, socket)?;
    handle_set_capture_program(program, socket)?;

    let handler = Arc::new(CtrlcHandle::new());
    let ctrlc_handler = handler.clone();
    // Will set wait to false in CtrlcHandler if ctrl+c is pressed
    ctrlc::set_handler(move || ctrlc_handler.set_false()).unwrap();
    handler.timed_wait(sleep_time);

    basic_command!(RpcCommands::CloseCaptureFile, socket)?;

    Ok(())
}

/// Converts capture program into serialized format so that the RPC worker doesn't
/// need to use the pcap library, and can just have knowledge of the serialized
/// format and use exclusively cbpf-rs
fn handle_set_capture_program(program: Option<String>, socket: &str) -> std::io::Result<()> {
    // Ensures that a program has properly been provided before sending message because
    // there is no default program
    match program {
        Some(program) => {
            let serialized_program = serialize(&program);
            basic_call_response_1(RpcCommands::SetCaptureProgram, &socket, serialized_program)?;
        }
        None => (),
    };

    Ok(())
}

fn handle_link_command(link_args: LinkArgs, socket: &str) -> std::io::Result<()> {
    match link_args.command {
        LinkCommands::Show { id: None } => basic_command!(RpcCommands::ShowLink, socket)?,
        LinkCommands::Show { id: Some(id) } => basic_command!(RpcCommands::ShowLink, socket, id)?,
        LinkCommands::Configure { id } => basic_command!(RpcCommands::ConfigureLink, socket, id)?,
        LinkCommands::Start { id } => basic_command!(RpcCommands::StartLink, socket, id)?,
        LinkCommands::Stop { id } => basic_command!(RpcCommands::StopLink, socket, id)?,
        LinkCommands::Reset { id } => basic_command!(RpcCommands::ResetLink, socket, id)?,
    }

    Ok(())
}

fn handle_logging(vec: Vec<String>, socket: &str) -> std::io::Result<()> {
    let mut new_str = String::new();

    for elem in vec {
        new_str = format!("{} {}", new_str, elem);
    }

    basic_command!(RpcCommands::SetLogging, socket, new_str)?;

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

fn generate_completion() -> std::io::Result<()> {
    let exts: Vec<&str> = Vec::from(["sh", "elv", "fish", "ps1", "zsh"]);

    for extension in exts {
        let path = format!("extensions/ph-cli.{}", extension);
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);
        generate(
            get_shell(extension).unwrap(),
            &mut CmdlineArgs::command(),
            CmdlineArgs::command().get_name().to_string(),
            &mut writer,
        );
    }

    Ok(())
}

fn get_shell(ext: &str) -> Result<Shell, &str> {
    match ext {
        "sh" => Ok(Shell::Bash),
        "elv" => Ok(Shell::Elvish),
        "fish" => Ok(Shell::Fish),
        "ps1" => Ok(Shell::PowerShell),
        "zsh" => Ok(Shell::Zsh),
        _ => Err("No shell found"),
    }
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
