//! Tool to help debug PH
//! Note: at this moment the program can only handle one-word commands, so
//! when a command is multiple words, this program assumes the spaces are replaced
//! with a '-' on the command line
mod main_args;

use crate::main_args::{CaptureCommands, CliCommand, CmdlineArgs, Commands, LinkCommands};
use cbpf_rs;
use clap::Parser;
use cli_proto::cli_capnp as cli;
use cli_proto::cli_capnp::cmd_line_inter as svc;
use pcap::{Capture, Linktype};
use std::borrow::Borrow;
use std::fs::OpenOptions;
use std::io;
use std::io::prelude::*;
use std::io::{BufReader, Error, IoSlice};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use thiserror::Error;
use tokio::time::{sleep, Duration};
use tokio_util::compat::*;
use zpr::rpc_commands::RpcCommands;
use zpr_ext::std::os::unix::net::{SocketAncillary, UnixStreamExt};

#[allow(unused_imports)]
use ctrlc;
#[allow(unused_imports)]
use std::sync::{Arc, Condvar, Mutex};

#[allow(dead_code)]
const ANCILLARY_BUFFER_SIZE: usize = 128;

#[derive(Error, Debug)]
enum CliError {
    #[error("Protocol error: {0}")]
    ProtocolError(#[from] capnp::Error),
    #[error("OS error: {0}")]
    OsError(#[from] std::io::Error),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("RPC error: {0}")]
    RpcError(String),
    #[error("Pcap error: {0}")]
    CaptureError(#[from] pcap::Error),
}

// thiserror does not propagate From implementations up
impl From<capnp::NotInSchema> for CliError {
    fn from(err: capnp::NotInSchema) -> Self {
        // could also use .into() instead
        CliError::ProtocolError(capnp::Error::from(err))
    }
}

impl From<std::str::Utf8Error> for CliError {
    fn from(err: std::str::Utf8Error) -> Self {
        CliError::ProtocolError(capnp::Error::from(err))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), CliError> {
    let args = CmdlineArgs::parse();
    let socket = args.socket.clone();
    let cap_socket = args.cap_socket.clone();

    if let Some(command) = args.command {
        process_command(command, &socket, cap_socket.as_deref())
            .await
            .map(|_| {})
    } else {
        run_cli(&socket, cap_socket.as_deref()).await
    }
}

async fn run_cli(socket: &str, cap_socket: Option<&str>) -> Result<(), CliError> {
    loop {
        print!("> ");
        io::stdout().flush()?;
        let mut line = String::new();
        match io::stdin().read_line(&mut line) {
            Ok(0) => {
                println!("Goodbye!");
                return Ok(());
            }
            Err(e) => {
                println!("{}", e);
                return Err(CliError::ParseError("Failed to read line".to_string()));
            }
            Ok(_) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }

                match parse_and_exec(line, socket, cap_socket.clone()).await {
                    Ok(quit) => {
                        if quit {
                            return Ok(());
                        }
                    }
                    Err(err) => match err {
                        // Quits the program if the specified port is not open
                        CliError::OsError(err) => match err.kind() {
                            std::io::ErrorKind::NotFound => return Err(CliError::OsError(err)),
                            _ => println!("Failed to parse command \"{}\".  Error: {}", line, err),
                        },
                        _ => println!("Failed to parse command \"{}\".  Error: {}", line, err),
                    },
                }
            }
        }
    }
}

async fn parse_and_exec(
    line: &str,
    socket: &str,
    cap_socket: Option<&str>,
) -> Result<bool, CliError> {
    let args = shlex::split(line).ok_or(Error::other("Invalid quoting"))?;
    let cli = CliCommand::try_parse_from(args).map_err(|e| Error::other(e.to_string()))?;

    process_command(cli.command, socket, cap_socket).await
}

async fn process_command(
    command: Commands,
    socket: &str,
    cap_socket: Option<&str>,
) -> Result<bool, CliError> {
    // Must quit immediately otherwise you get an error if the port is no longer open
    if matches!(command, Commands::Quit) {
        return Ok(true);
    }

    let sock = tokio::net::UnixStream::connect(socket).await?;
    let (reader, writer) = sock.into_split();

    let network = capnp_rpc::twoparty::VatNetwork::new(
        tokio::io::BufReader::new(reader).compat(),
        tokio::io::BufWriter::new(writer).compat_write(),
        capnp_rpc::rpc_twoparty_capnp::Side::Client,
        capnp::message::ReaderOptions::new(),
    );

    let mut rpc_system = capnp_rpc::RpcSystem::new(Box::new(network), None);

    let service: cli::cmd_line_inter::Client =
        rpc_system.bootstrap(capnp_rpc::rpc_twoparty_capnp::Side::Server);

    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(rpc_system);

            match command {
                Commands::Echo => echo_task(service).await?,
                Commands::Counters { reset } => {
                    if reset {
                        counters_reset_task(service).await?
                    } else {
                        counters_task(service).await?
                    }
                }
                Commands::Capture(capture) => match capture.command {
                    CaptureCommands::SetFile { file_path } => {
                        handle_set_capture_file(file_path, cap_socket)?
                    }
                    CaptureCommands::CloseFile => close_capture_file_task(service).await?,
                    CaptureCommands::FlushFile => flush_capture_file_task(service).await?,
                    CaptureCommands::SetProgram { program } => {
                        set_capture_program_task(service, program).await?
                    }
                    CaptureCommands::DeleteProgram => delete_capture_program_task(service).await?,
                    CaptureCommands::Sequence {
                        file_path,
                        duration,
                        program,
                    } => {
                        capture_sequence_task(service, file_path, duration, program, cap_socket)
                            .await?
                    }
                },
                Commands::Watch { interval } => watch_task(service, interval).await?,
                Commands::PerfSample {
                    duration,
                    frequency,
                } => perf_sample_task(service, duration, frequency).await?,
                Commands::Link(link) => match link.command {
                    LinkCommands::Show { id: None } => show_link_summary_task(service).await?,
                    LinkCommands::Show { id: Some(id) } => show_link_task(service, id).await?,
                    LinkCommands::Configure { id } => configure_link_task(service, id).await?,
                    LinkCommands::Start { id } => start_link_task(service, id).await?,
                    LinkCommands::Stop { id } => stop_link_task(service, id).await?,
                    LinkCommands::Reset { id } => reset_link_task(service, id).await?,
                },
                Commands::Logging { logs } => change_logging_task(service, logs).await?,
                Commands::Quit => return Ok(true), // Will never reach here
            }

            Ok(false)
        })
        .await
}

// TODO combine no arg tasks into one func w/ closure
async fn echo_task(service: svc::Client) -> Result<(), CliError> {
    let request = service.echo_request();

    request.send().promise.await?;
    println!("Echo received");

    Ok(())
}

async fn counters_reset_task(service: svc::Client) -> Result<(), CliError> {
    let request = service.reset_counters_request();

    request.send().promise.await?;
    println!("Counters Reset");

    Ok(())
}

async fn counters_task(service: svc::Client) -> Result<(), CliError> {
    let request = service.counters_request();

    let response = request.send().promise.await?;
    let results = response.get()?.get_counts()?;

    let management = results.get_management()?;
    let fastpaths = results.get_fastpaths()?;
    let uptime_sec = results.get_uptime_sec();
    let uptime_subsec_ms = results.get_uptime_subsec_ms();

    println!("Management counts:");
    let counters = management.get_counters()?;
    for counter in counters.iter() {
        println!("{}: {}", counter.get_name()?.to_str()?, counter.get_val());
    }

    for fastpath in fastpaths.iter() {
        println!("\nFastpath #{} counts:", fastpath.get_id());
        let counters = fastpath.get_counters()?;
        for counter in counters.iter() {
            println!("{}: {}", counter.get_name()?.to_str()?, counter.get_val());
        }
    }

    println!("\nUptime: {uptime_sec}.{uptime_subsec_ms}");

    Ok(())
}

// TODO determine if possible to send FD through capnp or by some side channel
#[allow(dead_code)]
async fn set_capture_file_task(_service: svc::Client, _file_path: String) -> Result<(), CliError> {
    // let mut request = service.set_capture_file_request();
    // request
    //     .get()
    //     .init_file_path(file_path.len() as u32)
    //     .push_str(&file_path);

    // let response = request.send().promise.await?;
    // let results = response.get()?;
    // match results.get_result()?.which()? {
    //     cli_proto::cli_capnp::success_or_error::Which::Success(_) => {
    //         println!("Capture file set")
    //     }
    //     cli_proto::cli_capnp::success_or_error::Which::Error(e) => {
    //         let result = e.unwrap().get_txt()?.to_string()?;
    //         return Err(capnp::Error::failed(result));
    //     }
    // };
    Ok(())
}

async fn close_capture_file_task(service: svc::Client) -> Result<(), CliError> {
    let request = service.close_capture_file_request();

    request.send().promise.await?;
    println!("Capture file closed and capture program deleted");

    Ok(())
}

async fn flush_capture_file_task(service: svc::Client) -> Result<(), CliError> {
    let request = service.flush_capture_file_request();

    request.send().promise.await?;
    println!("Capture file flushed");

    Ok(())
}

/// Converts capture program into serialized format so that the RPC worker doesn't
/// need to use the pcap library, and can just have knowledge of the serialized
/// format and use exclusively cbpf-rs
// TODO change parameters of set cap prog to take the actual bpf vals instead of string
async fn set_capture_program_task(
    service: svc::Client,
    program: Option<String>,
) -> Result<(), CliError> {
    // Ensures that a program has properly been provided before sending message because
    // there is no default program
    match program {
        Some(program) => {
            let capture = Capture::dead(Linktype::USER0)?;
            let program = capture.compile(&program, true)?;
            let instructions: &[pcap::BpfInstruction] = program.get_instructions();

            let mut request = service.set_capture_program_request();
            let mut program_request = request
                .get()
                .init_program()
                .init_bpf_prog(instructions.len() as u32);

            for (i, instruction) in instructions.iter().enumerate() {
                let insn: &cbpf_rs::BpfInsn = instruction.borrow();
                let mut insn_builder = program_request.reborrow().get(i as u32);
                insn_builder.set_code(insn.code);
                insn_builder.set_jt(insn.jt);
                insn_builder.set_jf(insn.jf);
                insn_builder.set_k(insn.k);
            }

            let response = request.send().promise.await?;
            let results = response.get()?;
            match results.get_result()?.which()? {
                cli_proto::cli_capnp::success_or_error::Which::Success(_) => {
                    println!("Capture program set")
                }
                cli_proto::cli_capnp::success_or_error::Which::Error(e) => {
                    let result = e.unwrap().get_txt()?.to_string()?;
                    println!("{result}");
                    return Err(CliError::RpcError(result));
                }
            };
            Ok(())
        }
        None => Err(CliError::ParseError("No capture program set".to_string())),
    }
}

async fn delete_capture_program_task(service: svc::Client) -> Result<(), CliError> {
    let request = service.delete_capture_program_request();

    request.send().promise.await?;
    println!("Capture program deleted");

    Ok(())
}

async fn capture_sequence_task(
    service: svc::Client,
    file_path: String,
    time: u64,
    program: Option<String>,
    cap_socket: Option<&str>,
) -> Result<(), CliError> {
    let sleep_time = Duration::new(time, 0);
    handle_set_capture_file(file_path, cap_socket)?;
    set_capture_program_task(service.clone(), program).await?;

    let handler = Arc::new(CtrlcHandle::new());
    let ctrlc_handler = handler.clone();

    // Will set wait to false in CtrlcHandler if ctrl+c is pressed
    ctrlc::set_handler(move || ctrlc_handler.set_false()).unwrap();

    handler.timed_wait(sleep_time);

    close_capture_file_task(service).await?;

    Ok(())
}

async fn watch_task(service: svc::Client, interval: u64) -> Result<(), CliError> {
    let mut mgmt_values: Vec<u64> = Vec::new();
    let mut fastpaths_values: Vec<Vec<u64>> = Vec::new();

    let sleep_time = Duration::new(interval, 0);
    let mut first_run = true;

    loop {
        let request = service.counters_request();
        let response = request.send().promise.await?;
        let results = response.get()?.get_counts()?;

        let management = results.get_management()?;
        let fastpaths = results.get_fastpaths()?;

        // Set initial counts to 0
        if first_run {
            mgmt_values.resize(management.get_counters()?.len() as usize, 0);
            fastpaths_values.resize(fastpaths.len() as usize, Vec::new());
            for (i, fastpath) in fastpaths.reborrow().iter().enumerate() {
                fastpaths_values[i].resize(fastpath.get_counters()?.len() as usize, 0)
            }
        }

        println!("Increases in management counts:");
        let counters = management.get_counters()?;
        for (i, counter) in counters.iter().enumerate() {
            println!(
                "{}: {}",
                counter.get_name()?.to_str()?,
                counter.get_val() - mgmt_values[i]
            );
            mgmt_values[i] = counter.get_val();
        }

        for (i, fastpath) in fastpaths.iter().enumerate() {
            println!("\nIncreases in Fastpath #{} counts:", fastpath.get_id());
            let counters = fastpath.get_counters()?;
            for (j, counter) in counters.iter().enumerate() {
                println!(
                    "{}: {}",
                    counter.get_name()?.to_str()?,
                    counter.get_val() - fastpaths_values[i][j]
                );
                fastpaths_values[i][j] = counter.get_val();
            }
        }

        first_run = false;
        sleep(sleep_time).await;
    }
}

async fn perf_sample_task(
    service: svc::Client,
    duration: u64,
    frequency: u64,
) -> Result<(), CliError> {
    let mut request = service.perf_sample_request();
    request.get().set_duration_secs(duration);
    request.get().set_frequency_per_sec(frequency);

    let response = request.send().promise.await?;
    let results = response.get()?;
    println!("{}", results.get_result()?.to_str()?);

    Ok(())
}

async fn show_link_summary_task(service: svc::Client) -> Result<(), CliError> {
    let request = service.show_link_summary_request();

    let response = request.send().promise.await?;
    let results = response.get()?;
    let summaries = results.get_summary()?;
    println!("Link summary:");
    for summary in summaries.iter() {
        println!("{}", summary?.to_str()?)
    }

    Ok(())
}

async fn show_link_task(service: svc::Client, id: u32) -> Result<(), CliError> {
    let mut request = service.show_link_request();
    request.get().set_id(id);

    let response = request.send().promise.await?;
    let results = response.get()?;
    println!("{}", results.get_result()?.to_str()?);

    Ok(())
}

async fn configure_link_task(service: svc::Client, id: u32) -> Result<(), CliError> {
    let mut request = service.show_link_request();
    request.get().set_id(id);

    request.send().promise.await?;
    println!("Command currently unsupported");

    Ok(())
}

async fn start_link_task(service: svc::Client, id: u32) -> Result<(), CliError> {
    let mut request = service.start_link_request();
    request.get().set_id(id);

    let response = request.send().promise.await?;
    let results = response.get()?;
    match results.get_result()?.which()? {
        cli_proto::cli_capnp::success_or_error::Which::Success(_) => {
            println!("Link {id} started")
        }
        cli_proto::cli_capnp::success_or_error::Which::Error(e) => {
            let result = e.unwrap().get_txt()?.to_string()?;
            println!("{result}");
            return Err(CliError::RpcError(result));
        }
    };

    Ok(())
}

async fn stop_link_task(service: svc::Client, id: u32) -> Result<(), CliError> {
    let mut request = service.stop_link_request();
    request.get().set_id(id);

    let response = request.send().promise.await?;
    let results = response.get()?;
    match results.get_result()?.which()? {
        cli_proto::cli_capnp::success_or_error::Which::Success(_) => {
            println!("CLink {id} stopped")
        }
        cli_proto::cli_capnp::success_or_error::Which::Error(e) => {
            let result = e.unwrap().get_txt()?.to_string()?;
            println!("{result}");
            return Err(CliError::RpcError(result));
        }
    };

    Ok(())
}

async fn reset_link_task(service: svc::Client, id: u32) -> Result<(), CliError> {
    let mut request = service.reset_link_request();
    request.get().set_id(id);

    request.send().promise.await?;
    println!("Link reset");

    Ok(())
}

async fn change_logging_task(
    service: svc::Client,
    logs: Vec<(String, String)>,
) -> Result<(), CliError> {
    // TODO convert logging to take a List instead of a string
    let mut request = service.change_logging_request();
    let mut log_builder = request.get().init_logs(logs.len() as u32);

    for (i, log) in logs.iter().enumerate() {
        let mut tuple_builder = log_builder.reborrow().get(i as u32);
        tuple_builder.set_level(&log.0);
        tuple_builder.set_target(&log.1);
    }

    let response = request.send().promise.await?;
    let results = response.get()?.get_result()?;
    if results.has_applied() {
        println!("Applied: {:?}", results.get_applied()?);
    }
    if results.has_ignored() {
        println!("Ignored: {:?}", results.get_ignored()?);
    }

    Ok(())
}

/// Opens a capture file, sends a message to the RPC worker to prepare to receive
/// the file descriptor, upon receiving correct response, sends the fd as
/// ancillary data, and awaits response again.
#[allow(dead_code)]
fn handle_set_capture_file(file_path: String, cap_socket: Option<&str>) -> Result<(), CliError> {
    if cap_socket.is_none() {
        return Err(CliError::ParseError("No capture file socket".to_string()));
    }

    let socket: &str = &cap_socket.unwrap();

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
        return Err(CliError::RpcError("Incorrect Message Received".to_string()));
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
// fn handle_capture_sequence(
//     file_path: String,
//     time: u64,
//     program: Option<String>,
//     socket: &str,
// ) -> std::io::Result<()> {
//     let sleep_time = Duration::new(time, 0);
//     handle_set_capture_file(file_path, socket)?;
//     handle_set_capture_program(program, socket)?;

//     let handler = Arc::new(CtrlcHandle::new());
//     let ctrlc_handler = handler.clone();
//     // Will set wait to false in CtrlcHandler if ctrl+c is pressed
//     ctrlc::set_handler(move || ctrlc_handler.set_false()).unwrap();
//     handler.timed_wait(sleep_time);

//     basic_command!(RpcCommands::CloseCaptureFile, socket)?;

//     Ok(())
// }

#[allow(dead_code)]
struct CtrlcHandle {
    wait: Mutex<bool>,
    cv: Condvar,
}

#[allow(dead_code)]
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
