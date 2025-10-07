//! Tool to help debug PH
//! Note: at this moment the program can only handle one-word commands, so
//! when a command is multiple words, this program assumes the spaces are replaced
//! with a '-' on the command line
mod main_args;

use crate::main_args::{CaptureCommands, CliCommand, CmdlineArgs, Commands, LinkCommands};
use capnp_rpc::twoparty::VatId;
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

#[tokio::main]
async fn main() -> Result<(), capnp::Error> {
    let args = CmdlineArgs::parse();
    let socket = args.socket.clone();
    let cap_socket = args.cap_socket.clone();

    if let Some(command) = args.command {
        process_command(command, &socket, cap_socket).await.map(|_| {})
    } else {
        run_cli(&socket, cap_socket).await
    }
}

async fn run_cli(socket: &str, cap_socket: Option<String>) -> Result<(), capnp::Error> {
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
                return Err(capnp::Error::failed("Failed to read line".to_string()));
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
                    Err(err) => match err.extra {
                        // Quits the program if the specified port is not open
                        ref val if *val == "No such file or directory (os error 2)".to_string() => {
                            return Err(err)
                        }
                        _ => println!("Failed to parse command \"{}\".  Error: {}", line, err),
                    },
                }
            }
        }
    }
}

async fn parse_and_exec(line: &str, socket: &str, cap_socket: Option<String>) -> Result<bool, capnp::Error> {
    let args = shlex::split(line).ok_or(Error::other("Invalid quoting"))?;
    let cli = CliCommand::try_parse_from(args).map_err(|e| Error::other(e.to_string()))?;

    process_command(cli.command, socket, cap_socket).await
}

async fn process_command(command: Commands, socket: &str, cap_socket: Option<String>) -> Result<bool, capnp::Error> {
    // TODO handle error can't find sock here - need to change location because this was moved
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

    // Commands that don't need any additional data can be sent right here, those
    // with extra info get sent in their handler funcs
    match command {
        Commands::Echo => echo_task(service, rpc_system).await?,
        Commands::Counters { reset } => {
            if reset {
                counters_reset_task(service, rpc_system).await?
            } else {
                counters_task(service, rpc_system).await?
            }
        }
        Commands::Capture(capture) => match capture.command {
            CaptureCommands::SetFile { file_path } => {
                handle_set_capture_file(file_path, cap_socket)?
            }
            CaptureCommands::CloseFile => close_capture_file_task(service, rpc_system).await?,
            CaptureCommands::FlushFile => flush_capture_file_task(service, rpc_system).await?,
            CaptureCommands::SetProgram { program } => {
                set_capture_program_task(service, rpc_system, program).await?
            }
            CaptureCommands::DeleteProgram => {
                delete_capture_program_task(service, rpc_system).await?
            }
            CaptureCommands::Sequence {
                file_path,
                duration,
                program,
            } => capture_sequence_task(service, rpc_system, file_path, duration, program).await?,
        },
        Commands::Watch { interval } => watch_task(service, rpc_system, interval).await?,
        Commands::PerfSample {
            duration,
            frequency,
        } => perf_sample_task(service, rpc_system, duration, frequency).await?,
        Commands::Link(link) => match link.command {
            LinkCommands::Show { id: None } => show_link_summary_task(service, rpc_system).await?,
            LinkCommands::Show { id: Some(id) } => show_link_task(service, rpc_system, id).await?,
            LinkCommands::Configure { id } => configure_link_task(service, rpc_system, id).await?,
            LinkCommands::Start { id } => start_link_task(service, rpc_system, id).await?,
            LinkCommands::Stop { id } => stop_link_task(service, rpc_system, id).await?,
            LinkCommands::Reset { id } => reset_link_task(service, rpc_system, id).await?,
        },
        Commands::Logging { logs } => change_logging_task(service, rpc_system, logs).await?,
        Commands::Quit => return Ok(true),
    }

    Ok(false)
}

// TODO combine no arg tasks into one func w/ closure
async fn echo_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
) -> Result<(), capnp::Error> {
    // TODO perhaps make the localset around the whole match?
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);

            let request = service.echo_request();

            request.send().promise.await?;
            println!("Echo received");

            Ok(())
        })
        .await
}

async fn counters_reset_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
) -> Result<(), capnp::Error> {
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);

            let request = service.reset_counters_request();

            request.send().promise.await?;
            println!("Counters Reset");

            Ok(())
        })
        .await
}

async fn counters_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
) -> Result<(), capnp::Error> {
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);

            let request = service.counters_request();

            let response = request.send().promise.await?;
            let results = response.get()?;
            println!("Counters Reset");
            println!("{}", results.get_counts()?.to_str()?);

            Ok(())
        })
        .await
}

// TODO determine if possible to send FD through capnp or by some side channel
#[allow(dead_code)]
async fn set_capture_file_task(
    _service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
    _file_path: String,
) -> Result<(), capnp::Error> {
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);

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
        })
        .await
}

async fn close_capture_file_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
) -> Result<(), capnp::Error> {
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);

            let request = service.close_capture_file_request();

            request.send().promise.await?;
            println!("Capture file closed and capture program deleted");

            Ok(())
        })
        .await
}

async fn flush_capture_file_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
) -> Result<(), capnp::Error> {
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);

            let request = service.flush_capture_file_request();

            request.send().promise.await?;
            println!("Capture file flushed");

            Ok(())
        })
        .await
}

/// Converts capture program into serialized format so that the RPC worker doesn't
/// need to use the pcap library, and can just have knowledge of the serialized
/// format and use exclusively cbpf-rs
// TODO change parameters of set cap prog to take the actual bpf vals instead of string
async fn set_capture_program_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
    program: Option<String>,
) -> Result<(), capnp::Error> {
    // Ensures that a program has properly been provided before sending message because
    // there is no default program

    match program {
        Some(program) => {
            tokio::task::LocalSet::new()
                .run_until(async move {
                    tokio::task::spawn_local(system);
                    let serialized_program = serialize(&program);
                    let mut request = service.set_capture_program_request();
                    request
                        .get()
                        .init_program(serialized_program.len() as u32)
                        .push_str(&serialized_program);

                    let response = request.send().promise.await?;
                    let results = response.get()?;
                    match results.get_result()?.which()? {
                        cli_proto::cli_capnp::success_or_error::Which::Success(_) => {
                            println!("Capture program set")
                        }
                        cli_proto::cli_capnp::success_or_error::Which::Error(e) => {
                            let result = e.unwrap().get_txt()?.to_string()?;
                            println!("{result}");
                            return Err(capnp::Error::failed(result));
                        }
                    };
                    Ok(())
                })
                .await
        }
        // TODO probably not the best form to simply create a capnpn error out of other errors...
        // perhaps create a cutom error type enum
        // Or maybe this doesn't need to be an error - user could be able to continue putting in
        // info after they do an incorrect prog, same if invalid program above
        None => Err(capnp::Error::failed("No capture program set".to_string())),
    }
}

async fn delete_capture_program_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
) -> Result<(), capnp::Error> {
    // TODO perhaps make the localset around the whole match?
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);

            let request = service.delete_capture_program_request();

            request.send().promise.await?;
            println!("Capture program deleted");

            Ok(())
        })
        .await
}

async fn capture_sequence_task(
    _service: svc::Client,
    _system: capnp_rpc::RpcSystem<VatId>,
    _file_path: String,
    _time: u64,
    _program: Option<String>,
) -> Result<(), capnp::Error> {
    // TODO
    println!("Unimplemented");
    Ok(())
}

async fn watch_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
    interval: u64,
) -> Result<(), capnp::Error> {
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);

            let mut values: Vec<u64> = Vec::new();
            let sleep_time = Duration::new(interval, 0);
            let mut first_run = true;

            loop {
                let request = service.counters_request();
                let response = request.send().promise.await?;
                let results = response.get()?.get_counts()?.to_string()?;

                // Split up the long string with all the counts and words into a vector
                // with each line as a different index of the vector
                let counts: Vec<&str> = results.split('\n').collect(); // Split the messages

                if first_run {
                    values.resize(counts.len(), 0);
                }

                // TODO error checking, make sure actually got a message back, and that it's the correct message
                for (n, count) in counts[0..].iter().enumerate() {
                    // split up the individual lines to get the count from the end and convert to u64
                    println!("line: {count}");
                    let one_line: Vec<&str> = count.split(':').collect();
                    match one_line[0] {
                        "OK" => break,
                        "Uptime" => println!("\nUptime: {}", one_line[1]),
                        "Management counts" => println!("\nManagement counts:"),
                        "Fastpath counts" => println!("\nFastpath counts: {}", one_line[1]),
                        "" => (),
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
                sleep(sleep_time).await;
            }
        })
        .await
}

async fn perf_sample_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
    duration: u64,
    frequency: u64,
) -> Result<(), capnp::Error> {
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);
            let mut request = service.perf_sample_request();
            request.get().set_duration_secs(duration);
            request.get().set_frequency_per_sec(frequency);

            let response = request.send().promise.await?;
            let results = response.get()?;
            println!("{}", results.get_result()?.to_str()?);

            Ok(())
        })
        .await
}

async fn show_link_summary_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
) -> Result<(), capnp::Error> {
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);
            let request = service.show_link_summary_request();

            let response = request.send().promise.await?;
            let results = response.get()?;
            println!("{}", results.get_summary()?.to_str()?);

            Ok(())
        })
        .await
}

async fn show_link_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
    id: u32,
) -> Result<(), capnp::Error> {
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);
            let mut request = service.show_link_request();
            request.get().set_id(id);

            let response = request.send().promise.await?;
            let results = response.get()?;
            println!("{}", results.get_result()?.to_str()?);

            Ok(())
        })
        .await
}

async fn configure_link_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
    id: u32,
) -> Result<(), capnp::Error> {
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);
            let mut request = service.show_link_request();
            request.get().set_id(id);

            request.send().promise.await?;
            println!("Command currently unsupported");

            Ok(())
        })
        .await
}

async fn start_link_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
    id: u32,
) -> Result<(), capnp::Error> {
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);
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
                    return Err(capnp::Error::failed(result));
                }
            };

            Ok(())
        })
        .await
}

async fn stop_link_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
    id: u32,
) -> Result<(), capnp::Error> {
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);
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
                    return Err(capnp::Error::failed(result));
                }
            };

            Ok(())
        })
        .await
}

async fn reset_link_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
    id: u32,
) -> Result<(), capnp::Error> {
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);
            let mut request = service.reset_link_request();
            request.get().set_id(id);

            request.send().promise.await?;
            println!("Link reset");

            Ok(())
        })
        .await
}

async fn change_logging_task(
    service: svc::Client,
    system: capnp_rpc::RpcSystem<VatId>,
    logs: Vec<String>,
) -> Result<(), capnp::Error> {
    tokio::task::LocalSet::new()
        .run_until(async move {
            tokio::task::spawn_local(system);
            // TODO convert logging to take a List instead of a string
            let mut log_str = String::new();

            for elem in logs {
                log_str = format!("{} {}", log_str, elem);
            }

            let mut request = service.change_logging_request();
            request
                .get()
                .init_logs(log_str.len() as u32)
                .push_str(&log_str);

            let response = request.send().promise.await?;
            let results = response.get()?.get_result()?;
            if results.has_applied() {
                println!("Applied: {:?}", results.get_applied()?);
            }
            if results.has_ignored() {
                println!("Ignored: {:?}", results.get_ignored()?);
            }

            Ok(())
        })
        .await
}

/// Opens a capture file, sends a message to the RPC worker to prepare to receive
/// the file descriptor, upon receiving correct response, sends the fd as
/// ancillary data, and awaits response again.
#[allow(dead_code)]
fn handle_set_capture_file(file_path: String, cap_socket: Option<String>) -> std::io::Result<()> {
    if cap_socket.is_none() {
        return Err(Error::other("No capture file socket")); 
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
