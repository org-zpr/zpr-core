use std::path::PathBuf;
use clap::{Args, Parser, Subcommand};

use admin_api::get_data_home;

#[derive(Parser, Debug)]
#[command(version, about = "This program controls the RPC calls to the ZPR Packet Handler\nRun without a command to enter CLI mode", long_about = None)]
pub struct CmdlineArgs {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to the Packet Handler's management socket
    #[arg(long, short = 'p', default_value_os_t = get_data_home().join("control.sock"))]
    pub socket: PathBuf,

    /// Path to the Packet Handler's capture socket, only necessary when performing Capture commands
    #[arg(long, short = 'c')]
    pub cap_socket: Option<PathBuf>,
}

#[derive(Parser, Debug)]
#[command(multicall = true)]
pub struct CliCommand {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
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
    /// Format: logging [<level>=<target>]*
    /// There must be at least level, target pair
    /// The options for targets are:
    ///     all, capture, datapath, flow_mgmt, link_state,
    ///     mgmt_events, net_os, peer_mgmt, reporting, rpc,
    ///     startup, visa_mgmt, zdp
    /// The options for levels are:
    ///     OFF, ERROR, WARN, INFO, DEBUG, TRACE
    Logging {
        #[arg(required = true, value_delimiter = ' ', num_args = 1.., value_parser = parse_key_val, verbatim_doc_comment)]
        logs: Vec<(String, String)>,
    },
    /// Exit the CLI
    Quit,
}

#[derive(Debug, Args)]
#[command(flatten_help = true)]
pub struct CaptureArgs {
    #[command(subcommand)]
    pub command: CaptureCommands,
}

#[derive(Debug, Subcommand)]
pub enum CaptureCommands {
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
pub struct LinkArgs {
    #[command(subcommand)]
    pub command: LinkCommands,
}

#[derive(Debug, Subcommand)]
pub enum LinkCommands {
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

fn parse_key_val(s: &str) -> Result<(String, String), String> {
    let key_val: Vec<&str> = s.split("=").collect();
    match key_val.len() {
        2 => {
            return Ok((key_val[0].to_string(), key_val[1].to_uppercase()));
        }
        1 => {
            return Ok(("all".to_string(), key_val[0].to_uppercase()));
        }
        _ => Err(format!("Invalid key-value pair")),
    }
}