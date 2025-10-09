use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(version, about = "This program controls the RPC calls to the ZPR Packet Handler\nRun without a command to enter CLI mode", long_about = None)]
pub struct CmdlineArgs {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Path to the Packet Handler's management socket
    #[arg(long, short = 'p', default_value = "/var/run/zpr/ph.sock")]
    pub socket: String,

    /// Path to the Packet Handler's management socket
    #[arg(long, short = 'c')]
    pub cap_socket: Option<String>,
}

#[derive(Parser, Debug)]
#[command(multicall = true)]
pub struct CliCommand {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, PartialEq)]
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
    Logging {
        #[arg(required = true)]
        logs: Vec<String>,
    },
    /// Exit the CLI
    Quit,
}

#[derive(Debug, Args, PartialEq)]
#[command(flatten_help = true)]
pub struct CaptureArgs {
    #[command(subcommand)]
    pub command: CaptureCommands,
}

#[derive(Debug, Subcommand, PartialEq)]
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

#[derive(Debug, Args, PartialEq)]
#[command(flatten_help = true)]
pub struct LinkArgs {
    #[command(subcommand)]
    pub command: LinkCommands,
}

#[derive(Debug, Subcommand, PartialEq)]
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
