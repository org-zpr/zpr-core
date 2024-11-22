//! RPC commands that can be sent to a packet handler

use strum::{Display, EnumString};

#[derive(Debug, Eq, PartialEq, EnumString, Display)]
#[strum(serialize_all = "kebab-case")]
pub enum RpcCommands {
    // TODO: Restructure the worker to accept subcommands
    CountersReset,
    Counters,
    Echo,
    PerfSample,
    SetCaptureFile,
    FlushCaptureFile,
    CloseCaptureFile,
    SetCaptureProgram,
    DeleteCaptureProgram,
    ConfigureLink,
    StartLink,
    StopLink,
    ResetLink,
}
