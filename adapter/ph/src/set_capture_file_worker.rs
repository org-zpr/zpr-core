//! Receives commands, either from the cli or from someone directly interfacing
//! with the socket, performs action based on received command
//! To avoid excess parsing, the command must not have spaces


use crate::assembly::Assembly;
use crate::config;
use crate::logging::targets::RPC;
use std::io::Error;
use std::io::IoSliceMut;
use std::str::FromStr;
use std::sync::Arc;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinSet;
use tracing::error;
use zpr::rpc_commands::RpcCommands;
use zpr_ext::std::os::unix::net::{AncillaryData, SocketAncillary};
use zpr_ext::tokio::net::*;

pub async fn launch(asm: Arc<Assembly>, socket: Arc<UnixListener>) {
    let mut set = JoinSet::<Result<(), Error>>::new();

    // Continuously looks for a connection to the socket, allows for concurrent connections
    loop {
        tokio::select! {
            // Collecting state of completed task ensures that return code doesn't
            // just sit in JoinSet forever
            Some(ret) = set.join_next() =>
                match ret {
                    Ok(Ok(())) => (),
                    Ok(Err(err)) => error!(target: RPC, "Handle Connection Failed: {err}"),
                    Err(err) => error!(target: RPC, "join_next panicked: {err}")
                },
            accepted = socket.accept() =>
                match accepted {
                    Ok((stream, _addr)) => {
                        set.spawn_local(handle_connection(asm.clone(), stream));
                    },
                    Err(_e) => {
                        error!(target: RPC, "Connection failed");
                    }
            }
        }
    }
}

async fn handle_connection(asm: Arc<Assembly>, mut stream: UnixStream) -> std::io::Result<()> {
    let mut str_message = String::new();

    let split_buf = stream.split(); // split stream into read/write streams
    let mut buf_reader = BufReader::new(split_buf.0);
    let mut buf_writer = BufWriter::new(split_buf.1);
    buf_reader.read_line(&mut str_message).await?;

    let last_let = str_message.pop(); // Removes \n from end of string
    if last_let != Some('\n') {
        // close stream then skip the rest of the loop and moves to next iteration
        buf_writer.shutdown().await?;
    } else {
        buf_writer.write("Message Received\n".as_bytes()).await?;

        // Separate command from any other information associated with the command
        let vec_message: Vec<&str> = str_message.split_whitespace().collect();
        match RpcCommands::from_str(vec_message[0]) {
            // SET-CAPTURE-FILE <file_path>
            Ok(RpcCommands::SetCaptureFile) => {
                // Tell debug tool we're ready for the ancillary data
                buf_writer.write_all("SEND ANCILLARY\n".as_bytes()).await?;
                buf_writer.flush().await?;

                // Receive ancillary data
                let mut ancillary_buffer = [0; config::ANCILLARY_BUFFER_SIZE];
                let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);
                let mut buf = [0; 1]; // Must receive data sent with ancillary data
                let bufs = &mut [IoSliceMut::new(&mut buf)][..];
                buf_reader
                    .into_inner()
                    .as_ref()
                    .recv_vectored_with_ancillary(bufs, &mut ancillary)
                    .await?;

                // Set capture file using ancillary data
                buf_writer
                    .write_all(set_capture_file(&asm, ancillary).await.as_bytes())
                    .await?;
                buf_writer.write_all("OK\n".as_bytes()).await?
            },
            _ => buf_writer.write_all("ERR\n".as_bytes()).await?,
        };

        buf_writer.flush().await?;
        buf_writer.shutdown().await?;
    }

    Ok(())
}
// Takes in ancillary data, extracts the file descriptor, and creates a file using the
// fd
async fn set_capture_file(asm: &Assembly, ancillary: SocketAncillary<'_>) -> String {
    // Get the ancillary data
    let anc_message = ancillary.into_messages().nth(0).unwrap();
    // Get the SCM rights from the ancillary data
    if let AncillaryData::ScmRights(mut scm_rights) = anc_message.unwrap() {
        // See if there's actually data in the scm_rights, if yes try to open a
        // capture file, otherwise report failure to open file
        match scm_rights.nth(0) {
            Some(fd) => {
                let std_file = std::fs::File::from(fd.try_into_owned().unwrap()); // tokio::fs::File doesn't implement From<OwnedFd>
                let tokio_file = File::from(std_file);
                match asm.capture_worker.open_capture_file(tokio_file).await {
                    Ok(()) => format!("Capture file opened\n"),
                    Err(err) => format!("Error opening Capture file: {}\n", err),
                }
            }
            None => format!("Error opening Capture file: no ancillary data received\n"),
        }
    } else {
        format!("Error opening Capture file: no ancillary data received\n")
    }
}