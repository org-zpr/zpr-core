use std::path::Path;
use std::vec;
use std::{io, sync::Arc};

use tracing::{error, info};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

pub use crate::cd::config::{load_configuration, Config};
pub use crate::cd::zpr::{ConfigState, Zpr};

use super::cmonitor;

type NetWriterT = Arc<Mutex<tokio::io::BufWriter<tokio::net::unix::OwnedWriteHalf>>>;

pub async fn command_server(
    config: Arc<Config>,
    zpr: Zpr,
    token: CancellationToken,
    monitor_ctrl: Sender<cmonitor::Command>,
) -> io::Result<()> {
    info!(
        "starting command server on {}",
        config.socket_path.display()
    );
    let listener = UnixListener::bind(config.socket_path.clone())?;
    loop {
        tokio::select! {
            _ = token.cancelled() => {
                info!("command server is cancelled");
                return Ok(());
            }
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        info!("accepted command connection");
                        let zpr = zpr.clone();
                        let mctrl = monitor_ctrl.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_command_connection(stream, zpr, mctrl).await {
                                error!("Error handling command connection: {}", e);
                            }
                        });
                    },
                    Err(e) => {
                        error!("Error accepting command connection: {}", e);
                        return Err(e);
                    }
                }
            }
        }
    }
}

// A command message is one line of text terminated with "\n".
// A response is multi line with the first line just being the integer number of lines to follow.
// Also, line 2 is always OK or ERR.
//
// For example:
//
//      2
//      OK
//      explanatory message here
//
async fn handle_command_connection(
    stream: tokio::net::UnixStream,
    zpr: Zpr,
    monitor_ctrl: Sender<cmonitor::Command>,
) -> io::Result<()> {
    let (reader, send) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(reader);

    let writer = tokio::io::BufWriter::new(send);
    let writer = Arc::new(Mutex::new(writer));

    let mut line = String::new();

    line.clear();
    let n = reader.read_line(&mut line).await?;
    if n > 0 {
        let line = line.trim();
        if line.is_empty() {
            error!("empty line received");
        } else {
            let parts: Vec<&str> = line.split_whitespace().collect();
            match parts[0] {
                "status" => handle_status(Arc::clone(&writer), zpr).await?,
                "connect" => handle_connect(&parts, Arc::clone(&writer), zpr, monitor_ctrl).await?,
                "disconnect" => {
                    handle_disconnect(&parts, Arc::clone(&writer), zpr, monitor_ctrl).await?
                }
                _ => {
                    let mut ww = writer.lock().await;
                    ww.write_all(b"2\nERR\nunknown command\n").await?;
                }
            }
        }
    }
    writer.lock().await.flush().await?;
    Ok(())
}

async fn handle_status(writer: NetWriterT, zpr: Zpr) -> Result<(), io::Error> {
    let stats = zpr.get_status();

    let mut writer = writer.lock().await;

    if stats.is_empty() {
        writer.write_all(b"2\nOK\nno configurations\n").await?;
        return Ok(());
    }
    writer
        .write_all(format!("{}\nOK\n", stats.len() + 1).as_bytes())
        .await?;
    for (cname, cpath, cstat) in &stats {
        writer
            .write_all(format!("{}: {} - {}\n", cname, cpath, cstat).as_bytes())
            .await?;
    }
    writer.flush().await?;
    Ok(())
}

async fn handle_connect(
    parts: &[&str],
    writer: NetWriterT,
    zpr: Zpr,
    monitor_ctrl: Sender<cmonitor::Command>,
) -> Result<(), io::Error> {
    let mut writer = writer.lock().await;
    if parts.len() < 2 {
        writer
            .write_all(b"2\nERR\nconnect requires a configuration path or name\n")
            .await?;
        return Err(io::Error::new(io::ErrorKind::Other, "argument error"));
    }

    // Determine if it is a name of existing or a path to a new one.
    // Our approach - if the name is found in our configuration list then use it as a name, else assume a path.

    let cname: String;

    if !zpr.has_configuration(parts[1]) {
        info!(
            "configuration not found '{}', attempting to load as file",
            parts[1]
        );
        let configuration = match load_configuration(Path::new(parts[1])) {
            Ok(c) => c,
            Err(e) => {
                error!("Error loading configuration {}: {}", parts[1], e);
                let emsg = e.to_string().replace('\n', " ");
                writer
                    .write_all(format!("2\nERR\n{}\n", emsg).as_bytes())
                    .await?;
                return Err(io::Error::new(io::ErrorKind::Other, e));
            }
        };

        cname = configuration.get_name().to_string();

        // install the configuration
        match zpr.add_configuration(configuration) {
            Ok(()) => (),
            Err(e) => {
                let emsg = e.to_string().replace('\n', " ");
                writer
                    .write_all(format!("2\nERR\n{}\n", emsg).as_bytes())
                    .await?;
                return Err(io::Error::new(io::ErrorKind::Other, e));
            }
        }
    } else {
        cname = parts[1].to_string();
    }

    match monitor_ctrl
        .send(cmonitor::Command::Connect(cname.clone()))
        .await
    {
        Ok(()) => (),
        Err(e) => {
            error!("Error sending connect command to monitor: {}", e);
            writer
                .write_all(b"2\nERR\nerror sending connect command\n")
                .await?;
            return Err(io::Error::new(io::ErrorKind::Other, e));
        }
    }

    writer
        .write_all(format!("2\nOK\nconnect starting for {}\n", cname).as_bytes())
        .await?;
    Ok(())
}

async fn handle_disconnect(
    parts: &[&str],
    writer: NetWriterT,
    zpr: Zpr,
    monitor_control: Sender<cmonitor::Command>,
) -> Result<(), io::Error> {
    let mut writer = writer.lock().await;

    let mut all = true;
    let mut cname = "";

    if parts.len() > 1 {
        all = false;
        cname = parts[1];
    }

    let mut fails = vec![];
    let mut successes = vec![];

    for name in zpr.get_configuration_names() {
        if let Some(cs) = zpr.get_configuration_state(&name) {
            let is_connected = match cs {
                ConfigState::Connected { .. } | ConfigState::Connecting => true,
                _ => false,
            };
            if is_connected {
                match monitor_control
                    .send(cmonitor::Command::Disconnect(name.clone()))
                    .await
                {
                    Ok(()) => {
                        successes.push(name);
                    }
                    Err(e) => {
                        error!("Error sending disconnect command to monitor: {}", e);
                        writer
                            .write_all(b"2\nERR\nerror sending disconnect command\n")
                            .await?;
                        fails.push(name);
                    }
                }
            }
        }
    }

    let stats_total = fails.len() + successes.len();
    if stats_total == 0 {
        if all {
            writer
                .write_all("1\nERR\nnothing connected".as_bytes())
                .await?;
        } else {
            writer
                .write_all(format!("1\nERR\n{} is not connected", cname).as_bytes())
                .await?;
        }
    } else {
        writer
            .write_all(format!("{}\nOK\n", stats_total + 1).as_bytes())
            .await?;
        for name in &successes {
            writer
                .write_all(format!("{}: disconnect requested\n", name).as_bytes())
                .await?;
        }
        for name in &fails {
            writer
                .write_all(format!("{}: disconnect ERROR\n", name).as_bytes())
                .await?;
        }
    }

    Ok(())
}
