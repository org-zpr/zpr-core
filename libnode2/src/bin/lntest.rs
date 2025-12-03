use clap::Parser;
use ipnet::IpNet;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::Level;
use tracing::{error, info};
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*};

use libnode2::vsconn::{VSConn, VSConnectRequest, VSVisaRequest};
use zpr::L3Type;
use zpr::vsapi_types::{CommFlag, PacketDesc, VsapiFiveTuple};

/// lntest: test tool for libnode2
///
/// This will attempt to register as a node to the visa service.
///
#[derive(Parser, Debug)]
#[command(name = "lntest")]
#[command(version, verbatim_doc_comment)]
struct Args {
    /// Address of the visa service VS-API endpoint in 'HOST:PORT' format.
    #[arg(short = 'a', long, default_value = "[fd5a:5052::1]:5002")]
    vs_addr: String,

    /// Value to present to visa service as the node's common name.
    #[arg(short, long)]
    node_cn: String,

    /// Path to the nodes private key.
    #[arg(short, long)]
    private_key: PathBuf,

    /// Nodes ZPR address to present to the visa service.
    #[arg(long, default_value = "fd5a:5052:90de::1")]
    self_addr: String,

    /// Node AAA prefix to present to the visa service.
    #[arg(long, default_value = "fd5a:5052:90de:0::/64")]
    aaa_prefix: String,
}

enum Cmd {
    Disconnect,
    VisaRequest(VsapiFiveTuple),
}

fn parse_ipaddr_and_port(input: &str) -> Result<(IpAddr, u16), String> {
    let sockaddr: SocketAddr = input
        .parse()
        .map_err(|e| format!("invalid socket address '{}': {}", input, e))?;
    Ok((sockaddr.ip(), sockaddr.port()))
}

fn parse_command(input: &str) -> Result<Cmd, String> {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return Err("does not compte".into());
    }
    match parts[0] {
        "exit" | "quit" | "q" => Ok(Cmd::Disconnect),

        // TODO: parse quit here too
        "visa_request" => {
            if parts.len() != 4 {
                return Err(
                    "usage: visa_request (TCP|UDP|ICMP6) <src_ip>:<src_port> <dst_ip>:<dst_port>"
                        .to_string(),
                );
            }
            let protocol = match parts[1].trim() {
                "TCP" | "tcp" => 6,
                "UDP" | "udp" => 17,
                "ICMP6" | "icmp6" => 58,
                _ => return Err("protocol must be TCP, UDP, or ICMP6".to_string()),
            };

            let (src_ip, src_port) = parse_ipaddr_and_port(parts[2])?;
            let (dst_ip, dst_port) = parse_ipaddr_and_port(parts[3])?;

            Ok(Cmd::VisaRequest(VsapiFiveTuple::new(
                L3Type::new_from_addr(&src_ip),
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
            )))
        }
        _ => Err("does not compute".into()),
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    enable_logging();

    let vs_sa: SocketAddr = args.vs_addr.parse().expect("failed to parse vs-addr");
    let node_zpr_addr: IpAddr = args.self_addr.parse().expect("failed to parse self_addr");
    let node_aaa_prefix: IpNet = args.aaa_prefix.parse().expect("failed to parse aaa_prefix");

    let mut vsc = VSConn::new(
        8,
        vs_sa,
        args.node_cn,
        load_private_key(&args.private_key).expect("failed to load private key"),
    );

    let handle = vsc.handle();

    let local_set = tokio::task::LocalSet::new();
    let _local_set_guard = local_set.enter();
    let mut js = JoinSet::new();

    js.spawn_local(async move {
        info!("starting the VSConn");
        vsc.run().await.map_err(|e| {
            error!("VSConn run loop exited with error: {:?}", e);
            e
        })
    });

    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<Cmd>();

    js.spawn(async move {
        // Pause briefly to allow VSConn to start up.
        info!("allowing VSConn to start up...");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let request = VSConnectRequest {
            zpr_addr: node_zpr_addr,
            aaa_prefix: node_aaa_prefix,
        };

        info!("requesting a connect");
        let mut connected = false;
        match handle.connect(request).await {
            Ok(resp) => {
                info!("Connection response: {:?}", resp);
                println!("connected");
                connected = true;
            }
            Err(e) => {
                error!("connection failed: {:?}", e);
                println!("connection failed: {:?}", e);
            }
        }

        if connected {
            loop {
                tokio::select! {
                    Some(cmd) = cmd_rx.recv() => {
                        match cmd {
                            Cmd::Disconnect => break,
                            Cmd::VisaRequest(five_tuple) => {
                                let pdesc = PacketDesc {
                                    five_tuple,
                                    comm_flags: CommFlag::BiDirectional, // TODO
                                };
                                let req = VSVisaRequest {
                                    pdesc,
                                    previous_id: None, // TODO
                                };
                                let reply = handle.visa_request(req).await;
                                match reply {
                                    Ok(decision) => {
                                        println!("visa_request decision: {:?}", decision);
                                    }
                                    Err(e) => {
                                        println!("visa_request failed: {:?}", e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        info!("requesting a stop");
        match handle.stop(true).await {
            Ok(_) => {
                info!("stopped VSConn");
                println!("stopped vsconn");
            }
            Err(e) => {
                error!("failed to stop VSConn: {:?}", e);
                println!("failed to stop VSConn: {:?}", e);
            }
        }

        Ok(())
    });

    // The readline loop is blocking.
    js.spawn_blocking(move || {
        let mut rl = DefaultEditor::new().unwrap();
        let mut do_disconnect = false;
        loop {
            let readline = rl.readline("lntest> ");
            match readline {
                Ok(line) => {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    rl.add_history_entry(trimmed).unwrap();
                    match parse_command(trimmed) {
                        Ok(cmd) => match cmd {
                            Cmd::Disconnect => {
                                do_disconnect = true;
                            }
                            _ => {
                                if let Err(e) = cmd_tx.send(cmd) {
                                    println!("failed to send command: {:?}", e);
                                    do_disconnect = true;
                                }
                            }
                        },
                        Err(e) => {
                            println!("{e}");
                        }
                    }
                }
                Err(ReadlineError::Interrupted) => {
                    // ^C
                    do_disconnect = true;
                }
                Err(ReadlineError::Eof) => {
                    // ^D
                    do_disconnect = true;
                }
                Err(err) => {
                    println!("error: {:?}", err);
                    do_disconnect = true;
                }
            }
            if do_disconnect {
                if let Err(e) = cmd_tx.send(Cmd::Disconnect) {
                    println!("failed to send disconnect command: {:?}", e);
                }
                break;
            }
        }
        Ok(())
    });

    local_set
        .run_until(async move {
            while let Some(res) = js.join_next().await {
                match res {
                    Ok(_) => (),
                    Err(e) => {
                        error!("task failed: {:?}", e);
                    }
                }
            }
        })
        .await;
}

fn load_private_key(keyfile: &Path) -> Result<PKey<Private>, Box<dyn std::error::Error>> {
    let key_data = fs::read(keyfile)?;
    let rsa = Rsa::private_key_from_pem(&key_data)?;
    let pkey = PKey::from_rsa(rsa)?;
    Ok(pkey)
}

pub fn enable_logging() {
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(LevelFilter::from_level(Level::DEBUG)),
    )
    .expect("setting default subscriber failed");
}
