use clap::Parser;
use ipnet::IpNet;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::Level;
use tracing::{error, info};
use tracing_subscriber::{filter::LevelFilter, fmt, prelude::*};

use libnode2::vsconn::{VSConn, VSConnectRequest, VSDisconnectNotice, VSVisaRequest};
use zpr::packet_info::L3Type;
use zpr::vsapi_types::{
    AuthBlob, ChallengeAlg, Claim, CommFlag, ConnectRequest, DisconnectReason, PacketDesc,
    SelfSignedBlob, VisaOp, VsapiFiveTuple,
};

use libnode2::vss::{ListProcessingResponse, VSSMessage, launch_vss};

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

struct Config {
    node_zpr_addr: IpAddr,
}

enum Cmd {
    Nop,
    Disconnect,
    VisaRequest(VsapiFiveTuple),
    RegisterVss(SocketAddr),
    AuthorizeConnect(PathBuf, Vec<Claim>),
    NotifyDisconnect(IpAddr),
}

fn help() {
    println!("commands:");
    println!("  h                          : print this help");
    println!("  exit | quit | q            : disconnect and exit");
    println!("  visa_request               : send a visa request");
    println!(
        "  register_vss [<ADDR:PORT>] : call registerVss (default sock addr is <self_addr>:8183)"
    );
    println!("                               Note lntest starts a VSS server on <self_addr>:8183");
    println!("                               automatically at startup so adding a socket addr is");
    println!("                               only serves to send bad data to the visa service.");
    println!("  authorize_connect <KEY_PATH> [<CLAIM> ...] :");
    println!("                               authorize an adapter connection");
    println!("                               Claims are key:value pairs (split on first ':').");
    println!("                               The endpoint.zpr.adapter.cn claim is required.");
    println!(
        "                               Example: authorize_connect /path/to/adapter.key endpoint.zpr.adapter.cn:adapter1 zpr.addr:fd5a::100"
    );
    println!("  notify_disconnect <ZPR_ADDR>  : notify VS to disconnect an adapter");
}

/// Tokenize input splitting on whitespace, but keeping double-quoted substrings as single tokens.
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for ch in input.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            c if c.is_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn parse_ipaddr_and_port(input: &str) -> Result<(IpAddr, u16), String> {
    let sockaddr: SocketAddr = input
        .parse()
        .map_err(|e| format!("invalid socket address '{}': {}", input, e))?;
    Ok((sockaddr.ip(), sockaddr.port()))
}

/// Parse user input and return a "command".
fn parse_command(cfg: &Config, input: &str) -> Result<Cmd, String> {
    let parts = tokenize(input);
    if parts.is_empty() {
        return Err("does not compte".into());
    }
    match parts[0].as_str() {
        "h" => {
            help();
            Ok(Cmd::Nop)
        }

        "exit" | "quit" | "q" => Ok(Cmd::Disconnect),

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

            let (src_ip, src_port) = parse_ipaddr_and_port(&parts[2])?;
            let (dst_ip, dst_port) = parse_ipaddr_and_port(&parts[3])?;

            Ok(Cmd::VisaRequest(VsapiFiveTuple::new(
                L3Type::new_from_addr(&src_ip),
                src_ip,
                dst_ip,
                protocol,
                src_port,
                dst_port,
            )))
        }

        "register_vss" => {
            let saddr: SocketAddr = if parts.len() == 2 {
                parts[1]
                    .parse()
                    .map_err(|e| format!("invalid socket address '{}': {}", parts[1], e))?
            } else if parts.len() > 2 {
                return Err("usage: register_vss [<ADDR:PORT>]".into());
            } else {
                // Default to self address with port 8183
                SocketAddr::new(cfg.node_zpr_addr, 8183)
            };
            Ok(Cmd::RegisterVss(saddr))
        }

        "authorize_connect" => {
            if parts.len() < 2 {
                return Err("usage: authorize_connect <KEY_PATH> [<key:value> ...]".to_string());
            }
            let key_path = PathBuf::from(&parts[1]);
            let mut claims = Vec::new();
            for token in &parts[2..] {
                if let Some((key, value)) = token.split_once(':') {
                    claims.push(Claim {
                        key: key.to_string(),
                        value: value.to_string(),
                    });
                } else {
                    return Err(format!(
                        "invalid claim '{}': expected key:value format",
                        token
                    ));
                }
            }
            Ok(Cmd::AuthorizeConnect(key_path, claims))
        }

        "notify_disconnect" => {
            if parts.len() != 2 {
                return Err("usage: notify_disconnect <ZPR_ADDR>".to_string());
            }
            let addr: IpAddr = parts[1]
                .parse()
                .map_err(|e| format!("invalid ZPR address '{}': {}", parts[1], e))?;
            Ok(Cmd::NotifyDisconnect(addr))
        }

        _ => Err("does not compute: type 'h' for help".into()),
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    enable_logging();

    let vs_sa: SocketAddr = args.vs_addr.parse().expect("failed to parse vs-addr");
    let node_zpr_addr: IpAddr = args.self_addr.parse().expect("failed to parse self_addr");
    let node_aaa_prefix: IpNet = args.aaa_prefix.parse().expect("failed to parse aaa_prefix");

    let cfg = Config { node_zpr_addr };

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

    let (vss_tx, mut vss_rx) = mpsc::channel(32);
    // Launch VSS server
    let vss_aborter = {
        let vss_saddr = SocketAddr::new(node_zpr_addr, 8183);
        info!("launching VSS server on {}", vss_saddr);
        js.spawn_local(async move {
            launch_vss(&vss_saddr, vss_tx).await.map_err(|e| {
                error!("VSS server exited with error: {:?}", e);
                e
            })
        })
    };

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
                            Cmd::Nop => {}
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
                            },
                            Cmd::RegisterVss(saddr) => {
                                let res = handle.register_vss(saddr).await;
                                match res {
                                    Ok(ops) => {
                                        println!("register_vss succeeded: got {} VisaOps", ops.len());
                                        for vo in &ops {
                                            match vo {
                                                VisaOp::Grant(v) => {
                                                    println!("  visa id: {}", v.issuer_id);
                                                }
                                                VisaOp::RevokeVisaId(vid) => {
                                                    println!("  revoke visa id: {}", vid);
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        println!("register_vss failed: {:?}", e);
                                    }
                                }
                            },
                            Cmd::NotifyDisconnect(zpr_addr) => {
                                let notice = VSDisconnectNotice {
                                    zpr_addr: Some(zpr_addr),
                                    reason: DisconnectReason::Admin,
                                };
                                match handle.notify_disconnect(notice).await {
                                    Ok(()) => println!("notify_disconnect succeeded"),
                                    Err(e) => println!("notify_disconnect failed: {:?}", e),
                                }
                            },
                            Cmd::AuthorizeConnect(key_path, claims) => {
                                let adapter_key = match load_private_key(&key_path) {
                                    Ok(k) => k,
                                    Err(e) => {
                                        println!("failed to load adapter key: {}", e);
                                        continue;
                                    }
                                };

                                let cn = match claims.iter().find(|c| c.key == "endpoint.zpr.adapter.cn") {
                                    Some(c) => c.value.clone(),
                                    None => {
                                        println!("error: endpoint.zpr.adapter.cn claim is required");
                                        continue;
                                    }
                                };

                                let blob = match build_self_signed_blob(&cn, &adapter_key) {
                                    Ok(b) => b,
                                    Err(e) => {
                                        println!("failed to build self-signed blob: {}", e);
                                        continue;
                                    }
                                };

                                let mut rand_octets = [0u8; 3];
                                rand_bytes(&mut rand_octets).unwrap();
                                let substrate_addr = IpAddr::V4(Ipv4Addr::new(
                                    10, rand_octets[0], rand_octets[1], rand_octets[2],
                                ));

                                let connect_req = ConnectRequest {
                                    blobs: vec![AuthBlob::SS(blob)],
                                    claims,
                                    substrate_addr,
                                    dock_interface: 0,
                                };

                                match handle.authorize_connect(connect_req).await {
                                    Ok(conn) => {
                                        println!(
                                            "authorize_connect succeeded: zpr_addr={}, auth_expires={}",
                                            conn.zpr_addr, conn.auth_expires
                                        );
                                    }
                                    Err(e) => {
                                        println!("authorize_connect failed: {:?}", e);
                                    }
                                }
                            },
                        }
                    }
                    Some(vss_msg) = vss_rx.recv() => {
                        match vss_msg {
                            VSSMessage::PushVisaOp(visa_ops, resp_tx) => {
                                println!("[VSS incomming] PushVisaOp with {} ops", visa_ops.len());
                                let _ = resp_tx.send(ListProcessingResponse::Ack { processed: visa_ops.len() as u32});
                            }
                            VSSMessage::RevokeAuth(ip_addrs, resp_tx) => {
                                println!("[VSS incomming] RevokeAuth for {} addresses", ip_addrs.len());
                                let _ = resp_tx.send(ListProcessingResponse::Ack { processed: ip_addrs.len() as u32});
                            }
                            VSSMessage::SetServices(version, services, resp_tx) => {
                                println!("[VSS incomming] SetServices v{} with {} services", version, services.len());
                                let _ = resp_tx.send(Ok(()));
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
        vss_aborter.abort();

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
                    match parse_command(&cfg, trimmed) {
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

fn build_self_signed_blob(
    cn: &str,
    private_key: &PKey<Private>,
) -> Result<SelfSignedBlob, Box<dyn std::error::Error>> {
    let mut challenge = vec![0u8; 32];
    rand_bytes(&mut challenge)?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Sign: timestamp_be(8) + cn_utf8(var) + challenge(32)
    let mut data = Vec::new();
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.extend_from_slice(cn.as_bytes());
    data.extend_from_slice(&challenge);

    let mut signer = Signer::new(MessageDigest::sha256(), private_key)?;
    signer.update(&data)?;
    let raw_signature = signer.sign_to_vec()?;

    // VS decodes base64 from the signature field before verifying.
    let b64_signature = openssl::base64::encode_block(&raw_signature);

    Ok(SelfSignedBlob {
        alg: ChallengeAlg::RsaSha256Pkcs1v15,
        challenge,
        cn: cn.to_string(),
        timestamp,
        signature: b64_signature.into_bytes(),
    })
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
