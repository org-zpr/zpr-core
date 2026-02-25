//! Command enum and user-input parsing for the lntest REPL.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use tokio::sync::mpsc;
use zpr::packet_info::L3Type;
use zpr::vsapi_types::{Claim, VsapiFiveTuple};

use super::args::Config;

/// Commands that the TUI REPL can dispatch to the async handler task.
pub enum Cmd {
    /// No-op; used when a command produces output but needs no async action.
    Nop,
    /// Disconnect from the visa service and exit.
    Disconnect,
    /// Send a visa request for the given five-tuple.
    VisaRequest(VsapiFiveTuple),
    /// Register a VSS server at the given socket address.
    RegisterVss(SocketAddr),
    /// Authorize an adapter connection using the key at the path with the given claims.
    AuthorizeConnect(PathBuf, Vec<Claim>),
    /// Notify VS to disconnect the adapter at the given ZPR address.
    NotifyDisconnect(IpAddr),
}

/// Print available commands to the output channel.
pub fn help(output_tx: &mpsc::UnboundedSender<String>) {
    let lines = [
        "commands:".to_string(),
        "  h                          : print this help".to_string(),
        "  exit | quit | q            : disconnect and exit".to_string(),
        "  visa_request               : send a visa request".to_string(),
        "  register_vss [<ADDR:PORT>] : call registerVss (default sock addr is <self_addr>:8183)"
            .to_string(),
        "                               Note lntest starts a VSS server on <self_addr>:8183"
            .to_string(),
        "                               automatically at startup.".to_string(),
        "  authorize_connect <KEY_PATH> [<CLAIM> ...] :".to_string(),
        "                               authorize an adapter connection".to_string(),
        "                               Claims are key:value pairs (split on first ':')."
            .to_string(),
        "                               The endpoint.zpr.adapter.cn claim is required.".to_string(),
        "  notify_disconnect <ZPR_ADDR>  : notify VS to disconnect an adapter".to_string(),
    ];
    for line in &lines {
        let _ = output_tx.send(line.clone());
    }
}

/// Tokenize input splitting on whitespace, but keeping double-quoted substrings as single tokens.
pub fn tokenize(input: &str) -> Vec<String> {
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

/// Parse a `"<ip>:<port>"` string into its components.
pub fn parse_ipaddr_and_port(input: &str) -> Result<(IpAddr, u16), String> {
    let sockaddr: SocketAddr = input
        .parse()
        .map_err(|e| format!("invalid socket address '{}': {}", input, e))?;
    Ok((sockaddr.ip(), sockaddr.port()))
}

/// Parse a user-supplied command string and return the corresponding [Cmd].
///
/// On success, output messages are sent to `output_tx`; on failure the error
/// string is returned so the TUI can display it.
pub fn parse_command(
    cfg: &Config,
    input: &str,
    output_tx: &mpsc::UnboundedSender<String>,
) -> Result<Cmd, String> {
    let parts = tokenize(input);
    if parts.is_empty() {
        return Err("does not compte".into());
    }
    match parts[0].as_str() {
        "h" => {
            help(output_tx);
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
