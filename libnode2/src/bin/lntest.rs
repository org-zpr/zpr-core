use clap::Parser;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen},
};
use tui_input::{Input, InputRequest, backend::crossterm::EventHandler};
use ipnet::IpNet;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rand::rand_bytes;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::fs;
use std::io::stdout;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;
use tracing::{Level, error, info, warn};
use tracing_subscriber::{filter::LevelFilter, prelude::*};

use libnode2::vsconn::{
    VSConn, VSConnLifecycleEvent, VSConnectRequest, VSDisconnectNotice, VSVisaRequest,
};
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

/// Shared log buffer for the TUI log pane.
#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<String>>>);

impl LogBuffer {
    fn push(&self, line: String) {
        self.0.lock().unwrap().push(line);
    }

    fn drain_into(&self, dest: &mut Vec<String>) {
        let mut buf = self.0.lock().unwrap();
        dest.append(&mut *buf);
    }
}

/// Custom tracing layer that captures log records into a LogBuffer.
struct TuiLogLayer {
    buf: LogBuffer,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for TuiLogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let meta = event.metadata();
        let level = meta.level();
        let target = meta.target();

        struct Visitor(String);
        impl tracing::field::Visit for Visitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "message" {
                    self.0 = format!("{:?}", value);
                    // Remove surrounding quotes added by debug formatting of &str
                    if self.0.starts_with('"') && self.0.ends_with('"') && self.0.len() >= 2 {
                        self.0 = self.0[1..self.0.len() - 1].to_string();
                    }
                }
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "message" {
                    self.0 = value.to_string();
                }
            }
        }

        let mut visitor = Visitor(String::new());
        event.record(&mut visitor);

        let line = format!("[{level}] {target}: {}", visitor.0);
        self.buf.push(line);
    }
}

fn help(output_tx: &mpsc::UnboundedSender<String>) {
    let lines = [
        "commands:".to_string(),
        "  h                          : print this help".to_string(),
        "  exit | quit | q            : disconnect and exit".to_string(),
        "  visa_request               : send a visa request".to_string(),
        "  register_vss [<ADDR:PORT>] : call registerVss (default sock addr is <self_addr>:8183)".to_string(),
        "                               Note lntest starts a VSS server on <self_addr>:8183".to_string(),
        "                               automatically at startup.".to_string(),
        "  authorize_connect <KEY_PATH> [<CLAIM> ...] :".to_string(),
        "                               authorize an adapter connection".to_string(),
        "                               Claims are key:value pairs (split on first ':').".to_string(),
        "                               The endpoint.zpr.adapter.cn claim is required.".to_string(),
        "  notify_disconnect <ZPR_ADDR>  : notify VS to disconnect an adapter".to_string(),
    ];
    for line in &lines {
        let _ = output_tx.send(line.clone());
    }
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
fn parse_command(
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

struct App {
    log_lines: Vec<String>,
    output_lines: Vec<String>,
    input: Input,
    history: Vec<String>,
    history_idx: Option<usize>,
    should_quit: bool,
}

impl App {
    fn new() -> Self {
        App {
            log_lines: Vec::new(),
            output_lines: Vec::new(),
            input: Input::default(),
            history: Vec::new(),
            history_idx: None,
            should_quit: false,
        }
    }
}

fn render(f: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::vertical([Constraint::Percentage(70), Constraint::Percentage(30)])
        .split(f.area());

    // --- Log pane (upper) ---
    let log_area = chunks[0];
    let inner_height = log_area.height.saturating_sub(2) as usize; // subtract borders
    let log_start = app.log_lines.len().saturating_sub(inner_height);
    let visible_logs: Vec<Line> = app.log_lines[log_start..]
        .iter()
        .map(|s| {
            // Color-code by log level prefix
            let color = if s.contains("[ERROR]") {
                Color::Red
            } else if s.contains("[WARN]") {
                Color::Yellow
            } else if s.contains("[INFO]") {
                Color::Green
            } else {
                Color::Gray
            };
            Line::from(Span::styled(s.as_str(), Style::default().fg(color)))
        })
        .collect();

    let log_widget = Paragraph::new(visible_logs)
        .block(Block::default().title(" Logs ").borders(Borders::ALL))
        .wrap(Wrap { trim: false });
    f.render_widget(log_widget, log_area);

    // --- REPL pane (lower) ---
    let repl_area = chunks[1];
    let inner_height = repl_area.height.saturating_sub(2) as usize; // subtract borders
    // Reserve 1 line for the input prompt
    let output_lines_to_show = inner_height.saturating_sub(1);
    let output_start = app.output_lines.len().saturating_sub(output_lines_to_show);
    let mut repl_lines: Vec<Line> = app.output_lines[output_start..]
        .iter()
        .map(|s| Line::from(s.as_str()))
        .collect();
    // Pad with empty lines so the prompt is always at the bottom of the pane
    while repl_lines.len() < output_lines_to_show {
        repl_lines.push(Line::from(""));
    }
    // Add prompt line
    repl_lines.push(Line::from(vec![
        Span::styled("lntest> ", Style::default().fg(Color::Cyan)),
        Span::raw(app.input.value()),
    ]));

    let repl_widget = Paragraph::new(repl_lines)
        .block(Block::default().title(" REPL ").borders(Borders::ALL));
    f.render_widget(repl_widget, repl_area);

    // Position the real terminal cursor inside the prompt line
    let prompt_len = "lntest> ".len() as u16;
    let cursor_x = repl_area.x + 1 + prompt_len + app.input.visual_cursor() as u16;
    let cursor_y = repl_area.y + repl_area.height - 2;
    f.set_cursor_position((cursor_x, cursor_y));
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let vs_sa: SocketAddr = args.vs_addr.parse().expect("failed to parse vs-addr");
    let node_zpr_addr: IpAddr = args.self_addr.parse().expect("failed to parse self_addr");
    let node_aaa_prefix: IpNet = args.aaa_prefix.parse().expect("failed to parse aaa_prefix");

    let cfg = Config { node_zpr_addr };

    // Set up logging to our TUI buffer instead of stdout
    let log_buf = LogBuffer::default();
    enable_logging(log_buf.clone());

    let mut vsc = VSConn::new(
        8,
        vs_sa,
        args.node_cn,
        load_private_key(&args.private_key).expect("failed to load private key"),
    );
    let mut life_rx = vsc.subscribe_lifecycle_events();
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
    let (output_tx, mut output_rx) = mpsc::unbounded_channel::<String>();

    // Command handler task
    let cmd_output_tx = output_tx.clone();
    js.spawn(async move {
        info!("allowing VSConn to start up...");
        tokio::time::sleep(Duration::from_secs(1)).await;

        let request = VSConnectRequest {
            zpr_addr: node_zpr_addr,
            aaa_prefix: node_aaa_prefix,
        };

        info!("requesting a connect");
        let mut connected = false;
        match handle.connect(request).await {
            Ok(resp) => {
                info!("Connection response: {:?}", resp);
                let _ = cmd_output_tx.send("connected".to_string());
                connected = true;
            }
            Err(e) => {
                error!("connection failed: {:?}", e);
                let _ = cmd_output_tx.send(format!("connection failed: {:?}", e));
            }
        }

        if connected {
            loop {
                tokio::select! {
                    event_res = life_rx.recv() => {
                        match event_res {
                            Ok(event) => {
                                match event {
                                    VSConnLifecycleEvent::RunLoopStarts =>
                                        info!("lifecycle event: VSConn run loop starts"),
                                    VSConnLifecycleEvent::ConnectedToVsApi =>
                                        info!("lifecycle event: connected to VS API"),
                                    VSConnLifecycleEvent::RunLoopExits =>
                                        info!("lifecycle event: VSConn run loop exits"),
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(skipped)) => {
                                warn!("lifecycle event receiver lagged, skipped {} messages", skipped);
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                warn!("lifecycle event sender closed");
                            }
                        }
                    }

                    Some(cmd) = cmd_rx.recv() => {
                        match cmd {
                            Cmd::Nop => {}
                            Cmd::Disconnect => break,
                            Cmd::VisaRequest(five_tuple) => {
                                let pdesc = PacketDesc {
                                    five_tuple,
                                    comm_flags: CommFlag::BiDirectional,
                                };
                                let req = VSVisaRequest {
                                    pdesc,
                                    previous_id: None,
                                };
                                match handle.visa_request(req).await {
                                    Ok(decision) => {
                                        let _ = cmd_output_tx.send(format!("visa_request decision: {:?}", decision));
                                    }
                                    Err(e) => {
                                        let _ = cmd_output_tx.send(format!("visa_request failed: {:?}", e));
                                    }
                                }
                            }
                            Cmd::RegisterVss(saddr) => {
                                match handle.register_vss(saddr).await {
                                    Ok(ops) => {
                                        let _ = cmd_output_tx.send(format!(
                                            "register_vss succeeded: got {} VisaOps", ops.len()
                                        ));
                                        for vo in &ops {
                                            match vo {
                                                VisaOp::Grant(v) => {
                                                    let _ = cmd_output_tx.send(format!("  visa id: {}", v.issuer_id));
                                                }
                                                VisaOp::RevokeVisaId(vid) => {
                                                    let _ = cmd_output_tx.send(format!("  revoke visa id: {}", vid));
                                                }
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        let _ = cmd_output_tx.send(format!("register_vss failed: {:?}", e));
                                    }
                                }
                            }
                            Cmd::NotifyDisconnect(zpr_addr) => {
                                let notice = VSDisconnectNotice {
                                    zpr_addr: Some(zpr_addr),
                                    reason: DisconnectReason::Admin,
                                };
                                match handle.notify_disconnect(notice).await {
                                    Ok(()) => {
                                        let _ = cmd_output_tx.send("notify_disconnect succeeded".to_string());
                                    }
                                    Err(e) => {
                                        let _ = cmd_output_tx.send(format!("notify_disconnect failed: {:?}", e));
                                    }
                                }
                            }
                            Cmd::AuthorizeConnect(key_path, claims) => {
                                let adapter_key = match load_private_key(&key_path) {
                                    Ok(k) => k,
                                    Err(e) => {
                                        let _ = cmd_output_tx.send(format!("failed to load adapter key: {}", e));
                                        continue;
                                    }
                                };

                                let cn = match claims.iter().find(|c| c.key == "endpoint.zpr.adapter.cn") {
                                    Some(c) => c.value.clone(),
                                    None => {
                                        let _ = cmd_output_tx.send("error: endpoint.zpr.adapter.cn claim is required".to_string());
                                        continue;
                                    }
                                };

                                let blob = match build_self_signed_blob(&cn, &adapter_key) {
                                    Ok(b) => b,
                                    Err(e) => {
                                        let _ = cmd_output_tx.send(format!("failed to build self-signed blob: {}", e));
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
                                        let _ = cmd_output_tx.send(format!(
                                            "authorize_connect succeeded: zpr_addr={}, auth_expires={}",
                                            conn.zpr_addr, conn.auth_expires
                                        ));
                                    }
                                    Err(e) => {
                                        let _ = cmd_output_tx.send(format!("authorize_connect failed: {:?}", e));
                                    }
                                }
                            }
                        }
                    }

                    Some(vss_msg) = vss_rx.recv() => {
                        match vss_msg {
                            VSSMessage::PushVisaOp(visa_ops, resp_tx) => {
                                let _ = cmd_output_tx.send(format!(
                                    "[VSS incoming] PushVisaOp with {} ops", visa_ops.len()
                                ));
                                let _ = resp_tx.send(ListProcessingResponse::Ack { processed: visa_ops.len() as u32 });
                            }
                            VSSMessage::RevokeAuth(ip_addrs, resp_tx) => {
                                let _ = cmd_output_tx.send(format!(
                                    "[VSS incoming] RevokeAuth for {} addresses", ip_addrs.len()
                                ));
                                let _ = resp_tx.send(ListProcessingResponse::Ack { processed: ip_addrs.len() as u32 });
                            }
                            VSSMessage::SetServices(version, services, resp_tx) => {
                                let _ = cmd_output_tx.send(format!(
                                    "[VSS incoming] SetServices v{} with {} services", version, services.len()
                                ));
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
                let _ = cmd_output_tx.send("stopped vsconn".to_string());
            }
            Err(e) => {
                error!("failed to stop VSConn: {:?}", e);
                let _ = cmd_output_tx.send(format!("failed to stop VSConn: {:?}", e));
            }
        }
        vss_aborter.abort();

        Ok(())
    });

    // TUI event loop — runs as a blocking task alongside the async tasks
    js.spawn_blocking(move || {
        let result = (|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            crossterm::terminal::enable_raw_mode()?;
            let mut stdout = stdout();
            execute!(stdout, EnterAlternateScreen)?;
            let backend = CrosstermBackend::new(stdout);
            let mut terminal = Terminal::new(backend)?;

            let mut app = App::new();

            let r = run_tui(&mut terminal, &mut app, &log_buf, &mut output_rx, &cmd_tx, &output_tx, &cfg);

            // Restore terminal regardless of result
            crossterm::terminal::disable_raw_mode()?;
            execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

            r
        })();
        if let Err(e) = result {
            eprintln!("TUI error: {:?}", e);
        }
        Ok(())
    });

    local_set
        .run_until(async move {
            while let Some(res) = js.join_next().await {
                match res {
                    Ok(_) => (),
                    Err(e) => {
                        eprintln!("task failed: {:?}", e);
                    }
                }
            }
        })
        .await;
}

fn run_tui(
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    app: &mut App,
    log_buf: &LogBuffer,
    output_rx: &mut mpsc::UnboundedReceiver<String>,
    cmd_tx: &mpsc::UnboundedSender<Cmd>,
    output_tx: &mpsc::UnboundedSender<String>,
    cfg: &Config,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    loop {
        // Drain log buffer
        log_buf.drain_into(&mut app.log_lines);

        // Drain output channel
        while let Ok(line) = output_rx.try_recv() {
            app.output_lines.push(line);
        }

        terminal.draw(|f| render(f, app))?;

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                // Ignore key release events (only act on press / repeat)
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                match key.code {
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.should_quit = true;
                    }
                    KeyCode::Char('d') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        app.should_quit = true;
                    }
                    KeyCode::Up => {
                        if !app.history.is_empty() {
                            let new_idx = match app.history_idx {
                                None => app.history.len() - 1,
                                Some(i) => i.saturating_sub(1),
                            };
                            app.history_idx = Some(new_idx);
                            let mut inp: Input = app.history[new_idx].clone().into();
                            inp.handle(InputRequest::GoToEnd);
                            app.input = inp;
                        }
                    }
                    KeyCode::Down => match app.history_idx {
                        None => {}
                        Some(i) if i + 1 < app.history.len() => {
                            let new_idx = i + 1;
                            app.history_idx = Some(new_idx);
                            let mut inp: Input = app.history[new_idx].clone().into();
                            inp.handle(InputRequest::GoToEnd);
                            app.input = inp;
                        }
                        Some(_) => {
                            app.history_idx = None;
                            app.input = Input::default();
                        }
                    },
                    KeyCode::Enter => {
                        let input = app.input.value().trim().to_string();
                        app.input = Input::default();
                        app.history_idx = None;
                        if input.is_empty() {
                            continue;
                        }
                        // Append to history (skip exact duplicates at the end)
                        if app.history.last().map(|s| s.as_str()) != Some(input.as_str()) {
                            app.history.push(input.clone());
                        }
                        // Echo the command in the REPL pane
                        app.output_lines.push(format!("lntest> {}", input));

                        match parse_command(cfg, &input, output_tx) {
                            Ok(Cmd::Disconnect) => {
                                app.should_quit = true;
                            }
                            Ok(cmd) => {
                                if let Err(e) = cmd_tx.send(cmd) {
                                    app.output_lines.push(format!("failed to send command: {:?}", e));
                                    app.should_quit = true;
                                }
                            }
                            Err(e) => {
                                app.output_lines.push(e);
                            }
                        }
                    }
                    _ => {
                        // Forward everything else to tui-input for line editing:
                        // ← → Home End Ctrl+A/E Ctrl+W Ctrl+K Alt+← Alt+→ etc.
                        app.input.handle_event(&Event::Key(key));
                    }
                }
            }
        }

        if app.should_quit {
            let _ = cmd_tx.send(Cmd::Disconnect);
            break;
        }
    }
    Ok(())
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

    let mut data = Vec::new();
    data.extend_from_slice(&timestamp.to_be_bytes());
    data.extend_from_slice(cn.as_bytes());
    data.extend_from_slice(&challenge);

    let mut signer = Signer::new(MessageDigest::sha256(), private_key)?;
    signer.update(&data)?;
    let raw_signature = signer.sign_to_vec()?;

    Ok(SelfSignedBlob {
        alg: ChallengeAlg::RsaSha256Pkcs1v15,
        challenge,
        cn: cn.to_string(),
        timestamp,
        signature: raw_signature,
    })
}

fn load_private_key(keyfile: &Path) -> Result<PKey<Private>, Box<dyn std::error::Error>> {
    let key_data = fs::read(keyfile)?;
    let rsa = Rsa::private_key_from_pem(&key_data)?;
    let pkey = PKey::from_rsa(rsa)?;
    Ok(pkey)
}

fn enable_logging(buf: LogBuffer) {
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(TuiLogLayer { buf })
            .with(LevelFilter::from_level(Level::DEBUG)),
    )
    .expect("setting default subscriber failed");
}
