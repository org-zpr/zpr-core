use clap::Parser;
use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen},
};
use ipnet::IpNet;
use std::io::stdout;
use std::net::{IpAddr, SocketAddr};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, info};

use libnode2::cli::{App, Args, Cmd, Config, LogBuffer, enable_logging, run_handler, run_tui};
use libnode2::vsconn::VSConn;
use libnode2::vss::launch_vss;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let vs_sa: SocketAddr = args.vs_addr.parse().expect("failed to parse vs-addr");
    let node_zpr_addr: IpAddr = args.self_addr.parse().expect("failed to parse self_addr");
    let node_aaa_prefix: IpNet = args.aaa_prefix.parse().expect("failed to parse aaa_prefix");

    let cfg = Config { node_zpr_addr };

    let log_buf = LogBuffer::default();
    enable_logging(log_buf.clone());

    let private_key = libnode2::cli::crypto::load_private_key(&args.private_key)
        .expect("failed to load private key");

    let mut vsc = VSConn::new(8, vs_sa, args.node_cn, private_key);
    let life_rx = vsc.subscribe_lifecycle_events();
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

    let (vss_tx, vss_rx) = mpsc::channel(32);
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

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<Cmd>();
    let (output_tx, mut output_rx) = mpsc::unbounded_channel::<String>();

    js.spawn(run_handler(
        handle,
        node_zpr_addr,
        node_aaa_prefix,
        life_rx,
        cmd_rx,
        vss_rx,
        output_tx.clone(),
        vss_aborter,
    ));

    js.spawn_blocking(move || {
        let result = (|| -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            crossterm::terminal::enable_raw_mode()?;
            let mut stdout = stdout();
            execute!(stdout, EnterAlternateScreen)?;
            let backend = ratatui::backend::CrosstermBackend::new(stdout);
            let mut terminal = ratatui::Terminal::new(backend)?;

            let mut app = App::new();

            let r = run_tui(
                &mut terminal,
                &mut app,
                &log_buf,
                &mut output_rx,
                &cmd_tx,
                &output_tx,
                &cfg,
            );

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
