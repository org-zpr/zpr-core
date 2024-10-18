use libnode::vss;
use std::net::SocketAddr;
use tokio::signal;
use tokio::sync::mpsc;
use tracing::info;

#[derive(Debug)]
#[allow(dead_code)]
pub enum VssError {
    Error,
}

pub fn run_vss(listen_sock: SocketAddr) -> Result<(), VssError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(_run_vss(listen_sock))
}

async fn _run_vss(listen_sock: SocketAddr) -> Result<(), VssError> {
    let (vss_tx, mut vss_rx) = mpsc::channel(32);
    /*
    tokio::spawn(async move {
        vss::start_vss_server(vss_tx, &listen_sock.to_string());
    });
    */
    let _handle = std::thread::spawn(move || {
        vss::start_vss_server(vss_tx, &listen_sock.to_string());
    });

    info!("VSS server started on {}", listen_sock);

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                break;
            }
            Some(vss_msg) = vss_rx.recv() => {
                match vss_msg {
                    vss::VSSMsg::PolicyInstall(pi) => {
                        info!("VSS policy install: {:?}", pi);
                    }
                    vss::VSSMsg::PushedVisa(v) => {
                        info!("VSS pushed visa: issuer_id={:?}", v.issuer_id);
                    }
                    _ => {
                        info!("VSConn::run received VSS message: {:?}", vss_msg);
                    }
                }
            }
        }
    }

    Ok(())
}
