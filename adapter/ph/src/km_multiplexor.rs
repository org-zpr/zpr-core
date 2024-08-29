use crate::assembly::Assembly;
use crate::km::*;
use crate::km_noise::KMNoise;
use crate::zpr;

use bytes::Bytes;
use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// Global state for the KM system.
/// TODO: Move to assembly?
pub struct KmState<'pktbuf> {
    // This token is used to create cancellation tokens for all the link KeyManager state machines.
    // So cancellign this will shutdown them all.
    ctok: CancellationToken,
    km_tx: mpsc::Sender<KMLinkMsg<Bytes>>,
    km_sig_tx: mpsc::Sender<KMLinkMsg<KMSignal>>,
    inner: Mutex<KmStateInner<'pktbuf>>,
}
pub struct KmStateInner<'pktbuf> {
    km_table: HashMap<zpr::LinkId, KMHandle<'pktbuf>>, // Not sure how to set the lifetime variable here.
}

impl<'pktbuf> KmState<'pktbuf> {
    pub fn new(
        km_buffers_out: mpsc::Sender<KMLinkMsg<Bytes>>,
        km_sig_tx: mpsc::Sender<KMLinkMsg<KMSignal>>,
        ctok: CancellationToken,
    ) -> Self {
        Self {
            ctok,
            km_tx: km_buffers_out,
            km_sig_tx,
            inner: Mutex::new(KmStateInner {
                km_table: HashMap::new(),
            }),
        }
    }

    fn add_link_handle(&self, link_id: zpr::LinkId, handle: KMHandle<'pktbuf>) {
        let mut inner = self.inner.lock().unwrap();
        inner.km_table.insert(link_id, handle);
    }
}

// I'd like the KeyManager to live as long as the hashmap that holds the handle.
// Which for us is forever -- since map should be created on KmState and stored
// forever in the Assembly.
//
// TODO: move to assembly?
pub struct KMHandle<'pktbuf> {
    ctok: CancellationToken,
    mgr: KeyManager<'pktbuf>, // The manager must remnain valid for lifetime of the link
}

/// SAState is placed in the assembly so that other parts of the code can check
/// to see if an SA is established, and if so get all the details.
///
/// Do not use any values in here until `sa_established` is true.
///
/// - TODO: Replace this lame synchronization method with RCU ??
/// - TODO: This could be more tightly integrated into the assembly.
pub struct SAState {
    pub sa_established: AtomicBool,
    pub transport_sa: KMTransportSA,
}

impl SAState {
    /// Create a new, empty SAState.
    pub fn new() -> Self {
        Self {
            sa_established: AtomicBool::new(false),
            transport_sa: KMTransportSA {
                sa_id: 0,
                recv_zpis: ZPIPair::new_zero(),
                send_zpis: ZPIPair::new_zero(),
                send_hmac_key: [0; 32],
                recv_hmac_key: [0; 32],
                codec: Arc::new(UnimplCodec::new()),
            },
        }
    }
}

/// This is one of the multiplexor related workers, the other one is in main.rs.
/// This watches for signals from the running KeyManagers and updates the SAState
/// when SA's are established.
///
/// TODO: Handle case when SAs are torn down.
async fn worker<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    sig_queue: &mut mpsc::Receiver<KMLinkMsg<KMSignal>>,
) {
    let sp_ctok = asm.km_state.ctok.clone();
    let state_table_p = asm.sa_states.clone();

    loop {
        tokio::select! {
            _ = sp_ctok.cancelled() => {
                info!("KM Multiplexor shutting down");
                break;
            }

            Some(linkmsg) = sig_queue.recv() => {
                info!("km_multiplexor: signal {:?} on link {}", linkmsg.msg, linkmsg.link_id);
                match linkmsg.msg {
                    KMSignal::SaIdChange { old, new } => {
                        info!("km_multiplexor: SA ID change on link {}: {} -> {}", linkmsg.link_id, old, new);
                    }
                    KMSignal::SaEstablished(sa) => {
                            let mut state_db = state_table_p.lock().unwrap();
                            if let Some(sa_state) = state_db.get_mut(&linkmsg.link_id) {
                                sa_state.transport_sa = sa;
                                sa_state.sa_established.store(true, Ordering::Relaxed);
                            } else {
                                error!("km_multiplexor: no SA state for link {}", linkmsg.link_id);
                            }
                    }
                    _ => {} // TODO: Handle other signals.
                }
            }
        }
    }
}

/// Start the signal watcher worker.
///
/// (I've totally copied the pattern that Chris used for other workers but don't really understand it. --mk)
pub fn launch<'pktbuf, AsmRef: 'pktbuf>(
    asm: AsmRef,
    mut sig_queue: mpsc::Receiver<KMLinkMsg<KMSignal>>,
) -> impl Future<Output = ()> + Send + 'pktbuf
where
    AsmRef: std::ops::Deref<Target = Assembly<'pktbuf>> + Send + Sync,
{
    async move { worker(&*asm, &mut sig_queue).await }
}

/// Creates a new KeyManager for the link and starts its state machine.  An adapter link will
/// initiate the KM exchange with its peer.
///
/// - `peer_noise_key` is the public noise key for the node/dock.
pub fn add_adapter_link(
    asm: &'static Assembly,
    link_id: zpr::LinkId,
    recv_zpis: ZPIPair,
    peer_noise_key: [u8; 32],
) -> Result<(), String> {
    let noise = match KMNoise::new(
        true,
        Some(peer_noise_key.into()),
        None,
        recv_zpis.encr,
        recv_zpis.hmac,
    ) {
        Ok(n) => n,
        Err(e) => {
            return Err(format!("Failed to create Noise protocol: {:?}", e));
        }
    };
    add_noise_link(asm, link_id, noise)
}

/// Creates a new KeyManager for the link and starts its state machine.  A node link waits for a
/// KM initiator.
///
/// - `local_noise_key` is the local noise key for the dock (public key is shared out of band with adapters).
pub fn add_node_link(
    asm: &'static Assembly,
    link_id: zpr::LinkId,
    recv_zpis: ZPIPair,
    local_noise_key: snow::Keypair,
) -> Result<(), String> {
    let noise = match KMNoise::new(
        false,
        None,
        Some(local_noise_key),
        recv_zpis.encr,
        recv_zpis.hmac,
    ) {
        Ok(n) => n,
        Err(e) => {
            return Err(format!("Failed to create Noise protocol: {:?}", e));
        }
    };
    add_noise_link(asm, link_id, noise)
}

// Completes the add_*_link functions above.
fn add_noise_link(
    asm: &'static Assembly,
    link_id: zpr::LinkId,
    noise: KMNoise,
) -> Result<(), String> {
    let mgr = KeyManager::new(link_id, Box::new(noise));

    asm.sa_states
        .lock()
        .unwrap()
        .insert(link_id, SAState::new());

    let mut spawn_mgr = mgr.clone();
    let child_ctok = asm.km_state.ctok.child_token();
    let spawn_ctok = child_ctok.clone();
    let spawn_km_tx = asm.km_state.km_tx.clone();
    let spawn_sig_tx = asm.km_state.km_sig_tx.clone();
    tokio::spawn(async move {
        match spawn_mgr.start(spawn_ctok, spawn_km_tx, spawn_sig_tx).await {
            Ok(_) => (),
            Err(e) => {
                error!("KeyManager failed on link {}: {:?}", link_id, e);
            }
        }
    });

    let handle = KMHandle {
        ctok: child_ctok,
        mgr,
    };

    asm.km_state.add_link_handle(link_id, handle);

    Ok(())
}

/// When an inbound key management ZDP message arrives on a link, send it here after parsing.
///
/// The km_payload should be the km-payload part of the ZDP KM message.  We copy the payload before
/// returning.
pub async fn handle_inbound_km_msg<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    from_link: zpr::LinkId,
    km_payload: &[u8],
) -> Result<(), String> {
    let manager: Option<KeyManager>;

    {
        match asm.km_state.inner.lock().unwrap().km_table.get(&from_link) {
            None => {
                return Err(format!("no KM found for link {}", from_link));
            }
            Some(h) => {
                manager = Some(h.mgr.clone());
            }
        };
    }

    match manager.unwrap().handle_km_message(km_payload).await {
        Ok(_) => Ok(()),
        Err(e) => Err(format!(
            "Failed to handle KM message on link{}: {:?}",
            from_link, e
        )),
    }
}
