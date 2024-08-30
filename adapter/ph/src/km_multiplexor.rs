use crate::assembly::Assembly;
use crate::km::*;
use crate::km_noise::KMNoise;
use crate::zpr;

use bytes::Bytes;
use dashmap::DashMap;
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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
    table: DashMap<zpr::LinkId, KMHandle<'pktbuf>>, // Not sure how to set the lifetime variable here.
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
            table: DashMap::new(),
        }
    }

    fn add_link_handle(&self, link_id: zpr::LinkId, handle: KMHandle<'pktbuf>) {
        self.table.insert(link_id, handle);
    }
}

// I'd like the KeyManager to live as long as the hashmap that holds the handle.
// Which for us is forever -- since map should be created on KmState and stored
// forever in the Assembly.
//
// TODO: move to assembly?

#[allow(dead_code)]
pub struct KMHandle<'pktbuf> {
    ctok: CancellationToken,  // for this KeyManager
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
                            if let Some(mut sa_state) = state_table_p.get_mut(&linkmsg.link_id) {
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
///
/// - `link_id` is the link to the peer, in this case better be a link to a node.
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
/// - `link_id` is the link to the peer, in this case better be a link to an adapter.
/// - `local_noise_key` is the local noise key for the dock (public part of this key must be shared out of band with adapters).
#[allow(dead_code)]
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

/// Remove all state for this link, invalidating the SA and stopping the Key Manager.
#[allow(dead_code)]
pub fn drop_link(asm: &'static Assembly, link_id: zpr::LinkId) -> Result<(), String> {
    // If present in sa_state, turn off the SA.
    if let Some(sa_state) = asm.sa_states.get_mut(&link_id) {
        sa_state.sa_established.store(false, Ordering::Relaxed);
    }

    // remove handle from our km state, if found
    let handle = asm.km_state.table.remove(&link_id);

    // Stop the KM
    if handle.is_some() {
        handle.unwrap().1.ctok.cancel(); // stop the KM
    }

    // Remove from SA
    match asm.sa_states.remove(&link_id) {
        None => {}
        Some(_) => (),
    }
    Ok(())
}

// Completes the add_*_link functions above.
fn add_noise_link(
    asm: &'static Assembly,
    link_id: zpr::LinkId,
    noise: KMNoise,
) -> Result<(), String> {
    let mgr = KeyManager::new(link_id, Box::new(noise));

    asm.sa_states.insert(link_id, SAState::new());

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
///
/// TODO: Note this will block if the KeyManager queue is full.  Should this instead be using
///       the non-blocking call?
pub async fn handle_inbound_km_msg<'pktbuf>(
    asm: &Assembly<'pktbuf>,
    from_link: zpr::LinkId,
    km_payload: &[u8],
) -> Result<(), String> {
    let manager: Option<KeyManager>;

    {
        match asm.km_state.table.get(&from_link) {
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

#[cfg(test)]
mod test {
    use super::*;

    use crate::assembly::test::{create_assembly, TestAssemblyBuilder};
    use crate::buffer_stack::BufferStack;
    use crate::config;
    use crate::km::KMLinkMsg;
    use crate::km_noise;
    use base64::prelude::*;
    use std::time::Duration;
    use tokio::task::yield_now;
    use tokio::time::timeout;

    #[tokio::test]
    async fn test_km_multiplexor_updates_assembly_state() {
        let nk_private_b64 = "AB2eP6zV7ve0A4eQgNVNXlAM2q0rYerCPXFMl+/ntUw=";
        let nk_private: [u8; 32] = match BASE64_STANDARD.decode(nk_private_b64) {
            Ok(d) => d.try_into().unwrap(),
            Err(e) => {
                panic!("error decoding base64: {:?}", e);
            }
        };
        let nk_public = km_noise::derive_public_key(&nk_private);
        let node_kp = snow::Keypair {
            private: nk_private.into(),
            public: nk_public.into(),
        };

        let (km_sig_tx, km_sig_rx) = mpsc::channel(4);
        let (km_tx, mut km_rx) = mpsc::channel(4);
        let km_mpx_ctok = CancellationToken::new();
        let km_state = KmState::new(km_tx, km_sig_tx, km_mpx_ctok.clone());

        let buf_storage = vec![[0u8; config::PACKET_BUFFER_SIZE]; 8];
        let buffer_stack = BufferStack::new(buf_storage.leak::<'static>());

        let mut builder = TestAssemblyBuilder::new();
        builder.km_state = Some(km_state);
        builder.buffer_stack = Some(buffer_stack);

        let asm = Box::leak(Box::new(create_assembly(builder)));

        // add a fake adapter.
        let adapter_link_id = 27;

        // Adding a link starts a KM
        add_adapter_link(asm, adapter_link_id, ZPIPair::new(1, 2), nk_public).unwrap();

        yield_now().await;

        // Start our multiplexor worker
        tokio::spawn(launch(&*asm, km_sig_rx));
        yield_now().await;

        // An adapter should send a KM message over link 1.
        let handshake_req: Bytes;
        match timeout(Duration::from_secs(2), km_rx.recv()).await {
            Ok(resp) => match resp {
                Some(KMLinkMsg { link_id, msg }) => {
                    assert_eq!(link_id, adapter_link_id);
                    assert_eq!(msg.len(), 130); // should be a KM payload
                    handshake_req = msg;
                }
                None => panic!("Expected KMLinkMessage message"),
            },
            Err(_) => panic!("Timed out waiting for KM message"),
        }

        // Check that initially, our state is not established.
        {
            let sa_state = asm.sa_states.get(&adapter_link_id).unwrap();
            assert!(sa_state.sa_established.load(Ordering::Relaxed) == false);
        }

        // Pretend to be a node and send back a valid reply.
        let mut responder = KMNoise::new(false, None, Some(node_kp), 3, 4).unwrap();
        match responder.reset() {
            Ok(Some(_m)) => panic!("unexpected message from responder.reset!"),
            Ok(None) => {} // good
            Err(e) => {
                panic!("error resetting responder: {:?}", e);
            }
        };

        // Since we have a "raw" responder, we can just pass the payload (no ZDP headers have been added).
        let handshake_reply = match responder.handle_message(&handshake_req) {
            Ok(Some(m)) => m,
            Ok(None) => {
                panic!("expected handshake-1 message, got nothing!");
            }
            Err(e) => {
                panic!("responder handle_message failed on handshake-req: {:?}", e);
            }
        };

        // Now send the reply back into our link.
        handle_inbound_km_msg(asm, adapter_link_id, &handshake_reply)
            .await
            .unwrap();

        yield_now().await;

        // The KM on the link will process the message and transition to established-state.
        // It will send two signals - SaIdChange followed by SaEstablished.  Both signals
        // are picked up by our multiplexor worker.  The second one triggers a state update.
        {
            let sa_state = asm.sa_states.get(&adapter_link_id).unwrap();
            assert!(sa_state.sa_established.load(Ordering::Relaxed));
        }

        match drop_link(asm, adapter_link_id) {
            Ok(_) => (),
            Err(e) => panic!("Failed to drop link: {:?}", e),
        }
    }
}
