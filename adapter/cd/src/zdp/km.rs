// km.rs - Key Management for ZDP
// TODO: Probably need this in node too.

use tokio::sync::mpsc;
use std::sync::RwLock;
use bytes::BytesMut;

use ph-test::packet::Packet;


/*
        According to 6.2.8 the key management packets can run in native mode
        when running over a an IP substrate.


         non per-flow management packet

         0    1    ZPI   (for KM this is always set 0)
         1    1    TYPE  (KM = 0x81)    sec. 6.2.8
         2    1    excess len (0)
         3    2    seqnum
         5    x    MANAGEMENT_DATA (km packet)
         x    x    PADDING
         x    x    MAC    (w/ ZPI=0 this is just internet checksum)


         The managemnt data looks like:

         0    2    TYPE       0=none, 1=ikeV2, 2=noise
         2    2    LENGTH     includes type and length
         4    x    KM_PACKET


*/


pub struct KeyManager {
    state: RwLock<KMState>,
    mgmt_tx: Option<mpsc::Sender<Bytes>>, // Internal queue for key management messages to be processed.
    km_buffers_out: mpsc::Sender<Bytes>,  // Key Management Payloads for the wire are placed here.
}


struct KMState {
    statemachine: Box<dyn KeyManagerStateMachine>,
    sa_id: u8, // current SA identifier
}


// KeyManager maintains an SA with its peer.
impl KeyManager {
    /// `statemachine` is the key management algorithm.
    /// `km_buffers_out` is the output channel for key management packets.  These are the payloads only (no ZDP header).
    pub fn new(statemachine: Box<dyn KeyManagerStateMachine>, km_buffers_out: mpsc::Sender<Bytes>) -> KeyManager {
        KeyManager {
            state: RwLock::new(KMState {
                statemachine,
                sa_id: 0,
            }),
            mgmt_tx: None,
        }
    }

    pub fn get_sa_id(&self) -> u8 {
        self.state.read().unwrap().sa_id
    }


    // Encrypt a ZDP message for transport.  Key Management messages should not be sent here.
    // This overwrites the plaintext ZDP header.
    // For ZDP management messages, also overwrites the payload.
    //
    // For transit packets, there must be enough padding between the header and
    // the agent-data to hold the output ciphertext.
    //
    // `message` is expected to be a ZDP message wihout a ZPI value.  We add a ZPI
    // value to the front of the message -- note that the value we add is just the
    // SA_ID.  It's up to caller to mix in the configuration ID value.
    pub fn encrypt_transport(&self, message: &mut Packet) -> io::Result<()> {
        // if this is transit packet
        //   encrypt just the ZDP header.
        // else
        //   encrypt the entire message.
        //
        // push a ZPI onto the front.
        // ...

        let state = self.state.read().unwrap();
        if state.statemachine.get_state() != KMSMState::Transport {
            return Err(io::Error::new(io::ErrorKind::Other, "SA not in transport state"));
        }
        if state.sa_id == 0 {
            // programming error
            panic!("SA_ID is zero");
        }

        Ok(())
    }


    // We assume that packet ZPI value has been clensed of the config ID and is only the SA_ID.
    // Key Management packets should not be sent here.
    pub fn decrypt_transport(&self, message: &mut Packet) -> io::Result<()> {
        // check ZPI...
        // if this is a transit packet
        //   decrypt just the ZDP header, zero out padding.
        // else
        //   decrypt the entire message.
        //
        let state = self.state.read().unwrap();

        if message.body()[0]  == 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "ZPI value is 0"));
        }
        if state.sa != message.body()[0] {
            return Err(io::Error::new(io::ErrorKind::Other, format!("SA_ID mismatch: expect {}, found {}", state.sa, message.body()[0])));
        }
        if state.statemachine.get_state() != KMSMState::Transport {
            return Err(io::Error::new(io::ErrorKind::Other, "SA not in transport state"));
        }

        Ok(())
    }


    // Pass in a full Key Management payload here.
    //
    // We copy the payload into our own buffer for processing. Caller should free buffer.
    pub async fn handle_km_message(&self, message: &Packet) -> io::Result<()> {
        match self.mgmt_tx {
            Some(ref tx) => {
                let km_buf = Bytes::from(message.body());
                tx.send(km_buf).await?;
            }
            None => {
                return Err(io::Error::new(io::ErrorKind::Other, "KeyManager not running"));
            }
        }
    }


    // Blocking run loop for the key manager.
    pub async fn start(&mut self, ctok: CancellationToken) -> io::Result<()> {


        let km_buffers_out: Sender<Bytes>;  // Key Management Payloads

        let (km_tx, mut km_rx) = mpsc::channel(16);
        self.mgmt_tx = Some(km_tx);

        let mut interval = time::interval(Duration::from_millis(500));


        let handshake = self.state.write().unwrap().statemachine.reset(true);
        if let Some(handshake) = handshake {
            km_buffers_out.send(handshake).await?;
        }

        let mut prev_state: KMSMState;
        let mut next_state: KMSMState;

        loop {
            {
                let state = self.state.read().unwrap();
                prev_state = state.statemachine.get_state();
            }

            match prev_state {
                KMSMState::Error =>  { // If error, send reset and loop again
                    let resp: Option<Bytes>;
                    {
                        let state = self.state.write().unwrap();
                        resp = state.statemachine.reset(true);
                    }
                    if let Some(resp) = resp {
                        km_buffers_out.send(resp).await?
                    }
                }

                _ => tokio::select! {
                    Some(inmsg) = km_rx.recv() => {
                        let resp: Option<Bytes>;
                        {
                            let state = self.state.write().unwrap();
                            resp = state.statemachine.handle_message(inmsg);
                        }
                        if let Some(resp) = resp {
                            km_buffers_out.send(resp).await?
                        }
                    }
                    _ = interval.tick() => {
                        let resp: Option<Bytes>;
                        {
                            let state = self.state.write().unwrap();
                            resp = state.statemachine.tick();
                        }
                        if let Some(resp) => resp {
                            km_buffers_out.send(resp).await?
                        }
                    }
                    _ = ctok.cancelled() => {
                        break;
                    }
                }
            }

            {
                let state = self.state.read().unwrap();
                next_state = state.statemachine.get_state();
            }

            if next_state != prev_state {
                // state transition
                info!("KM state transition {} -> {}", prev_state, next_state);

                if next_state == KMSMState::Transport {
                    let state = self.state.read().unwrap();
                    state.sa_id += 1;
                    if state.sa_id == 0 {
                        state.sa_id = 1;
                    }
                    info!("KM: New SA_ID: {}", state.sa_id);
                }
            } else if next_state == KMSMState::Error {
                error!("KM: stuck in error state");
                return Err(io::Error::new(io::ErrorKind::Other, "Key Manager in error state"));
                // TODO: Maybe use a timer and keep trying to reset?
            }
        }

        Ok(())
    }
}



// State transitions:
//
//      *
//      ↓
// Configuring -> Transport
//      ↓ ↑          ↓
//     Error <-------+
//
// Not accounting for "rekeying" -- for now assuming that can happen
// internally and machine can just stay in transport state.
#[derive(Debug, Clone)]
enum KMSMState {
    Configuring,
    Transport,
    Error,
}


pub trait KeyManagerStateMachine {

    // State can only change through handle_message, tick, or reset.
    fn get_state() -> KMSMState;

    // Reset state machine and optionally initiate a new handshake.
    // Must clear error state.
    fn reset(initiate: bool) -> Option<Bytes>;

    // process an inbound KM message.
    // may produce an output message.
    // may transition internal state.
    fn handle_message(message: &[u8]) -> Option<Bytes>;

    // Optional outbound KM message
    // May transition internal state
    fn tick() -> Option<Bytes>;

    /// Encrypt message from `payload`, write encrypted message to `message`.
    /// Must be in transport state.
    fn encrypt_transport(payload: &[u8], message: &mut [u8]) -> Result<usize, Error>;

    /// Read encrypted message from `payload`, write plaintext to `message`.
    /// Must be in transport state.
    fn decrypt_transport(&self, payload: &[u8], message: &mut [u8]) -> Result<usize, Error>;

}
