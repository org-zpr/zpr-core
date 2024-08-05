// km.rs - Key Management for ZDP
// TODO: Probably need this in node too.

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tokio::time;
use std::time::Duration;

use std::sync::{Arc, Mutex};
use std::fmt;
use std::io;

use bytes::{BufMut, BytesMut, Bytes};

use tracing::{info, error};

use ph::packet::Packet;


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


#[derive(Debug, Clone)]
pub struct KeyManager<'mgr> {
    shared: Arc<KMShared<'mgr>>,
}

#[derive(Debug)]
pub struct KMShared<'mgr> {
    state: Mutex<KMState<'mgr>>,
}


struct KMState<'mgr> {
    // Warning - have no idea what I'm doing with lifetimes.
    // What I'm trying to assert here is that the impl of KeyManagerStateMachine must live as long as the KeyManager it is passed to.
    statemachine: Box<dyn KeyManagerStateMachine + 'mgr>,
    kmsettings: KMSettings,

    sa_id: u8, // current SA identifier

    mgmt_tx: Option<mpsc::Sender<Bytes>>, // Internal queue for key management messages to be processed.
}


impl fmt::Debug for KMState<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "KMState {{ sa_id: {} }}", self.sa_id)
    }
}


// KeyManager maintains an SA with its peer.
impl KeyManager<'_> {
    /// `statemachine` is the key management algorithm.
    pub fn new<'a>(statemachine: Box<dyn KeyManagerStateMachine>) -> KeyManager<'a> {

        let settings = statemachine.get_settings();

        KeyManager {
            shared: Arc::new(KMShared {
                state: Mutex::new(KMState {
                    statemachine,
                    kmsettings: settings,
                    sa_id: 0,
                    mgmt_tx: None,
                })
            })
        }
    }

    pub fn get_sa_id(&self) -> u8 {
        let state = self.shared.state.lock().unwrap();
        state.sa_id
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
        let encr: Box<dyn TransportEncr>;
        let sa_id: u8;
        let padlen: usize;
        let align: u8;
        {
            let state = self.shared.state.lock().unwrap();
            if state.statemachine.get_state() != KMSMState::Transport {
                return Err(io::Error::new(io::ErrorKind::Other, "SA not in transport state"));
            }
            if state.sa_id == 0 {
                // programming error
                panic!("SA_ID is zero");
            }
            sa_id = state.sa_id;
            encr = state.statemachine.get_transport_encryptor();
            padlen = state.kmsettings.padlen;
            align = state.kmsettings.alignment;
        }



        // if this is transit packet
        //   encrypt just the ZDP header.
        // else
        //   encrypt the entire message.
        //
        // push a ZPI onto the front.
        // ...

        if align > 0 {
            panic!("aligment not implemented") // TODO
        }

        // TODO: will I always need to crate a buffer here or can I write to input packet in place?
        let mut outbuf = vec![0_u8; 1 + message.body().len() + padlen];

        match encr.encrypt_transport(message.body(), &mut outbuf) {
            Ok(len) => {
                // TODO: Write ZPI + contents of outbuf into passed packet.
                // ...
            }
            Err(e) => {
                return Err(io::Error::new(io::ErrorKind::Other, format!("encrypt failed: {}", e)));
            }
        }
        Ok(())
    }


    // We assume that packet ZPI value has been clensed of the config ID and is only the SA_ID.
    // Key Management packets should not be sent here.
    pub fn decrypt_transport(&self, message: &mut Packet) -> io::Result<()> {
        let encr: Box<dyn TransportEncr>;
        {
            let state = self.shared.state.lock().unwrap();
            if message.body()[0]  == 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "ZPI value is 0"));
            }
            if state.sa_id != message.body()[0] {
                return Err(io::Error::new(io::ErrorKind::Other, format!("SA_ID mismatch: expect {}, found {}", state.sa_id, message.body()[0])));
            }
            if state.statemachine.get_state() != KMSMState::Transport {
                return Err(io::Error::new(io::ErrorKind::Other, "SA not in transport state"));
            }
            encr = state.statemachine.get_transport_encryptor();
        }

        // TODO...

        // check ZPI...
        // if this is a transit packet
        //   decrypt just the ZDP header, zero out padding.
        // else
        //   decrypt the entire message.
        //

        Ok(())
    }


    // Pass in a full Key Management payload here.
    //
    // We copy the payload into our own buffer for processing. Caller should free buffer.
    pub async fn handle_km_message(&self, message: &[u8]) -> io::Result<()> {
        let tx: mpsc::Sender<Bytes>;
        {
            let state = self.shared.state.lock().unwrap();
            match state.mgmt_tx {
                Some(ref t) => {
                    tx = t.clone();
                }
                None => {
                    return Err(io::Error::new(io::ErrorKind::Other, "KeyManager not running"));
                }
            }
        }
        let mut km_buf = BytesMut::with_capacity(message.len());
        km_buf.put(message);
        match tx.send(km_buf.into()).await {
            Ok(_) => Ok(()),
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "failed to enqueue inbound KM message")),
        }
    }


    // Blocking run loop for the key manager.  This runs the key management algorithm
    // state machine handing KM messages in and out.
    pub async fn start(&mut self, ctok: CancellationToken, km_buffers_out: mpsc::Sender<Bytes>) -> io::Result<()> {
        let (km_tx, mut km_rx) = mpsc::channel(16);
        let tick_interval: Duration;
        {
            let mut state = self.shared.state.lock().unwrap();
            state.mgmt_tx = Some(km_tx);
            tick_interval = state.kmsettings.tick_interval;
        }


        let mut interval = time::interval(tick_interval);

        let handshake: Option<Bytes>;
        {
            let mut state = self.shared.state.lock().unwrap();
            handshake = state.statemachine.reset(true);
        }
        if let Some(handshake) = handshake {
            match km_buffers_out.send(handshake).await {
                Ok(_) => {},
                Err(_) => {
                    return Err(io::Error::new(io::ErrorKind::Other, "failed to enqueue outbound KM message"))
                }
            }
        };

        let mut prev_state: KMSMState;
        let mut next_state: KMSMState;

        loop {
            {
                let state = self.shared.state.lock().unwrap();
                prev_state = state.statemachine.get_state();
            }

            match prev_state {
                KMSMState::Error =>  { // If error, send reset and loop again
                    let resp: Option<Bytes>;
                    {
                        let mut state = self.shared.state.lock().unwrap();
                        resp = state.statemachine.reset(true);
                    }
                    if let Some(resp) = resp {
                        match km_buffers_out.send(resp).await {
                            Ok(_) => {},
                            Err(_) => {
                                error!("failed to enqueue outbound KM message")
                            }
                        }
                    }
                }

                _ => {
                    tokio::select! {
                        _ = ctok.cancelled() => {
                            break;
                        }

                        Some(inmsg) = km_rx.recv() => {
                            let resp: Option<Bytes>;
                            {
                                let mut state = self.shared.state.lock().unwrap();
                                resp = state.statemachine.handle_message(&inmsg);
                            }
                            if let Some(resp) = resp {
                                match km_buffers_out.send(resp).await {
                                    Ok(_) => {},
                                    Err(_) => {
                                        error!("failed to enqueue outbound KM message")
                                    }
                                }
                            }
                        }

                        _ = interval.tick() => {
                            let resp: Option<Bytes>;
                            {
                                let mut state = self.shared.state.lock().unwrap();
                                resp = state.statemachine.tick();
                            }
                            if let Some(resp) = resp {
                                match km_buffers_out.send(resp).await {
                                    Ok(_) => {},
                                    Err(_) => {
                                        error!("failed to enqueue oubound KM message")
                                    }
                                }
                            }
                        }
                    }
                }
            };

            {
                let state = self.shared.state.lock().unwrap();
                next_state = state.statemachine.get_state();
            }

            if next_state != prev_state {
                // state transition
                info!("KM state transition {:?} -> {:?}", prev_state, next_state);

                if next_state == KMSMState::Transport {
                    let mut state = self.shared.state.lock().unwrap();
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



struct EncryptionError;

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "EncryptionError")
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
#[derive(Debug, Clone, PartialEq)]
pub enum KMSMState {
    Configuring,
    Transport,
    Error,
}



// Static settigns for the key management routine.
#[derive(Debug, Clone)]
pub struct KMSettings {
    pub zdp_km_type: u16,
    pub padlen: usize,
    pub alignment: u8,
    pub tick_interval: Duration,
}

pub trait TransportEncr : Send + Sync {
    fn encrypt_transport(self: &Self, payload: &[u8], message: &mut[u8]) -> Result<usize, EncryptionError>;
    fn decrypt_transport(self: &Self, payload: &[u8], message: &mut[u8]) -> Result<usize, EncryptionError>;
}

pub trait KeyManagerStateMachine : Send + Sync {

    // These do not change
    fn get_settings(self: &Self) -> KMSettings;

    // State can only change through handle_message, tick, or reset.
    fn get_state(self: &Self) -> KMSMState;

    // Reset state machine and optionally initiate a new handshake.
    // Must clear error state.
    fn reset(self: &mut Self, initiate: bool) -> Option<Bytes>;

    // process an inbound KM message.
    // may produce an output message.
    // may transition internal state.
    fn handle_message(self: &mut Self, message: &[u8]) -> Option<Bytes>;

    // Optional outbound KM message
    // May transition internal state
    fn tick(self: &mut Self) -> Option<Bytes>;

    // The encrypt/decrypt should not alter internal state of SA. So any state needed
    // must be part of the message. Not sure about this assumption -- but hoping to
    // avoid locking whole machine during encrypt/decrypt.
    fn get_transport_encryptor(self: &Self) -> Box<dyn TransportEncr>;
}









pub struct SillyKeyManager {
    state: KMSMState,
    settings: KMSettings,
    hello_t: time::Instant,
}

impl SillyKeyManager {
    pub fn new() -> SillyKeyManager {
        SillyKeyManager {
            state: KMSMState::Configuring,
            settings: KMSettings {
                zdp_km_type: 255, // experimental
                padlen: 2, // we need 2 extra bytes
                alignment: 0,
                tick_interval: Duration::from_millis(1000),
            },
            hello_t: time::Instant::now(),
        }
    }
}

struct SillyEncr;

impl TransportEncr for SillyEncr {
    // Copy payload into message with a SIZE preamble.
    fn encrypt_transport(self: &Self, payload: &[u8], message: &mut [u8]) -> Result<usize, EncryptionError> {
        let sz = payload.len() + 2; // SIZE includes the 2 byte size field.
        if sz > std::u16::MAX as usize {
            return Err(EncryptionError);
        }

        let szbytes = (sz as u16).to_be_bytes();
        message[0..3].copy_from_slice(&szbytes); // write SIZE as u16 to front of buffer


        message[2..sz].copy_from_slice(payload); // then copy rest of payload
        Ok(sz)
    }

    // Check and remove the SIZE preamble, return the payload
    fn decrypt_transport(self: &Self, payload: &[u8], message: &mut [u8]) -> Result<usize, EncryptionError> {

        let buf_sz = payload.len();

        if buf_sz < 2 {
            return Err(EncryptionError);
        }

        let msg_sz: u16 = u16::from_be_bytes([payload[0], payload[1]]);
        if buf_sz < msg_sz as usize {
            return Err(EncryptionError);
        }

        let msg_len: usize = (msg_sz - 2) as usize;

        message[..msg_len].copy_from_slice(&payload[2..]);
        Ok(msg_len)
    }
}


impl KeyManagerStateMachine for SillyKeyManager {

    fn get_settings(&self) -> KMSettings {
        return self.settings.clone();
    }

    fn get_state(&self) -> KMSMState {
        self.state.clone()
    }

    fn reset(&mut self, _initiate: bool) -> Option<Bytes> {
        let handshake = Bytes::from_static(&[0, 255, 0, 12, 1, 2, 3, 4, 5, 6, 7, 8]); // TYPE | LEN | PAYLOAD
        self.state = KMSMState::Configuring;
        self.hello_t = time::Instant::now();
        Some(handshake)
    }

    fn handle_message(&mut self, _message: &[u8]) -> Option<Bytes> {
       if self.state == KMSMState::Configuring {
        self.state = KMSMState::Transport;
       }
       None
    }

    fn tick(&mut self) -> Option<Bytes> {
        if self.state == KMSMState::Configuring {
            if self.hello_t.elapsed() > Duration::from_secs(5) {
                // too long, send another hello.
                let handshake = Bytes::from_static(&[0, 255, 0, 12, 1, 2, 3, 4, 5, 6, 7, 8]); // TYPE | LEN | PAYLOAD
                self.hello_t = time::Instant::now();
                return Some(handshake);
            }
        }
        None
    }

    fn get_transport_encryptor(self: &Self) -> Box<dyn TransportEncr> {
        return Box::new(SillyEncr{})
    }
}


