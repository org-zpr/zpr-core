//! Atomic performance counters.

use enum_map::{Enum, EnumMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

// Counters used in the fastpath
pub type FastpathCounters = EnumMap<FastpathCounterType, Counter>;
pub type ManagementCounters = EnumMap<ManagementCounterType, Counter>;

/// Struct of the system's performance counters. Broken into
/// counters used in fastpath and those used for management
// TODO the only way I could figure out to allow the fastpaths
// to be able to push a new FastpathCounters to the asm was 
// to make fastpaths a mutex, but it is less efficient, and I 
// don't think it is necessary, but had to do to appease the compiler
#[derive(Default)]
pub struct Counters {
    pub fastpaths: Mutex<Vec<FastpathCounters>>,
    pub management: ManagementCounters,
}

/// Implement counter type. Uses Atomic values, ensuring saftey for values in
/// multi-thread environment.
pub struct Counter {
    number: AtomicU64,
}

#[allow(dead_code)]
impl Counter {
    pub fn new() -> Self {
        Self {
            number: AtomicU64::new(0),
        }
    }

    pub fn reset(&self) {
        self.number.store(0, Ordering::Relaxed);
    }

    pub fn set(&self, value: u64) {
        self.number.store(value, Ordering::Relaxed);
    }

    pub fn increment(&self) {
        self.number.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement(&self) {
        self.number.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn increase_by(&self, amount: u64) {
        self.number.fetch_add(amount, Ordering::Relaxed);
    }

    pub fn decrease_by(&self, amount: u64) {
        self.number.fetch_sub(amount, Ordering::Relaxed);
    }

    pub fn get_count(&self) -> u64 {
        self.number.load(Ordering::Relaxed)
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}
#[derive(Debug, Enum, Copy, Clone, Eq, Hash, PartialEq)]
pub enum FastpathCounterType {
    InPacksRec,
    InPacksDrop,
    InPacksSent,
    OutPacksRec,
    OutPacksDrop,
    OutPacksSent,
    RequeuedPacketsReceived,
    MgmtPacketsSent,
    InCapPacksWrite,
    OutCapPacksWrite,
    InCapPacksDrop,
    OutCapPacksDrop,
    InCapPacksFilt,
    OutCapPacksFilt,
    DroppedOversize,

    QueueBackpressure,
    DroppedAwaitingBind,

    DispatchedToMgmt, // exited fastpath from substrate ingress, sent to mgmt
    ActorSlowpath,    // exited fastpath from actor output, sent to mgmt

    UnknownPeer,
    PeerRemoved,

    UnknownZpi,
    MicvFailure,
    BadChecksum,
    DecryptionFailure,
    EncryptionFailure,
    UnknownStreamId,
    BadStructure,
    OtherError,

    TtlExpired,

    #[cfg(debug_assertions)]
    ActorPacketsOutOfOrder,
}
/// Allows for easy access to name of each counter as well as index in
/// counters array
#[derive(Debug, Enum, Copy, Clone, Eq, Hash, PartialEq)]
pub enum ManagementCounterType {
    QueueBackpressure,
    DroppedAwaitingBind,
    DroppedNop,           // normal, not an error drop
    DroppedTooOld,        // "old" management packet received (possible duplicate)
    DroppedDuplicate,     // duplicate management packet detected
    DroppedNoSA,          // no security association on link
    InternalRoutingError, // a packet ended up somewhere it shouldn't have due to a coding error

    BadMgmtResponse,
    UnexpectedMgmtResponse,
    LostPacket,       // lost management packet detected
    OutOfOrderPacket, // out-of-order management packet detected (and processed)

    UnknownPeer,
    PeerRemoved,
    PeerHandshakeSuccess,
    PeerHandshakeFailure,

    // RFC 6.5 § 8.2.1
    SequenceError,
    UnknownType,
    BadStructure,
    OtherError,

    VisaRequested,
    VisaRequestSuccess,
    VisaRequestDenied,
    VisaRequestError,
}

impl FastpathCounterType {
    pub fn name(&self) -> &'static str {
        match *self {
            // Basic RX/TX
            Self::InPacksRec => "Inbound Packets Received",
            Self::InPacksDrop => "Inbound Packets Dropped",
            Self::InPacksSent => "Inbound Packets Sent",
            Self::OutPacksRec => "Outbound Packets Received",
            Self::RequeuedPacketsReceived => "Requeued Packets Received",
            Self::MgmtPacketsSent => "Mgmt Packets Sent",
            Self::OutPacksDrop => "Outbound Packets Dropped",
            Self::OutPacksSent => "Outbound Packets Sent",
            Self::InCapPacksWrite => "Inbound Capture Packets Written",
            Self::OutCapPacksWrite => "Outbound Capture Packets Written",
            Self::InCapPacksDrop => "Inbound Capture Packets Dropped",
            Self::OutCapPacksDrop => "Outbound Capture Packets Dropped",
            Self::InCapPacksFilt => "Inbound Capture Packets Filtered",
            Self::OutCapPacksFilt => "Outbound Capture Packets Filtered",
            Self::DroppedOversize => "Inbound Oversize Packets Dropped",

            // Packet drops
            Self::QueueBackpressure => "Fastpath QueueBackpressure",
            Self::DroppedAwaitingBind => "Fastpath Dropped Awaiting Bind",

            // Management packets
            Self::DispatchedToMgmt => "Dispatched to Management",
            Self::ActorSlowpath => "Actor Slowpath",

            // Peer operation failures
            Self::UnknownPeer => "Fastpath Unknown Peer",
            Self::PeerRemoved => "Fastpath Peer Removed",

            // § 8.2.1 ZDP errors
            Self::UnknownZpi => "Unknown ZPI",
            Self::MicvFailure => "MICV Failure",
            Self::BadChecksum => "Bad Checksum",
            Self::DecryptionFailure => "Decryption Failure",
            Self::EncryptionFailure => "Encryption Failure",
            Self::UnknownStreamId => "Unknown Stream ID",
            Self::BadStructure => "Fastpath Bad Structure",
            Self::OtherError => "Fastpath Other Error",

            Self::TtlExpired => "TTL Reached 0",

            #[cfg(debug_assertions)]
            Self::ActorPacketsOutOfOrder => "Actor Packets Out-Of-Order",
        }
    }
}

impl ManagementCounterType {
    pub fn name(&self) -> &'static str {
        match *self {
            // Packet drops
            Self::QueueBackpressure => "Management QueueBackpressure",
            Self::DroppedAwaitingBind => "Management Dropped Awaiting Bind",
            Self::DroppedTooOld => "Dropped Too Old",
            Self::DroppedDuplicate => "Dropped Duplicate",
            Self::DroppedNop => "Dropped No Operation",
            Self::DroppedNoSA => "Dropped No Security Association",
            Self::InternalRoutingError => "Internal Routing Error",

            // Management packets
            Self::BadMgmtResponse => "Bad Management Response",
            Self::UnexpectedMgmtResponse => "Unexpected Management Response",
            Self::LostPacket => "Lost Packet",
            Self::OutOfOrderPacket => "Out Of Order Packet",

            // Peer operation failures
            Self::UnknownPeer => "Management Unknown Peer",
            Self::PeerRemoved => "Management Peer Removed",
            Self::PeerHandshakeSuccess => "Peer Handshake Success",
            Self::PeerHandshakeFailure => "Peer Handshake Failure",

            // § 8.2.1 ZDP errors
            Self::SequenceError => "Sequence Error",
            Self::UnknownType => "Unknown Type",
            Self::BadStructure => "Management Bad Structure",
            Self::OtherError => "Management Other Error",

            // Visa counters (Node only)
            Self::VisaRequested => "Visa Requested",
            Self::VisaRequestSuccess => "Visa Request Success",
            Self::VisaRequestDenied => "Visa Request Denied",
            Self::VisaRequestError => "Visa Request Error",
        }
    }
}
impl fmt::Display for FastpathCounterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl fmt::Display for ManagementCounterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// TODO could also impl aggregate as a function of Counters
pub trait Aggregate {
    fn aggregate(&self, batches: &FastpathCounters);
}

impl Aggregate for FastpathCounters {
    fn aggregate(&self, batches: &FastpathCounters) {
        for (key, value) in batches.iter() {
            self[key].increase_by(value.get_count())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_get_count() {
        let counter = Counter::new();
        assert_eq!(counter.get_count(), 0);
    }

    #[test]
    fn test_set() {
        let counter = Counter::new();
        counter.set(10);
        assert_eq!(counter.get_count(), 10);
    }

    #[test]
    fn test_increment() {
        let counter = Counter::new();
        counter.set(10);
        counter.increment();
        assert_eq!(counter.get_count(), 11);
        counter.increment();
        assert_eq!(counter.get_count(), 12);
    }

    #[test]
    fn test_decrement() {
        let counter = Counter::new();
        counter.set(10);
        counter.decrement();
        assert_eq!(counter.get_count(), 9);
        counter.decrement();
        assert_eq!(counter.get_count(), 8);
    }

    #[test]
    fn test_reset() {
        let counter = Counter::new();
        counter.set(7543);
        assert_eq!(counter.get_count(), 7543);
        counter.reset();
        assert_eq!(counter.get_count(), 0);
    }

    #[test]
    fn test_increase() {
        let counter = Counter::new();
        assert_eq!(counter.get_count(), 0);
        counter.increase_by(653546);
        assert_eq!(counter.get_count(), 653546);
    }

    #[test]
    fn test_decrease() {
        let counter = Counter::new();
        counter.set(975467);
        assert_eq!(counter.get_count(), 975467);
        counter.decrease_by(4543);
        assert_eq!(counter.get_count(), 970924);
    }

    #[test]
    fn test_aggregate_increment() {
        let counters: Counters = Default::default();
        counters.fastpaths.lock().unwrap().push(FastpathCounters::default());

        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::InPacksRec].get_count(),
            0
        );

        let mut counters_batch: FastpathCounters = Default::default();
        counters_batch[FastpathCounterType::InPacksRec].increment();
        assert_eq!(
            counters_batch[FastpathCounterType::InPacksRec].get_count(),
            1
        );
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::InPacksRec].get_count(),
            0
        );

        counters.fastpaths.lock().unwrap()[0][FastpathCounterType::InPacksRec].increment();
        counters.fastpaths.lock().unwrap()[0].aggregate(&counters_batch);
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::InPacksRec].get_count(),
            2
        );
        assert_eq!(
            counters_batch[FastpathCounterType::InPacksRec].get_count(),
            1
        );

        counters_batch.clear();
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::InPacksRec].get_count(),
            2
        );
        assert_eq!(
            counters_batch[FastpathCounterType::InPacksRec].get_count(),
            0
        );
    }

    #[test]
    fn test_aggregate_increase_by() {
        let counters: Counters = Default::default();
        counters.fastpaths.lock().unwrap().push(FastpathCounters::default());
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::InPacksRec].get_count(),
            0
        );

        let mut counters_batch: FastpathCounters = Default::default();
        counters_batch[FastpathCounterType::InPacksRec].increase_by(53);
        assert_eq!(
            counters_batch[FastpathCounterType::InPacksRec].get_count(),
            53
        );
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::InPacksRec].get_count(),
            0
        );

        counters.fastpaths.lock().unwrap()[0][FastpathCounterType::InPacksRec].increase_by(654);
        counters.fastpaths.lock().unwrap()[0].aggregate(&counters_batch);
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::InPacksRec].get_count(),
            707
        );
        assert_eq!(
            counters_batch[FastpathCounterType::InPacksRec].get_count(),
            53
        );

        counters_batch.clear();
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::InPacksRec].get_count(),
            707
        );
        assert_eq!(
            counters_batch[FastpathCounterType::InPacksRec].get_count(),
            0
        );
    }

    #[test]
    fn test_aggregate_multiples() {
        let counters: Counters = Default::default();
        counters.fastpaths.lock().unwrap().push(FastpathCounters::default());
        let mut counters_batch: FastpathCounters = Default::default();

        counters.fastpaths.lock().unwrap()[0][FastpathCounterType::InPacksRec].increase_by(2);
        counters.fastpaths.lock().unwrap()[0][FastpathCounterType::QueueBackpressure].increase_by(8);
        counters.fastpaths.lock().unwrap()[0][FastpathCounterType::DispatchedToMgmt].increase_by(75);
        counters.fastpaths.lock().unwrap()[0][FastpathCounterType::UnknownZpi].increase_by(4);
        counters.fastpaths.lock().unwrap()[0][FastpathCounterType::TtlExpired].increase_by(2);
        counters.management[ManagementCounterType::QueueBackpressure].increase_by(432);
        counters.management[ManagementCounterType::UnexpectedMgmtResponse].increase_by(54);

        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::InPacksRec].get_count(),
            2
        );
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::QueueBackpressure].get_count(),
            8
        );
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::DispatchedToMgmt].get_count(),
            75
        );
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::UnknownZpi].get_count(),
            4
        );
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::TtlExpired].get_count(),
            2
        );
        assert_eq!(
            counters.management[ManagementCounterType::QueueBackpressure].get_count(),
            432
        );
        assert_eq!(
            counters.management[ManagementCounterType::UnexpectedMgmtResponse].get_count(),
            54
        );

        counters_batch[FastpathCounterType::DroppedOversize].increase_by(28);
        counters_batch[FastpathCounterType::QueueBackpressure].increase_by(12);
        counters_batch[FastpathCounterType::DispatchedToMgmt].increase_by(65);
        counters_batch[FastpathCounterType::UnknownPeer].increase_by(4);
        counters_batch[FastpathCounterType::OtherError].increase_by(1);

        assert_eq!(
            counters_batch[FastpathCounterType::DroppedOversize].get_count(),
            28
        );
        assert_eq!(
            counters_batch[FastpathCounterType::QueueBackpressure].get_count(),
            12
        );
        assert_eq!(
            counters_batch[FastpathCounterType::DispatchedToMgmt].get_count(),
            65
        );
        assert_eq!(
            counters_batch[FastpathCounterType::UnknownPeer].get_count(),
            4
        );
        assert_eq!(
            counters_batch[FastpathCounterType::OtherError].get_count(),
            1
        );

        counters.fastpaths.lock().unwrap()[0].aggregate(&counters_batch);
        counters_batch.clear();

        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::InPacksRec].get_count(),
            2
        );
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::QueueBackpressure].get_count(),
            20
        );
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::DispatchedToMgmt].get_count(),
            140
        );
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::UnknownZpi].get_count(),
            4
        );
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::TtlExpired].get_count(),
            2
        );
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::DroppedOversize].get_count(),
            28
        );
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::UnknownPeer].get_count(),
            4
        );
        assert_eq!(
            counters.fastpaths.lock().unwrap()[0][FastpathCounterType::OtherError].get_count(),
            1
        );
        assert_eq!(
            counters.management[ManagementCounterType::QueueBackpressure].get_count(),
            432
        );
        assert_eq!(
            counters.management[ManagementCounterType::UnexpectedMgmtResponse].get_count(),
            54
        );
        assert_eq!(
            counters_batch[FastpathCounterType::DroppedOversize].get_count(),
            0
        );
        assert_eq!(
            counters_batch[FastpathCounterType::QueueBackpressure].get_count(),
            0
        );
        assert_eq!(
            counters_batch[FastpathCounterType::DispatchedToMgmt].get_count(),
            0
        );
        assert_eq!(
            counters_batch[FastpathCounterType::UnknownPeer].get_count(),
            0
        );
        assert_eq!(
            counters_batch[FastpathCounterType::OtherError].get_count(),
            0
        );
    }
}
