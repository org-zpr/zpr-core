//! Atomic performance counters.

use enum_map::{Enum, EnumMap};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// Array of the system's performance counters.
pub type Counters = EnumMap<CounterType, Counter>;

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

/// Allows for easy access to name of each counter as well as index in
/// counters array
#[derive(Debug, Enum, Copy, Clone)]
pub enum CounterType {
    InPacksRec,
    InPacksDrop,
    InPacksSent,
    OutPacksRec,
    RequeuedPacketsReceived,
    MgmtPacketsSent,
    OutPacksDrop,
    OutPacksSent,
    OutPacksErr,
    InCapPacksWrite,
    OutCapPacksWrite,
    InCapPacksDrop,
    OutCapPacksDrop,
    InCapPacksFilt,
    OutCapPacksFilt,
    DroppedOversize,

    QueueBackpressure,
    DroppedAwaitingBind,
    DroppedNop,           // normal, not an error drop
    DroppedTooOld,        // "old" management packet received (possible duplicate)
    DroppedDuplicate,     // duplicate management packet detected
    DroppedNoSA,          // no security association on link
    InternalRoutingError, // a packet ended up somewhere it shouldn't have due to a coding error

    DispatchedToMgmt, // exited fastpath from substrate ingress, sent to mgmt
    ActorSlowpath,    // exited fastpath from actor output, sent to mgmt
    BadMgmtResponse,
    UnexpectedMgmtResponse,
    LostPacket,       // lost management packet detected
    OutOfOrderPacket, // out-of-order management packet detected (and processed)

    UnknownPeer,
    PeerRemoved,
    PeerHandshakeSuccess,
    PeerHandshakeFailure,

    // RFC 6.5 § 8.2.1
    UnknownZpi,
    SequenceError,
    MicvFailure,
    BadChecksum, // internet checksum used in null encrypt/decrypt
    DecryptionFailure,
    EncryptionFailure,
    UnknownType,
    UnknownStreamId,
    BadStructure,
    OtherError,

    VisaRequested,
    VisaRequestSuccess,
    VisaRequestDenied,
    VisaRequestError,

    TtlExpired,

    #[cfg(debug_assertions)]
    ActorPacketsOutOfOrder,
}

impl CounterType {
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
            Self::OutPacksErr => "Outbound Packet Send Errors",
            Self::InCapPacksWrite => "Inbound Capture Packets Written",
            Self::OutCapPacksWrite => "Outbound Capture Packets Written",
            Self::InCapPacksDrop => "Inbound Capture Packets Dropped",
            Self::OutCapPacksDrop => "Outbound Capture Packets Dropped",
            Self::InCapPacksFilt => "Inbound Capture Packets Filtered",
            Self::OutCapPacksFilt => "Outbound Capture Packets Filtered",
            Self::DroppedOversize => "Inbound Oversize Packets Dropped",

            // Packet drops
            Self::QueueBackpressure => "QueueBackpressure",
            Self::DroppedAwaitingBind => "Dropped Awaiting Bind",
            Self::DroppedTooOld => "Dropped Too Old",
            Self::DroppedDuplicate => "Dropped Duplicate",
            Self::DroppedNop => "Dropped No Operation",
            Self::DroppedNoSA => "Dropped No Security Association",
            Self::InternalRoutingError => "Internal Routing Error",

            // Management packets
            Self::DispatchedToMgmt => "Dispatched to Management",
            Self::ActorSlowpath => "Actor Slowpath",
            Self::BadMgmtResponse => "Bad Management Response",
            Self::UnexpectedMgmtResponse => "Unexpected Management Response",
            Self::LostPacket => "Lost Packet",
            Self::OutOfOrderPacket => "Out Of Order Packet",

            // Peer operation failures
            Self::UnknownPeer => "Unknown Peer",
            Self::PeerRemoved => "Peer Removed",
            Self::PeerHandshakeSuccess => "Peer Handshake Success",
            Self::PeerHandshakeFailure => "Peer Handshake Failure",

            // § 8.2.1 ZDP errors
            Self::UnknownZpi => "Unknown ZPI",
            Self::SequenceError => "Sequence Error",
            Self::MicvFailure => "MICV Failure",
            Self::BadChecksum => "Bad Checksum",
            Self::DecryptionFailure => "Decryption Failure",
            Self::EncryptionFailure => "Encryption Failure",
            Self::UnknownType => "Unknown Type",
            Self::UnknownStreamId => "Unknown Stream ID",
            Self::BadStructure => "Bad Structure",
            Self::OtherError => "Other Error",

            // Visa counters (Node only)
            Self::VisaRequested => "Visa Requested",
            Self::VisaRequestSuccess => "Visa Request Success",
            Self::VisaRequestDenied => "Visa Request Denied",
            Self::VisaRequestError => "Visa Request Error",

            Self::TtlExpired => "TTL Reached 0",

            #[cfg(debug_assertions)]
            Self::ActorPacketsOutOfOrder => "Actor Packets Out-Of-Order",
        }
    }
}

impl fmt::Display for CounterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// pub trait Reset {
//     fn reset(&mut self);
// }

pub trait Aggregate {
    fn aggregate(&self, batch_counters: &Counters);
}

// impl Reset for Counters {
//     fn reset(&mut self) {
//         self.clear()
//     }
// }

impl Aggregate for Counters {
    fn aggregate(&self, batch_counters: &Counters) {
        for (counter_type, count) in batch_counters.iter() {
            self[counter_type].increase_by(count.get_count());
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
    fn test_aggregate() {
        let counters: Counters = Default::default();
        assert_eq!(counters[CounterType::DroppedOversize].get_count(), 0);

        let mut counters_batch: Counters = Default::default();
        counters_batch[CounterType::DroppedOversize].increase_by(5);
        assert_eq!(counters_batch[CounterType::DroppedOversize].get_count(), 5);
        assert_eq!(counters[CounterType::DroppedOversize].get_count(), 0);

        counters[CounterType::DroppedOversize].increment();
        counters.aggregate(&counters_batch);
        assert_eq!(counters[CounterType::DroppedOversize].get_count(), 6);
        assert_eq!(counters_batch[CounterType::DroppedOversize].get_count(), 5);

        counters_batch.clear();
        assert_eq!(counters[CounterType::DroppedOversize].get_count(), 6);
        assert_eq!(counters_batch[CounterType::DroppedOversize].get_count(), 0);
    }

    #[test]
    fn test_aggregate_multiples() {
        let counters: Counters = Default::default();
        let mut counters_batch: Counters = Default::default();

        counters[CounterType::InPacksRec].increase_by(2);
        counters[CounterType::QueueBackpressure].increase_by(8);
        counters[CounterType::DispatchedToMgmt].increase_by(75);
        counters[CounterType::UnknownZpi].increase_by(4);
        counters[CounterType::TtlExpired].increase_by(2);

        assert_eq!(counters[CounterType::InPacksRec].get_count(), 2);
        assert_eq!(counters[CounterType::QueueBackpressure].get_count(), 8);
        assert_eq!(counters[CounterType::DispatchedToMgmt].get_count(), 75);
        assert_eq!(counters[CounterType::UnknownZpi].get_count(), 4);
        assert_eq!(counters[CounterType::TtlExpired].get_count(), 2);

        counters_batch[CounterType::DroppedOversize].increase_by(28);
        counters_batch[CounterType::QueueBackpressure].increase_by(12);
        counters_batch[CounterType::DispatchedToMgmt].increase_by(65);
        counters_batch[CounterType::UnknownPeer].increase_by(4);
        counters_batch[CounterType::OtherError].increase_by(1);

        assert_eq!(counters_batch[CounterType::DroppedOversize].get_count(), 28);
        assert_eq!(
            counters_batch[CounterType::QueueBackpressure].get_count(),
            12
        );
        assert_eq!(
            counters_batch[CounterType::DispatchedToMgmt].get_count(),
            65
        );
        assert_eq!(counters_batch[CounterType::UnknownPeer].get_count(), 4);
        assert_eq!(counters_batch[CounterType::OtherError].get_count(), 1);

        counters.aggregate(&counters_batch);
        counters_batch.clear();

        assert_eq!(counters[CounterType::InPacksRec].get_count(), 2);
        assert_eq!(counters[CounterType::QueueBackpressure].get_count(), 20);
        assert_eq!(counters[CounterType::DispatchedToMgmt].get_count(), 140);
        assert_eq!(counters[CounterType::UnknownZpi].get_count(), 4);
        assert_eq!(counters[CounterType::TtlExpired].get_count(), 2);
        assert_eq!(counters[CounterType::DroppedOversize].get_count(), 28);
        assert_eq!(counters[CounterType::UnknownPeer].get_count(), 4);
        assert_eq!(counters[CounterType::OtherError].get_count(), 1);

        assert_eq!(counters_batch[CounterType::DroppedOversize].get_count(), 0);
        assert_eq!(
            counters_batch[CounterType::QueueBackpressure].get_count(),
            0
        );
        assert_eq!(counters_batch[CounterType::DispatchedToMgmt].get_count(), 0);
        assert_eq!(counters_batch[CounterType::UnknownPeer].get_count(), 0);
        assert_eq!(counters_batch[CounterType::OtherError].get_count(), 0);
    }
}
