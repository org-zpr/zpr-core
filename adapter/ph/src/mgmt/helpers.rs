//! Miscellaneous helpers that don't fit as private functions elsewhere.

use crate::assembly::Assembly;
use crate::packet::Packet;
use crate::tlv;
use zpr;

/// Grab the ZDPR window size for the given link from the assembly and put as a TLV in the given packet.
///
/// Used for both `HelloRequest` and `HelloResponse` messages.
pub fn put_window_size_tlv(asm: &Assembly, link_id: zpr::LinkId, pkt: &mut Packet) {
    asm.peer_table.inspect(link_id, |ps| {
        tlv::TlvEncoding::new_window_size(std::cmp::min(
            ps.zdpr_recv.lock().unwrap().window_size(),
            u16::MAX as usize,
        ) as u16)
        .put(pkt)
    });
}
