//! Writing replies.

use crate::wire::HEADER_LEN;

pub(crate) const FORMERR: u8 = 1;
pub(crate) const NOTIMP: u8 = 4;

/// A reply with only a header, for queries that could not be read: the id, opcode and RD
/// bit are copied, QR and RA are set and every count is zero.
pub(crate) fn header_only(query: &[u8], rcode: u8) -> Vec<u8> {
    let mut out = vec![0; HEADER_LEN];
    out[..2].copy_from_slice(&query[..2]);
    out[2] = 0x80 | (query[2] & 0x79);
    out[3] = 0x80 | rcode;
    out
}
