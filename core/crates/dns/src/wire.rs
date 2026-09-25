//! Just enough of the DNS wire format (RFC 1035 section 4.1) to answer and to patch answers
//! without decoding them: header bits, the question, and where each record's TTL is.

pub(crate) const HEADER_LEN: usize = 12;
const MAX_NAME_LEN: usize = 255;

pub(crate) fn u16_at(msg: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(at)?, *msg.get(at + 1)?]))
}

/// QR bit. `msg` must hold a whole header.
pub(crate) fn is_response(msg: &[u8]) -> bool {
    msg[2] & 0x80 != 0
}

/// Offset just past the name that starts at `at`. A compression pointer ends the name;
/// `allow_pointer` is false for the question, which is never compressed.
fn skip_name(msg: &[u8], mut at: usize, allow_pointer: bool) -> Option<usize> {
    let start = at;
    loop {
        let len = usize::from(*msg.get(at)?);
        match len & 0xc0 {
            0x00 if len == 0 => return Some(at + 1),
            0x00 => {
                at += 1 + len;
                if at - start >= MAX_NAME_LEN {
                    return None;
                }
            }
            0xc0 if allow_pointer => {
                msg.get(at + 1)?;
                return Some(at + 2);
            }
            _ => return None,
        }
    }
}

/// End offset of the only question, or `None` unless the message has exactly one question
/// with an uncompressed name.
pub(crate) fn question_end(msg: &[u8]) -> Option<usize> {
    if u16_at(msg, 4)? != 1 {
        return None;
    }
    let end = skip_name(msg, HEADER_LEN, false)? + 4;
    (end <= msg.len()).then_some(end)
}
