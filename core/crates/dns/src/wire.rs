//! Just enough of the DNS wire format (RFC 1035 section 4.1) to answer and to patch answers
//! without decoding them: header bits, the question, and where each record's TTL is.

use std::ops::Range;

pub(crate) const HEADER_LEN: usize = 12;
const TYPE_OPT: u16 = 41;
const MAX_NAME_LEN: usize = 255;

pub(crate) fn u16_at(msg: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(at)?, *msg.get(at + 1)?]))
}

pub(crate) fn set_u16(msg: &mut [u8], at: usize, value: u16) {
    msg[at..at + 2].copy_from_slice(&value.to_be_bytes());
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

/// The question as a cache key: the name with ASCII letters lowercased, then type and class
/// unchanged. `end` comes from [`question_end`].
pub(crate) fn question_key(msg: &[u8], end: usize) -> Box<[u8]> {
    let mut key = msg[HEADER_LEN..end].to_vec();
    let name_len = key.len() - 4;
    key[..name_len].make_ascii_lowercase();
    key.into_boxed_slice()
}

/// Where the records of a message are.
pub(crate) struct Records {
    /// Offset of the TTL field of every record except OPT.
    pub ttl_offsets: Vec<u16>,
    /// The OPT pseudo-record, if any.
    pub opt: Option<Range<usize>>,
    /// Extended RCODE bits from OPT (zero without OPT).
    pub extended_rcode: u8,
    /// Offset just past the last record.
    pub end: usize,
}

/// Walks every record after the question. `None` if a record runs past the end of the
/// message, OPT appears outside the additional section or more than once, or an offset does
/// not fit in 16 bits.
pub(crate) fn records(msg: &[u8], question_end: usize) -> Option<Records> {
    let answers = usize::from(u16_at(msg, 6)?);
    let authorities = usize::from(u16_at(msg, 8)?);
    let additionals = usize::from(u16_at(msg, 10)?);
    let mut found = Records {
        ttl_offsets: Vec::with_capacity(answers + authorities + additionals),
        opt: None,
        extended_rcode: 0,
        end: question_end,
    };
    let mut at = question_end;
    for index in 0..answers + authorities + additionals {
        let start = at;
        at = skip_name(msg, at, true)?;
        let rtype = u16_at(msg, at)?;
        let end = at + 10 + usize::from(u16_at(msg, at + 8)?);
        if end > msg.len() {
            return None;
        }
        if rtype == TYPE_OPT {
            if index < answers + authorities || found.opt.is_some() {
                return None;
            }
            found.opt = Some(start..end);
            found.extended_rcode = msg[at + 4];
        } else {
            found.ttl_offsets.push(u16::try_from(at + 4).ok()?);
        }
        at = end;
    }
    found.end = at;
    Some(found)
}
