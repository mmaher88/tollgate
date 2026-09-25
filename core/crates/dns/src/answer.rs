//! Writing replies. Local answers are built from the requester's own question bytes, so they
//! keep the requester's id, letter case and EDNS.

use hickory_proto::op::Message;

use crate::wire::HEADER_LEN;

/// TTL of the `0.0.0.0` and `::` answers for blocked names, in seconds.
pub const BLOCK_TTL: u32 = 60;
/// UDP payload size advertised in our OPT records and the most any reply uses.
pub const MAX_UDP_PAYLOAD: u16 = 1232;

pub(crate) const NOERROR: u8 = 0;
pub(crate) const FORMERR: u8 = 1;
pub(crate) const NOTIMP: u8 = 4;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const OPT_LEN: usize = 11;

/// A reply with only a header, for queries that could not be read: the id, opcode and RD
/// bit are copied, QR and RA are set and every count is zero.
pub(crate) fn header_only(query: &[u8], rcode: u8) -> Vec<u8> {
    let mut out = vec![0; HEADER_LEN];
    out[..2].copy_from_slice(&query[..2]);
    out[2] = 0x80 | (query[2] & 0x79);
    out[3] = 0x80 | rcode;
    out
}

/// EDNS from the requester's OPT record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClientEdns {
    pub dnssec_ok: bool,
}

/// What every reply to one query must match.
#[derive(Clone, Debug)]
pub(crate) struct Requester {
    pub id: u16,
    pub recursion_desired: bool,
    /// The question exactly as sent: name in the requester's letter case, type, class.
    pub question: Box<[u8]>,
    pub edns: Option<ClientEdns>,
}

impl Requester {
    pub fn from_query(query: &[u8], message: &Message, question_end: usize) -> Requester {
        Requester {
            id: message.metadata.id,
            recursion_desired: message.metadata.recursion_desired,
            question: query[HEADER_LEN..question_end].into(),
            edns: message.edns.as_ref().map(|edns| ClientEdns {
                dnssec_ok: edns.flags().dnssec_ok,
            }),
        }
    }

    fn qtype_and_class(&self) -> (u16, u16) {
        let n = self.question.len();
        (
            u16::from_be_bytes([self.question[n - 4], self.question[n - 3]]),
            u16::from_be_bytes([self.question[n - 2], self.question[n - 1]]),
        )
    }

    /// Our OPT record, echoing the DO bit, if the requester sent OPT.
    fn opt(&self) -> Option<[u8; OPT_LEN]> {
        self.edns.map(|edns| {
            let size = MAX_UDP_PAYLOAD.to_be_bytes();
            let flags = if edns.dnssec_ok { 0x80 } else { 0 };
            [0, 0, 41, size[0], size[1], 0, 0, flags, 0, 0, 0]
        })
    }

    /// Header, question, `records` (already encoded, `count` of them, all in the answer
    /// section) and OPT. `flags` are header bytes 2 and 3.
    fn build(&self, flags: [u8; 2], records: &[u8], count: u16) -> Vec<u8> {
        let opt = self.opt();
        let mut out =
            Vec::with_capacity(HEADER_LEN + self.question.len() + records.len() + OPT_LEN);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&flags);
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&u16::from(opt.is_some()).to_be_bytes());
        out.extend_from_slice(&self.question);
        out.extend_from_slice(records);
        if let Some(opt) = opt {
            out.extend_from_slice(&opt);
        }
        out
    }

    fn local_flags(&self, rcode: u8) -> [u8; 2] {
        [0x80 | u8::from(self.recursion_desired), 0x80 | rcode]
    }

    /// A reply with no records, for HTTPS and SVCB queries.
    pub fn empty(&self, rcode: u8) -> Vec<u8> {
        self.build(self.local_flags(rcode), &[], 0)
    }

    /// The reply for a blocked name: `0.0.0.0` for A, `::` for AAAA, both with a TTL of
    /// [`BLOCK_TTL`], and no records for any other type.
    pub fn blocked(&self) -> Vec<u8> {
        let (qtype, qclass) = self.qtype_and_class();
        let rdata_len: u16 = match (qtype, qclass) {
            (TYPE_A, CLASS_IN) => 4,
            (TYPE_AAAA, CLASS_IN) => 16,
            _ => return self.empty(NOERROR),
        };
        // Owner name: a pointer to the question name at offset 12.
        let mut record = vec![0xc0, 0x0c];
        record.extend_from_slice(&qtype.to_be_bytes());
        record.extend_from_slice(&CLASS_IN.to_be_bytes());
        record.extend_from_slice(&BLOCK_TTL.to_be_bytes());
        record.extend_from_slice(&rdata_len.to_be_bytes());
        record.resize(record.len() + usize::from(rdata_len), 0);
        self.build(self.local_flags(NOERROR), &record, 1)
    }
}
