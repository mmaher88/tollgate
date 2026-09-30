//! Whether a client that hung up during the TLS handshake had received our certificate.
//!
//! An app that pins certificates may refuse the proxy's leaf without the TLS alert that pin
//! learning looks for: the X app for iOS cancels the connection inside its certificate
//! check, and the socket just closes, sometimes after a close_notify. Any client also hangs
//! up for reasons that have nothing to do with the certificate, and one that hangs up
//! before our certificate reached it cannot have refused it. [`FlightWatch`] wraps the
//! client stream of an intercepted connection and follows the TLS records the proxy writes
//! to it, and the handshake messages among them that are sent in the clear, to tell when
//! the record carrying the certificate has been written in full:
//!
//! - TLS 1.3: a ServerHello that is neither a HelloRetryRequest (which X gets, because it
//!   offers a key share for a group the proxy does not support) nor the acceptance of a
//!   pre-shared key (a resumed session sends no certificate), then the first encrypted
//!   record. rustls sends EncryptedExtensions through Finished as one flight message, split
//!   into records only past 16 KiB, which Tollgate's leaf is far below.
//! - TLS 1.2: a Certificate message after the ServerHello. A resumed session sends
//!   ChangeCipherSpec instead.
//!
//! Anything else the proxy writes before that (an alert, or records that cannot be
//! followed) ends the watch without a certificate. The written bytes only show that the
//! certificate left the proxy, so the client must also have been still connected after
//! that: a read of the client found nothing to read yet. A client that closed right after
//! its ClientHello, before the proxy answered, has its end of stream waiting already, and
//! does not count.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// TLS record content types.
const CHANGE_CIPHER_SPEC: u8 = 20;
const ALERT: u8 = 21;
const HANDSHAKE: u8 = 22;
const APPLICATION_DATA: u8 = 23;

/// Handshake message types.
const SERVER_HELLO: u8 = 2;
const CERTIFICATE: u8 = 11;

/// Extension types in a ServerHello.
const PRE_SHARED_KEY: u16 = 41;
const SUPPORTED_VERSIONS: u16 = 43;

/// The `random` of a ServerHello that is a HelloRetryRequest (RFC 8446, section 4.1.3):
/// SHA-256 of "HelloRetryRequest".
const HELLO_RETRY_REQUEST: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// Plaintext handshake bytes kept while a message is incomplete. The proxy's first flight
/// in the clear is a ServerHello, and with TLS 1.2 the certificate chain, far below this;
/// more ends the watch.
const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;

/// How far the proxy's handshake has been written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Progress {
    /// No ServerHello yet, or only a HelloRetryRequest.
    Hello,
    /// A TLS 1.3 ServerHello starting a full handshake: the certificate follows in the
    /// first encrypted record.
    Tls13,
    /// A TLS 1.2 ServerHello: the certificate follows, unless the session is resumed.
    Tls12,
    /// The record carrying the certificate has been written in full.
    CertificateSent,
    /// No certificate is sent (the session is resumed), or the records could not be
    /// followed: the watch is over.
    NoCertificate,
}

/// Follows the TLS records written to the client, as [`FlightWatch`] describes.
#[derive(Debug)]
struct Records {
    progress: Progress,
    /// The header of the record being written.
    header: [u8; 5],
    header_len: usize,
    /// Bytes of the record being written still to come after its header.
    remaining: usize,
    /// Plaintext handshake bytes not yet parsed into messages.
    handshake: Vec<u8>,
}

impl Records {
    fn new() -> Records {
        Records {
            progress: Progress::Hello,
            header: [0; 5],
            header_len: 0,
            remaining: 0,
            handshake: Vec::new(),
        }
    }

    fn watching(&self) -> bool {
        !matches!(
            self.progress,
            Progress::CertificateSent | Progress::NoCertificate
        )
    }

    /// Follows `bytes`, the next bytes the proxy wrote to the client.
    fn written(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() && self.watching() {
            if self.header_len < self.header.len() {
                let n = (self.header.len() - self.header_len).min(bytes.len());
                self.header[self.header_len..self.header_len + n].copy_from_slice(&bytes[..n]);
                self.header_len += n;
                bytes = &bytes[n..];
                if self.header_len == self.header.len() {
                    self.remaining =
                        usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                    if self.remaining == 0 {
                        self.record_written();
                    }
                }
                continue;
            }
            let n = self.remaining.min(bytes.len());
            if self.header[0] == HANDSHAKE
                && matches!(self.progress, Progress::Hello | Progress::Tls12)
            {
                self.handshake.extend_from_slice(&bytes[..n]);
            }
            self.remaining -= n;
            bytes = &bytes[n..];
            if self.remaining == 0 {
                self.record_written();
            }
        }
        if !self.watching() {
            self.handshake = Vec::new();
        }
    }

    /// The record whose header is `self.header` has been written in full.
    fn record_written(&mut self) {
        self.header_len = 0;
        self.progress = match (self.header[0], self.progress) {
            (HANDSHAKE, Progress::Hello | Progress::Tls12) => self.handshake_messages(),
            // TLS 1.3 sends one for compatibility with middleboxes; ignore it.
            (CHANGE_CIPHER_SPEC, Progress::Hello | Progress::Tls13) => self.progress,
            (APPLICATION_DATA, Progress::Tls13) => Progress::CertificateSent,
            // The proxy failed the handshake itself.
            (ALERT, _) => Progress::NoCertificate,
            // TLS 1.2 changes cipher before any certificate only to resume a session.
            (CHANGE_CIPHER_SPEC, Progress::Tls12) => Progress::NoCertificate,
            // Anything else is out of order.
            _ => Progress::NoCertificate,
        };
    }

    /// Parses the complete handshake messages written so far and returns the progress
    /// they show.
    fn handshake_messages(&mut self) -> Progress {
        let mut progress = self.progress;
        let mut used = 0;
        loop {
            let rest = &self.handshake[used..];
            let Some(&[kind, a, b, c]) = rest.get(..4) else {
                break;
            };
            let len = (usize::from(a) << 16) | (usize::from(b) << 8) | usize::from(c);
            let Some(body) = rest.get(4..4 + len) else {
                break;
            };
            progress = match (progress, kind) {
                (Progress::Hello, SERVER_HELLO) => server_hello(body),
                (Progress::Tls12, CERTIFICATE) => Progress::CertificateSent,
                _ => Progress::NoCertificate,
            };
            used += 4 + len;
            if !matches!(progress, Progress::Hello | Progress::Tls12) {
                return progress;
            }
        }
        self.handshake.drain(..used);
        if self.handshake.len() > MAX_HANDSHAKE_BYTES {
            return Progress::NoCertificate;
        }
        progress
    }
}

/// What a ServerHello with this body starts: another ServerHello after a HelloRetryRequest,
/// a full TLS 1.3 handshake, a TLS 1.2 handshake, or none with a certificate (a resumed
/// TLS 1.3 session, or a body that cannot be read).
fn server_hello(body: &[u8]) -> Progress {
    fn read(body: &[u8]) -> Option<Progress> {
        // legacy_version, random, legacy_session_id, cipher_suite, compression_method.
        let random = body.get(2..34)?;
        if random == HELLO_RETRY_REQUEST {
            return Some(Progress::Hello);
        }
        let session_id_len = usize::from(*body.get(34)?);
        let mut rest = body.get(35 + session_id_len + 3..)?;
        if rest.is_empty() {
            return Some(Progress::Tls12);
        }
        let extensions_len = usize::from(u16::from_be_bytes([*rest.first()?, *rest.get(1)?]));
        rest = rest.get(2..2 + extensions_len)?;
        let (mut tls13, mut resumed) = (false, false);
        while !rest.is_empty() {
            let kind = u16::from_be_bytes([*rest.first()?, *rest.get(1)?]);
            let len = usize::from(u16::from_be_bytes([*rest.get(2)?, *rest.get(3)?]));
            let data = rest.get(4..4 + len)?;
            match kind {
                SUPPORTED_VERSIONS => tls13 = data == [3, 4],
                PRE_SHARED_KEY => resumed = true,
                _ => {}
            }
            rest = &rest[4 + len..];
        }
        Some(match (tls13, resumed) {
            (true, false) => Progress::Tls13,
            (true, true) => Progress::NoCertificate,
            (false, _) => Progress::Tls12,
        })
    }
    read(body).unwrap_or(Progress::NoCertificate)
}

/// A client stream that follows the proxy's side of the TLS handshake (see the module
/// docs). Reads and writes go straight to the stream; once the certificate has been
/// written, or can no longer be, the written bytes are no longer looked at.
pub(crate) struct FlightWatch<C> {
    inner: C,
    records: Records,
    /// A read found nothing to read after the certificate had been written.
    waited: bool,
}

impl<C> FlightWatch<C> {
    pub(crate) fn new(inner: C) -> FlightWatch<C> {
        FlightWatch {
            inner,
            records: Records::new(),
            waited: false,
        }
    }

    /// Whether the client could have seen our certificate: the record carrying it was
    /// written in full, and the client had not hung up by the time it was waited for.
    pub(crate) fn certificate_delivered(&self) -> bool {
        self.records.progress == Progress::CertificateSent && self.waited
    }
}

impl<C: AsyncRead + Unpin> AsyncRead for FlightWatch<C> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if result.is_pending() && self.records.progress == Progress::CertificateSent {
            self.waited = true;
        }
        result
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for FlightWatch<C> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result
            && self.records.watching()
        {
            self.records.written(&buf[..n]);
        }
        result
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(mut n)) = result {
            for buf in bufs {
                if n == 0 || !self.records.watching() {
                    break;
                }
                let written = n.min(buf.len());
                self.records.written(&buf[..written]);
                n -= written;
            }
        }
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TLS record of `kind` holding `fragment`.
    fn record(kind: u8, fragment: &[u8]) -> Vec<u8> {
        let mut out = vec![kind, 3, 3];
        out.extend_from_slice(&u16::try_from(fragment.len()).unwrap().to_be_bytes());
        out.extend_from_slice(fragment);
        out
    }

    /// A handshake message of `kind` holding `body`.
    fn message(kind: u8, body: &[u8]) -> Vec<u8> {
        let len = u32::try_from(body.len()).unwrap().to_be_bytes();
        let mut out = vec![kind, len[1], len[2], len[3]];
        out.extend_from_slice(body);
        out
    }

    /// A ServerHello body with `random` and these extensions (type, data).
    fn hello(random: [u8; 32], extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&random);
        body.push(32);
        body.extend_from_slice(&[7; 32]);
        body.extend_from_slice(&[0x13, 0x01, 0]);
        let mut ext = Vec::new();
        for (kind, data) in extensions {
            ext.extend_from_slice(&kind.to_be_bytes());
            ext.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
            ext.extend_from_slice(data);
        }
        if !extensions.is_empty() {
            body.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
            body.extend_from_slice(&ext);
        }
        body
    }

    const TLS13: (u16, &[u8]) = (SUPPORTED_VERSIONS, &[3, 4]);
    const KEY_SHARE: (u16, &[u8]) = (51, &[0, 29, 0, 2, 1, 2]);

    /// Feeds `bytes` in pieces of `step` bytes and returns the progress.
    fn follow(bytes: &[u8], step: usize) -> Progress {
        let mut records = Records::new();
        for piece in bytes.chunks(step) {
            records.written(piece);
        }
        records.progress
    }

    #[test]
    fn a_full_tls13_handshake_sends_the_certificate_in_the_first_encrypted_record() {
        let mut flight = record(
            HANDSHAKE,
            &message(SERVER_HELLO, &hello([1; 32], &[KEY_SHARE, TLS13])),
        );
        flight.extend(record(CHANGE_CIPHER_SPEC, &[1]));
        assert_eq!(follow(&flight, 1), Progress::Tls13);
        flight.extend(record(APPLICATION_DATA, &[9; 600]));
        for step in [1, 5, 7, 100, flight.len()] {
            assert_eq!(
                follow(&flight, step),
                Progress::CertificateSent,
                "step {step}"
            );
        }
        // Not before its last byte.
        assert_eq!(follow(&flight[..flight.len() - 1], 3), Progress::Tls13);
    }

    #[test]
    fn a_hello_retry_request_waits_for_the_second_server_hello() {
        let retry = record(
            HANDSHAKE,
            &message(SERVER_HELLO, &hello(HELLO_RETRY_REQUEST, &[TLS13])),
        );
        assert_eq!(follow(&retry, 2), Progress::Hello);
        let mut flight = retry.clone();
        flight.extend(record(CHANGE_CIPHER_SPEC, &[1]));
        flight.extend(record(
            HANDSHAKE,
            &message(SERVER_HELLO, &hello([1; 32], &[TLS13])),
        ));
        flight.extend(record(APPLICATION_DATA, &[9; 40]));
        assert_eq!(follow(&flight, 4), Progress::CertificateSent);
    }

    #[test]
    fn a_resumed_tls13_session_sends_no_certificate() {
        let psk = (PRE_SHARED_KEY, &[0u8, 0][..]);
        let mut flight = record(
            HANDSHAKE,
            &message(SERVER_HELLO, &hello([1; 32], &[TLS13, psk])),
        );
        flight.extend(record(APPLICATION_DATA, &[9; 40]));
        assert_eq!(follow(&flight, 3), Progress::NoCertificate);
    }

    #[test]
    fn tls12_sends_the_certificate_in_the_clear_unless_it_resumes() {
        let mut messages = message(SERVER_HELLO, &hello([1; 32], &[]));
        let hello_len = messages.len();
        messages.extend(message(CERTIFICATE, &[0; 700]));
        messages.extend(message(14, &[]));
        // In one record, or split across records.
        assert_eq!(
            follow(&record(HANDSHAKE, &messages), 1),
            Progress::CertificateSent
        );
        for at in [30, hello_len, hello_len + 10] {
            let (first, second) = messages.split_at(at);
            let mut split = record(HANDSHAKE, first);
            split.extend(record(HANDSHAKE, second));
            let expected = if at < hello_len {
                Progress::Hello
            } else {
                Progress::Tls12
            };
            assert_eq!(follow(&split[..split.len() - 1], 9), expected, "at {at}");
            assert_eq!(follow(&split, 9), Progress::CertificateSent, "at {at}");
        }

        let mut resumed = record(
            HANDSHAKE,
            &message(SERVER_HELLO, &hello([1; 32], &[(23, &[])])),
        );
        assert_eq!(follow(&resumed, 8), Progress::Tls12);
        resumed.extend(record(CHANGE_CIPHER_SPEC, &[1]));
        assert_eq!(follow(&resumed, 8), Progress::NoCertificate);
    }

    #[test]
    fn an_alert_or_garbage_ends_the_watch() {
        assert_eq!(follow(&record(ALERT, &[2, 40]), 1), Progress::NoCertificate);
        assert_eq!(follow(&record(99, &[0; 10]), 3), Progress::NoCertificate);
        assert_eq!(
            follow(&record(HANDSHAKE, &message(CERTIFICATE, &[0; 10])), 3),
            Progress::NoCertificate
        );
        assert_eq!(
            follow(&record(HANDSHAKE, &message(SERVER_HELLO, &[3, 3, 0])), 3),
            Progress::NoCertificate
        );
        assert_eq!(
            follow(&record(APPLICATION_DATA, &[0; 10]), 3),
            Progress::NoCertificate
        );
    }
}
