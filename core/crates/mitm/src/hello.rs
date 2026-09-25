//! Reading a TLS ClientHello without consuming it.

use std::io;

use rustls::server::Acceptor;
use tokio::io::{AsyncRead, AsyncReadExt};

/// A ClientHello larger than this is treated as something other than TLS.
const MAX_CLIENT_HELLO: usize = 64 * 1024;

/// What the proxy needs from a ClientHello.
pub(crate) struct ClientHelloInfo {
    pub(crate) server_name: Option<String>,
}

pub(crate) enum HelloError {
    NotTls,
    Io(io::Error),
}

/// Appends whatever the peer sends next to `buffer`; 0 means end of stream.
pub(crate) async fn read_more<T>(io: &mut T, buffer: &mut Vec<u8>) -> io::Result<usize>
where
    T: AsyncRead + Unpin,
{
    buffer.reserve(4096);
    io.read_buf(buffer).await
}

/// Reads until `buffer` holds a complete ClientHello. Every byte read stays in `buffer`,
/// so the connection can still be replayed to a tunnel or a TLS acceptor.
pub(crate) async fn read_client_hello<T>(
    io: &mut T,
    buffer: &mut Vec<u8>,
) -> Result<ClientHelloInfo, HelloError>
where
    T: AsyncRead + Unpin,
{
    let mut acceptor = Acceptor::default();
    let mut fed = 0;
    loop {
        while fed < buffer.len() {
            let mut rest = &buffer[fed..];
            match acceptor.read_tls(&mut rest) {
                Ok(0) => break,
                Ok(n) => fed += n,
                Err(_) => return Err(HelloError::NotTls),
            }
        }
        match acceptor.accept() {
            Ok(Some(accepted)) => {
                let hello = accepted.client_hello();
                return Ok(ClientHelloInfo {
                    server_name: hello.server_name().map(str::to_string),
                });
            }
            Ok(None) => {}
            Err(_) => return Err(HelloError::NotTls),
        }
        if buffer.len() >= MAX_CLIENT_HELLO {
            return Err(HelloError::NotTls);
        }
        match read_more(io, buffer).await {
            Ok(0) => return Err(HelloError::Io(io::ErrorKind::UnexpectedEof.into())),
            Ok(_) => {}
            Err(e) => return Err(HelloError::Io(e)),
        }
    }
}
