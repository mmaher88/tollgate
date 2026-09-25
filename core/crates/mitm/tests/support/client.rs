//! A client that sends plain requests through the proxy.

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::{HeaderMap, Request, Response, StatusCode, Version};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::TcpStream;

pub type Sender1 = http1::SendRequest<Empty<Bytes>>;

/// A response read to the end.
#[derive(Debug)]
pub struct Reply {
    pub status: StatusCode,
    pub version: Version,
    pub headers: HeaderMap,
    pub body: String,
}

pub async fn read_reply(response: Response<Incoming>) -> Reply {
    let (parts, body) = response.into_parts();
    let body = body.collect().await.unwrap().to_bytes();
    Reply {
        status: parts.status,
        version: parts.version,
        headers: parts.headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    }
}

/// A GET request with extra headers.
pub fn get(uri: &str, headers: &[(&str, &str)]) -> Request<Empty<Bytes>> {
    let mut builder = Request::get(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Empty::new()).unwrap()
}

pub async fn http1<T>(io: T) -> Sender1
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = http1::handshake(TokioIo::new(io)).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    sender
}

pub async fn send1(sender: &mut Sender1, request: Request<Empty<Bytes>>) -> Reply {
    read_reply(sender.send_request(request).await.unwrap()).await
}

/// A plain request through the proxy in absolute form, on a new connection.
pub async fn proxy_get(proxy: SocketAddr, url: &str, headers: &[(&str, &str)]) -> Reply {
    let tcp = TcpStream::connect(proxy).await.unwrap();
    let mut sender = http1(tcp).await;
    let mut request = get(url, headers);
    let host = request.uri().authority().unwrap().to_string();
    request.headers_mut().insert("host", host.parse().unwrap());
    send1(&mut sender, request).await
}

/// Polls `condition` every 10 ms for up to 5 s.
pub async fn wait_for(what: &str, condition: impl Fn() -> bool) {
    for _ in 0..500 {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timed out waiting for {what}");
}

/// Reads until the peer closes; returns what was read, or `None` if it did not close
/// within `limit`.
pub async fn read_to_close<T: AsyncRead + Unpin>(io: &mut T, limit: Duration) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match tokio::time::timeout(limit, io.read_to_end(&mut out)).await {
        Ok(_) => Some(out),
        Err(_) => None,
    }
}
