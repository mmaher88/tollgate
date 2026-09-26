//! Copying bytes both ways between a client and an upstream connection until either side
//! closes, or until nothing has moved for the idle timeout, so half-dead tunnels do not keep
//! their sockets and their slot forever.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

/// How a tunnel ended.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Ended {
    Closed,
    Idle,
}

/// Copies until both directions are done, an error, or `idle` without a byte read on
/// either side.
pub(crate) async fn copy_until_idle<A, B>(a: &mut A, b: &mut B, idle: Duration) -> io::Result<Ended>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let start = Instant::now();
    // Milliseconds after `start` of the last read that returned bytes.
    let last = AtomicU64::new(0);
    let mut a = Tracked {
        inner: a,
        start,
        last: &last,
    };
    let mut b = Tracked {
        inner: b,
        start,
        last: &last,
    };
    let copy = tokio::io::copy_bidirectional(&mut a, &mut b);
    let mut copy = std::pin::pin!(copy);
    loop {
        let deadline = start + Duration::from_millis(last.load(Ordering::Relaxed)) + idle;
        tokio::select! {
            result = &mut copy => return result.map(|_| Ended::Closed),
            () = tokio::time::sleep_until(deadline) => {
                let since = Duration::from_millis(last.load(Ordering::Relaxed));
                if start.elapsed().saturating_sub(since) >= idle {
                    return Ok(Ended::Idle);
                }
            }
        }
    }
}

/// Records when a read last returned bytes.
struct Tracked<'a, T: ?Sized> {
    inner: &'a mut T,
    start: Instant,
    last: &'a AtomicU64,
}

impl<T: AsyncRead + Unpin + ?Sized> AsyncRead for Tracked<'_, T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let poll = Pin::new(&mut *this.inner).poll_read(cx, buf);
        if matches!(poll, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            let millis = u64::try_from(this.start.elapsed().as_millis()).unwrap_or(u64::MAX);
            this.last.store(millis, Ordering::Relaxed);
        }
        poll
    }
}

impl<T: AsyncWrite + Unpin + ?Sized> AsyncWrite for Tracked<'_, T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(cx)
    }
}
