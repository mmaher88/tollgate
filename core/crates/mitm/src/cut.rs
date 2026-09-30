//! An upstream socket that can be closed from outside while hyper owns it, for connections
//! whose network is gone.
//!
//! Dropping hyper's handles does not close an HTTP/2 connection that still has streams (h2
//! keeps it open until they end), and an HTTP/1.1 response in flight keeps its connection
//! too. Cutting the socket makes every read and write fail, so hyper fails the requests on
//! it and closes the connection.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::oneshot;

#[derive(Default)]
struct State {
    cut: AtomicBool,
    /// The tasks last blocked reading and writing, woken by [`Cutter::cut`].
    read: Mutex<Option<Waker>>,
    write: Mutex<Option<Waker>>,
}

impl State {
    /// Remembers `waker` in `slot`, then reports whether the socket was cut. Registering
    /// first means a cut between the check and the task going to sleep still wakes it.
    fn check(&self, slot: &Mutex<Option<Waker>>, waker: &Waker) -> io::Result<()> {
        {
            let mut slot = slot.lock().unwrap_or_else(PoisonError::into_inner);
            if !slot.as_ref().is_some_and(|w| w.will_wake(waker)) {
                *slot = Some(waker.clone());
            }
        }
        if self.cut.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "network path gone",
            ));
        }
        Ok(())
    }
}

/// `inner`, until [`Cutter::cut`] is called: from then on reads and writes fail with
/// `ConnectionAborted`.
pub(crate) struct Cuttable<T> {
    inner: T,
    state: Arc<State>,
    /// Dropped with the socket, which tells the [`Cutter`] it is no longer needed.
    _alive: oneshot::Sender<()>,
}

/// Cuts a [`Cuttable`].
pub(crate) struct Cutter {
    state: Arc<State>,
    alive: oneshot::Receiver<()>,
}

pub(crate) fn cuttable<T>(inner: T) -> (Cuttable<T>, Cutter) {
    let state = Arc::new(State::default());
    let (alive_tx, alive) = oneshot::channel();
    let io = Cuttable {
        inner,
        state: state.clone(),
        _alive: alive_tx,
    };
    (io, Cutter { state, alive })
}

impl Cutter {
    /// Resolves once the socket has been dropped.
    pub(crate) async fn dropped(&mut self) {
        let _ = (&mut self.alive).await;
    }

    /// Makes every further read and write fail, and wakes the tasks waiting on either.
    pub(crate) fn cut(&self) {
        self.state.cut.store(true, Ordering::Release);
        for slot in [&self.state.read, &self.state.write] {
            let waker = slot.lock().unwrap_or_else(PoisonError::into_inner).take();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Cuttable<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.state.check(&this.state.read, cx.waker())?;
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Cuttable<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        this.state.check(&this.state.write, cx.waker())?;
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        this.state.check(&this.state.write, cx.waker())?;
        Pin::new(&mut this.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.state.check(&this.state.write, cx.waker())?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state.cut.load(Ordering::Acquire) {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::cuttable;

    #[tokio::test]
    async fn a_cut_fails_a_waiting_read_and_later_writes() {
        let (a, mut b) = tokio::io::duplex(64);
        let (mut io, mut cutter) = cuttable(a);
        b.write_all(b"hi").await.unwrap();
        let mut buf = [0u8; 2];
        io.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hi");

        let reader = tokio::spawn(async move {
            let mut byte = [0u8; 1];
            let read = io.read(&mut byte).await;
            (read.map_err(|e| e.kind()), io)
        });
        tokio::task::yield_now().await;
        cutter.cut();
        let (read, mut io) = reader.await.unwrap();
        assert_eq!(read, Err(std::io::ErrorKind::ConnectionAborted));
        let write = io.write_all(b"x").await.map_err(|e| e.kind());
        assert_eq!(write, Err(std::io::ErrorKind::ConnectionAborted));

        drop(io);
        tokio::time::timeout(std::time::Duration::from_secs(1), cutter.dropped())
            .await
            .unwrap();
    }
}
