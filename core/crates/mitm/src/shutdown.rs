//! Stopping every task the proxy spawned when `serve` returns.

use std::future::Future;

use tokio::sync::watch;

/// Held by `serve`; closing it (or dropping it) ends every task spawned through
/// [`Shutdown::spawn`].
pub(crate) struct Closer(watch::Sender<bool>);

#[derive(Clone)]
pub(crate) struct Shutdown(watch::Receiver<bool>);

pub(crate) fn channel() -> (Closer, Shutdown) {
    let (tx, rx) = watch::channel(false);
    (Closer(tx), Shutdown(rx))
}

impl Closer {
    pub(crate) fn close(self) {
        let _ = self.0.send(true);
    }
}

impl Shutdown {
    /// Spawns `task`, which is dropped as soon as the proxy shuts down.
    pub(crate) fn spawn<F>(&self, task: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let closed = closed(self.0.clone());
        tokio::spawn(async move {
            tokio::select! {
                () = task => {}
                () = closed => {}
            }
        });
    }
}

async fn closed(mut rx: watch::Receiver<bool>) {
    while !*rx.borrow_and_update() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}
