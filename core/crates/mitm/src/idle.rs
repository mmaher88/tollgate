//! Closing client connections that have been idle for too long.
//!
//! A connection is busy from the moment a request arrives until its response body has been
//! sent or dropped. Once nothing is in flight for the idle timeout, the connection is shut
//! down gracefully, so idle browsers cannot hold interception slots forever. A request can
//! also ask for the connection to be shut down, for example once its host is passed
//! through, so the client's next request opens a new `CONNECT`.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

pub(crate) struct Activity {
    in_flight: AtomicUsize,
    last: Mutex<Instant>,
    close_requested: AtomicBool,
    close: Notify,
}

impl Activity {
    pub(crate) fn new() -> Arc<Activity> {
        Arc::new(Activity {
            in_flight: AtomicUsize::new(0),
            last: Mutex::new(Instant::now()),
            close_requested: AtomicBool::new(false),
            close: Notify::new(),
        })
    }

    /// Asks `serve` to shut the connection down gracefully: requests in flight finish,
    /// HTTP/1.1 closes after the current response and HTTP/2 sends GOAWAY.
    pub(crate) fn request_close(&self) {
        self.close_requested.store(true, Ordering::Release);
        // notify_one stores a permit when `serve` is not waiting yet.
        self.close.notify_one();
    }

    fn close_requested(&self) -> bool {
        self.close_requested.load(Ordering::Acquire)
    }

    /// Marks a request as in flight until the returned guard is dropped.
    pub(crate) fn start(self: &Arc<Self>) -> InFlight {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlight(self.clone())
    }

    /// When the connection becomes idle, or `None` while a request is in flight.
    fn idle_at(&self, idle: Duration) -> Option<Instant> {
        if self.in_flight.load(Ordering::Relaxed) > 0 {
            return None;
        }
        Some(*self.last.lock().unwrap_or_else(PoisonError::into_inner) + idle)
    }
}

pub(crate) struct InFlight(Arc<Activity>);

impl InFlight {
    /// [`Activity::request_close`] for this request's connection.
    pub(crate) fn request_close(&self) {
        self.0.request_close();
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        *self.0.last.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
        self.0.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Drives `conn` to completion, calling `shutdown` once it has been idle for `idle` or a
/// close was requested. Returns the connection's result and whether `shutdown` was called.
pub(crate) async fn serve<F, T>(
    conn: F,
    activity: &Activity,
    idle: Duration,
    shutdown: impl Fn(Pin<&mut F>),
) -> (T, bool)
where
    F: Future<Output = T>,
{
    let mut conn = std::pin::pin!(conn);
    let mut closing = false;
    loop {
        if !closing && activity.close_requested() {
            shutdown(conn.as_mut());
            closing = true;
        }
        let wake = activity
            .idle_at(idle)
            .unwrap_or_else(|| Instant::now() + idle);
        tokio::select! {
            result = conn.as_mut() => return (result, closing),
            () = activity.close.notified(), if !closing => {}
            () = tokio::time::sleep_until(wake), if !closing => {
                if activity.idle_at(idle).is_some_and(|at| at <= Instant::now()) {
                    shutdown(conn.as_mut());
                    closing = true;
                }
            }
        }
    }
}
