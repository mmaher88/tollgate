//! Closing client connections that have been idle for too long.
//!
//! A connection is busy from the moment a request arrives until its response body has been
//! sent or dropped. Once nothing is in flight for the idle timeout, the connection is shut
//! down gracefully, so idle browsers cannot hold interception slots forever. A request can
//! also ask for the connection to be shut down, for example once its host is passed
//! through, so the client's next request opens a new `CONNECT`, and so can a new
//! connection that needs the interception slot of one that has been idle for a while.
//!
//! A graceful HTTP/2 shutdown waits for the client to answer a ping. A client that never
//! answers, such as an app iOS has suspended in the background, would keep its connection
//! and slot until the keep-alive gives up, so a connection with nothing in flight is
//! dropped once its shutdown has taken [`RECLAIM_GRACE`] (for a reclaimed slot) or
//! [`CLOSE_GRACE`] (otherwise).

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::sync::Notify;
use tokio::time::Instant;

/// How long a reclaimed connection may take to shut down before it is dropped. Well below
/// the time a new connection waits for the slot; a live client answers within one local
/// round trip.
pub(crate) const RECLAIM_GRACE: Duration = Duration::from_millis(50);

/// How long any other shutdown may take, once nothing is in flight, before the connection
/// is dropped.
pub(crate) const CLOSE_GRACE: Duration = Duration::from_secs(5);

pub(crate) struct Activity {
    in_flight: AtomicUsize,
    last: Mutex<Instant>,
    close_requested: AtomicBool,
    reclaim: AtomicBool,
    close: Notify,
}

impl Activity {
    pub(crate) fn new() -> Arc<Activity> {
        Arc::new(Activity {
            in_flight: AtomicUsize::new(0),
            last: Mutex::new(Instant::now()),
            close_requested: AtomicBool::new(false),
            reclaim: AtomicBool::new(false),
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

    /// Like [`Activity::request_close`], for a connection whose slot a new connection is
    /// waiting for: once the shutdown has taken [`RECLAIM_GRACE`] with nothing in flight,
    /// the connection is dropped.
    pub(crate) fn request_reclaim(&self) {
        self.reclaim.store(true, Ordering::Release);
        self.request_close();
    }

    fn close_requested(&self) -> bool {
        self.close_requested.load(Ordering::Acquire)
    }

    fn grace(&self) -> Duration {
        if self.reclaim.load(Ordering::Acquire) {
            RECLAIM_GRACE
        } else {
            CLOSE_GRACE
        }
    }

    fn busy(&self) -> bool {
        self.in_flight.load(Ordering::Relaxed) > 0
    }

    /// Marks a request as in flight until the returned guard is dropped.
    pub(crate) fn start(self: &Arc<Self>) -> InFlight {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        InFlight(self.clone())
    }

    /// Since when nothing has been in flight; `None` while a request is in flight or once a
    /// close was requested.
    pub(crate) fn idle_since(&self) -> Option<Instant> {
        if self.in_flight.load(Ordering::Relaxed) > 0 || self.close_requested() {
            return None;
        }
        Some(*self.last.lock().unwrap_or_else(PoisonError::into_inner))
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
/// close was requested. Returns the connection's result, or `None` when it was dropped
/// because its shutdown took too long (see [`RECLAIM_GRACE`] and [`CLOSE_GRACE`]), and
/// whether `shutdown` was called.
pub(crate) async fn serve<F, T>(
    conn: F,
    activity: &Activity,
    idle: Duration,
    shutdown: impl Fn(Pin<&mut F>),
) -> (Option<T>, bool)
where
    F: Future<Output = T>,
{
    let mut conn = std::pin::pin!(conn);
    let mut closing = false;
    // Once closing: when the connection is dropped if it has still not closed.
    let mut drop_at = Instant::now();
    loop {
        if !closing && activity.close_requested() {
            shutdown(conn.as_mut());
            closing = true;
            drop_at = Instant::now() + activity.grace();
        }
        let wake = if closing {
            drop_at
        } else {
            activity
                .idle_at(idle)
                .unwrap_or_else(|| Instant::now() + idle)
        };
        tokio::select! {
            result = conn.as_mut() => return (Some(result), closing),
            () = activity.close.notified() => {
                // A reclaim can arrive after an idle shutdown started.
                if closing {
                    drop_at = drop_at.min(Instant::now() + activity.grace());
                }
            }
            () = tokio::time::sleep_until(wake) => {
                if !closing {
                    if activity.idle_at(idle).is_some_and(|at| at <= Instant::now()) {
                        shutdown(conn.as_mut());
                        closing = true;
                        drop_at = Instant::now() + activity.grace();
                    }
                } else if activity.busy() {
                    drop_at = Instant::now() + activity.grace();
                } else {
                    return (None, true);
                }
            }
        }
    }
}
