//! The engine the tunnel runs: DNS answers on the packet path, and the proxy plus the DNS
//! forwarder on one runtime thread.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tollgate_common::clock;
use tollgate_common::stats::{Stats as Counters, StatsSnapshot};
use tollgate_dns::{DnsHandler, DohError, DohResolver, ForwardJob, Outcome};
use tollgate_filter::{DOMAINS_FILE, DomainSet, ENGINE_FILE, FilterEngine, FilterError};
use tollgate_mitm::{CertAuthority, ProxyContext};
use tollgate_policy::{Config, Policy};

use crate::ca::{load_ca, write_private};
use crate::error::{TollgateError, catch_panic, panic_message};

/// Name of the thread that runs the proxy and the DNS forwarder.
pub const RUNTIME_THREAD: &str = "tollgate-core";
/// Learned certificate pins, read by `Engine::new`, written while the engine runs when they
/// change and again by `Engine::stop`.
pub const LEARNED_PINS_FILE: &str = "learned-pins.json";
/// Default for [`EngineOptions::pins_save_interval`].
pub const PINS_SAVE_INTERVAL: Duration = Duration::from_secs(30);
/// Forwarded queries waiting for the runtime; when full, new ones get SERVFAIL at once.
pub const FORWARD_QUEUE: usize = 256;
/// Threads tokio may start for blocking work (the proxy's `getaddrinfo` calls).
const MAX_BLOCKING_THREADS: usize = 4;
/// How long `stop` waits for blocking work such as a hung `getaddrinfo`.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// Implemented in Swift over `NEPacketTunnelFlow.writePackets`. Called on the runtime
/// thread with the answers to forwarded DNS queries, so it must only hand the packets off.
#[uniffi::export(foreign)]
pub trait PacketSink: Send + Sync {
    fn write_packets(&self, packets: Vec<Vec<u8>>);
}

/// Counters since the engine was created. Mirrors `tollgate_common::stats::StatsSnapshot`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, uniffi::Record)]
pub struct Stats {
    pub dns_queries: u64,
    pub dns_blocked: u64,
    pub dns_cache_hits: u64,
    pub dns_forwarded: u64,
    pub dns_failed: u64,
    pub packets_dropped: u64,
    pub http_requests: u64,
    pub http_blocked: u64,
    pub connections_intercepted: u64,
    pub connections_passthrough: u64,
    pub tls_client_rejections: u64,
    pub tls_abandoned_after_handshake: u64,
}

impl From<StatsSnapshot> for Stats {
    fn from(s: StatsSnapshot) -> Stats {
        Stats {
            dns_queries: s.dns_queries,
            dns_blocked: s.dns_blocked,
            dns_cache_hits: s.dns_cache_hits,
            dns_forwarded: s.dns_forwarded,
            dns_failed: s.dns_failed,
            packets_dropped: s.packets_dropped,
            http_requests: s.http_requests,
            http_blocked: s.http_blocked,
            connections_intercepted: s.connections_intercepted,
            connections_passthrough: s.connections_passthrough,
            tls_client_rejections: s.tls_client_rejections,
            tls_abandoned_after_handshake: s.tls_abandoned_after_handshake,
        }
    }
}

/// Settings Swift never changes; tests use them to reach a local DoH server and to make
/// the forward queue small.
#[derive(Clone, Debug)]
pub struct EngineOptions {
    /// DER certificates trusted for DoH upstreams in addition to the webpki roots.
    pub doh_roots: Vec<Vec<u8>>,
    /// Capacity of the queue between `handle_packets` and the runtime.
    pub forward_queue: usize,
    /// DoH queries resolving at once; further jobs wait in the queue.
    pub forward_in_flight: usize,
    /// How often the running engine checks whether the learned pins changed and saves
    /// them. `stop` saves them too, but jetsam or a crash ends the extension without it.
    pub pins_save_interval: Duration,
}

impl Default for EngineOptions {
    fn default() -> EngineOptions {
        EngineOptions {
            doh_roots: Vec::new(),
            forward_queue: FORWARD_QUEUE,
            forward_in_flight: tollgate_dns::MAX_IN_FLIGHT,
            pins_save_interval: PINS_SAVE_INTERVAL,
        }
    }
}

struct Running {
    port: u16,
    jobs: mpsc::Sender<ForwardJob>,
    shutdown: oneshot::Sender<()>,
    thread: JoinHandle<()>,
}

/// What the runtime thread needs.
struct Work {
    proxy: Arc<ProxyContext>,
    dns: Arc<DnsHandler>,
    resolver: DohResolver,
    sink: Arc<dyn PacketSink>,
    queue: mpsc::Receiver<ForwardJob>,
    in_flight: usize,
    pins_file: PathBuf,
    pins_save_interval: Duration,
    /// The learned pins when `start` ran; the file holds these or equivalent ones.
    pins_at_start: String,
}

/// The tunnel's Rust side: DNS answers, the DNS forwarder and the HTTPS proxy.
#[derive(uniffi::Object)]
pub struct Engine {
    data_dir: PathBuf,
    config: Config,
    options: EngineOptions,
    mitm_active: bool,
    stats: Arc<Counters>,
    dns: Arc<DnsHandler>,
    proxy: Arc<ProxyContext>,
    running: Mutex<Option<Running>>,
}

#[uniffi::export]
impl Engine {
    /// Parses `config_json` and loads what `data_dir` holds: `engine.dat`, `domains.bin`,
    /// `ca.pem` with `ca.key`, and `learned-pins.json`. Each file is optional; a file that
    /// cannot be loaded is logged and skipped. HTTPS interception needs both the CA and
    /// `engine.dat`; without them every connection is passed through.
    #[uniffi::constructor]
    pub fn new(config_json: String, data_dir: String) -> Result<Arc<Engine>, TollgateError> {
        catch_panic(|| {
            Engine::with_options(&config_json, Path::new(&data_dir), EngineOptions::default())
        })
    }

    /// Starts the runtime thread with the proxy on `127.0.0.1` and returns the proxy's port
    /// once it is listening. Answers to forwarded DNS queries go to `sink`.
    pub fn start(&self, sink: Arc<dyn PacketSink>) -> Result<u16, TollgateError> {
        catch_panic(|| self.start_runtime(sink))
    }

    /// Stops the proxy and the forwarder, joins the runtime thread and saves the learned
    /// pins. Does nothing when not running. Queries still queued are dropped.
    pub fn stop(&self) {
        let _ = catch_panic(|| {
            self.stop_runtime();
            Ok(())
        });
    }

    /// Handles raw IP packets from the tunnel without waiting on the network. Returns the
    /// replies it can give at once (blocked names, HTTPS and SVCB queries, cache hits,
    /// errors, and SERVFAIL when stopped or when the queue is full); the answers to
    /// forwarded queries arrive later through the `PacketSink`.
    pub fn handle_packets(&self, packets: Vec<Vec<u8>>) -> Result<Vec<Vec<u8>>, TollgateError> {
        catch_panic(|| Ok(self.answer(&packets)))
    }

    /// Loads `engine.dat` and `domains.bin` again and swaps both in. A missing file clears
    /// that list; a file that fails to load is an error and nothing is swapped.
    pub fn reload_lists(&self) -> Result<(), TollgateError> {
        catch_panic(|| {
            let filter = load_filter(&self.data_dir)?;
            let domains = load_domains(&self.data_dir)?;
            log::info!(
                "reloaded lists: engine {}, DNS blocklist {} hashes",
                if filter.is_some() {
                    "loaded"
                } else {
                    "missing"
                },
                domains.as_ref().map_or(0, |set| set.len())
            );
            self.proxy.filter.store(filter);
            self.dns.set_blocklist(domains);
            Ok(())
        })
    }

    pub fn stats(&self) -> Stats {
        catch_panic(|| Ok(self.stats.snapshot().into())).unwrap_or_default()
    }

    /// The learned pins as JSON, the format of `learned-pins.json`.
    pub fn learned_pins_json(&self) -> String {
        catch_panic(|| Ok(self.proxy.policy.learned_pins_json())).unwrap_or_default()
    }

    /// Whether HTTPS connections can be intercepted: `mitm_enabled` in the config, a CA and
    /// `engine.dat` were all present when the engine was created.
    pub fn mitm_active(&self) -> bool {
        self.mitm_active
    }

    /// The proxy port while running.
    pub fn port(&self) -> Option<u16> {
        catch_panic(|| Ok(self.running().as_ref().map(|r| r.port))).unwrap_or_default()
    }
}

impl Engine {
    /// [`Engine::new`] with explicit options, for tests and tools.
    pub fn with_options(
        config_json: &str,
        data_dir: &Path,
        options: EngineOptions,
    ) -> Result<Arc<Engine>, TollgateError> {
        let config = Config::from_json(config_json).map_err(|e| TollgateError::Config {
            message: e.to_string(),
        })?;
        let filter = load_filter(data_dir).unwrap_or_else(|e| {
            log::warn!("running without the URL filter: {e}");
            None
        });
        let domains = load_domains(data_dir).unwrap_or_else(|e| {
            log::warn!("running without the DNS blocklist: {e}");
            None
        });
        let ca = load_ca(data_dir).unwrap_or_else(|e| {
            log::warn!("running without the CA: {e}");
            None
        });
        let mitm_active = config.mitm_enabled && ca.is_some() && filter.is_some();
        if config.mitm_enabled && !mitm_active {
            log::warn!(
                "HTTPS interception is off: {}",
                if ca.is_none() {
                    "no CA"
                } else {
                    "no engine.dat"
                }
            );
        }
        let policy_config = Config {
            mitm_enabled: mitm_active,
            ..config.clone()
        };
        let pins = read_pins(data_dir);
        let policy =
            Policy::new(&policy_config, pins.as_deref()).map_err(|e| TollgateError::Config {
                message: e.to_string(),
            })?;
        // The proxy needs a CA even when it only passes connections through; this one is
        // never used to issue a leaf because the policy intercepts nothing.
        let ca = match ca {
            Some(ca) => ca,
            None => CertAuthority::generate("Tollgate unused").map_err(|e| TollgateError::Ca {
                message: e.to_string(),
            })?,
        };
        let stats = Arc::new(Counters::default());
        let proxy = Arc::new(ProxyContext {
            policy: Arc::new(policy),
            filter: ArcSwapOption::new(filter),
            ca: Arc::new(ca),
            stats: stats.clone(),
            max_intercepted: config.max_intercepted_connections as usize,
            available_memory,
        });
        let dns = Arc::new(DnsHandler::new(domains, stats.clone()));
        Ok(Arc::new(Engine {
            data_dir: data_dir.to_path_buf(),
            config,
            options,
            mitm_active,
            stats,
            dns,
            proxy,
            running: Mutex::new(None),
        }))
    }

    fn running(&self) -> MutexGuard<'_, Option<Running>> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn answer(&self, packets: &[Vec<u8>]) -> Vec<Vec<u8>> {
        // Clone the sender and release the lock at once, so stop() never waits on us.
        let jobs = self.running().as_ref().map(|r| r.jobs.clone());
        let now = clock::now_secs();
        let mut replies = Vec::new();
        for packet in packets {
            match self.dns.handle_packet(packet, now) {
                Outcome::Reply(reply) => replies.push(reply),
                Outcome::Drop => {}
                Outcome::Forward(job) => {
                    let failed = match &jobs {
                        None => Some((job, DohError::Stopped)),
                        Some(jobs) => match jobs.try_send(job) {
                            Ok(()) => None,
                            Err(TrySendError::Full(job)) => Some((job, DohError::Busy)),
                            Err(TrySendError::Closed(job)) => Some((job, DohError::Stopped)),
                        },
                    };
                    if let Some((job, error)) = failed {
                        replies.push(self.dns.complete(job, Err(error), now));
                    }
                }
            }
        }
        replies
    }

    fn resolver(&self) -> Result<DohResolver, TollgateError> {
        let upstreams = self.config.doh_upstreams.clone();
        if self.options.doh_roots.is_empty() {
            return Ok(DohResolver::new(upstreams));
        }
        let roots: Vec<CertificateDer<'static>> = self
            .options
            .doh_roots
            .iter()
            .map(|der| CertificateDer::from(der.clone()))
            .collect();
        DohResolver::with_extra_roots(upstreams, &roots).map_err(|e| TollgateError::Config {
            message: e.to_string(),
        })
    }

    fn start_runtime(&self, sink: Arc<dyn PacketSink>) -> Result<u16, TollgateError> {
        let mut running = self.running();
        if running.is_some() {
            return Err(TollgateError::AlreadyRunning);
        }
        let (jobs, queue) = mpsc::channel(self.options.forward_queue.max(1));
        let work = Work {
            proxy: self.proxy.clone(),
            dns: self.dns.clone(),
            resolver: self.resolver()?,
            sink,
            queue,
            in_flight: self.options.forward_in_flight.max(1),
            pins_file: self.data_dir.join(LEARNED_PINS_FILE),
            pins_save_interval: self.options.pins_save_interval,
            pins_at_start: self.proxy.policy.learned_pins_json(),
        };
        let (shutdown, stopped) = oneshot::channel();
        let (ready_tx, ready) = std::sync::mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name(RUNTIME_THREAD.to_string())
            .spawn(move || run(work, stopped, ready_tx))
            .map_err(TollgateError::io)?;
        match ready.recv() {
            Ok(Ok(port)) => {
                log::info!("proxy listening on 127.0.0.1:{port}");
                *running = Some(Running {
                    port,
                    jobs,
                    shutdown,
                    thread,
                });
                Ok(port)
            }
            Ok(Err(e)) => {
                let _ = thread.join();
                Err(e)
            }
            Err(_) => {
                let _ = thread.join();
                Err(TollgateError::Internal {
                    message: "the runtime thread ended while starting".to_string(),
                })
            }
        }
    }

    fn stop_runtime(&self) {
        let Some(running) = self.running().take() else {
            return;
        };
        let Running {
            port,
            jobs,
            shutdown,
            thread,
        } = running;
        let _ = shutdown.send(());
        drop(jobs);
        if thread.thread().id() == thread::current().id() {
            // Called from a callback on the runtime thread (for example the last Engine
            // reference dropped inside PacketSink.write_packets). Joining would deadlock;
            // the thread ends by itself once the callback returns.
            log::warn!("stop() ran on the runtime thread; not joining it");
        } else if thread.join().is_err() {
            log::error!("the runtime thread panicked");
        }
        self.save_pins();
        log::info!("engine stopped, proxy port {port} closed");
    }

    fn save_pins(&self) {
        let path = self.data_dir.join(LEARNED_PINS_FILE);
        save_pins(&path, &self.proxy.policy.learned_pins_json());
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop();
    }
}

fn load_filter(dir: &Path) -> Result<Option<Arc<FilterEngine>>, TollgateError> {
    match FilterEngine::load(&dir.join(ENGINE_FILE)) {
        Ok(engine) => Ok(Some(Arc::new(engine))),
        Err(FilterError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TollgateError::Lists {
            message: e.to_string(),
        }),
    }
}

fn load_domains(dir: &Path) -> Result<Option<Arc<DomainSet>>, TollgateError> {
    match DomainSet::load(&dir.join(DOMAINS_FILE)) {
        Ok(set) => Ok(Some(Arc::new(set))),
        Err(FilterError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(TollgateError::Lists {
            message: e.to_string(),
        }),
    }
}

fn save_pins(path: &Path, json: &str) -> bool {
    match write_private(path, json) {
        Ok(()) => true,
        Err(e) => {
            log::warn!("could not save learned pins: {e}");
            false
        }
    }
}

fn read_pins(dir: &Path) -> Option<String> {
    let path = dir.join(LEARNED_PINS_FILE);
    match std::fs::read_to_string(&path) {
        Ok(json) => Some(json),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => {
            log::warn!("ignoring {}: {e}", path.display());
            None
        }
    }
}

/// Bytes the extension may still allocate before jetsam ends it. `None` outside iOS, and
/// when iOS reports 0, which it does for processes without a limit.
#[cfg(target_os = "ios")]
fn available_memory() -> Option<u64> {
    unsafe extern "C" {
        fn os_proc_available_memory() -> usize;
    }
    // SAFETY: os_proc_available_memory takes no arguments and has no preconditions; it is
    // part of libSystem since iOS 13.
    let bytes = unsafe { os_proc_available_memory() };
    (bytes > 0).then_some(bytes as u64)
}

#[cfg(not(target_os = "ios"))]
fn available_memory() -> Option<u64> {
    None
}

/// Body of the runtime thread. Reports the port (or why there is none) through `ready`.
fn run(work: Work, stopped: oneshot::Receiver<()>, ready: SyncSender<Result<u16, TollgateError>>) {
    let outcome = catch_unwind(AssertUnwindSafe(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(MAX_BLOCKING_THREADS)
            .thread_name("tollgate-blocking")
            .build()
        {
            Ok(runtime) => runtime,
            Err(e) => {
                let _ = ready.send(Err(TollgateError::io(e)));
                return;
            }
        };
        runtime.block_on(serve(work, stopped, ready));
        runtime.shutdown_timeout(SHUTDOWN_TIMEOUT);
    }));
    if let Err(payload) = outcome {
        log::error!(
            "the runtime thread panicked: {}",
            panic_message(payload.as_ref())
        );
    }
}

async fn serve(
    work: Work,
    stopped: oneshot::Receiver<()>,
    ready: SyncSender<Result<u16, TollgateError>>,
) {
    // A SocketAddr, not a host name, so binding never resolves anything.
    let listener = match TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await {
        Ok(listener) => listener,
        Err(e) => {
            let _ = ready.send(Err(TollgateError::io(e)));
            return;
        }
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(e) => {
            let _ = ready.send(Err(TollgateError::io(e)));
            return;
        }
    };
    let _ = ready.send(Ok(port));
    let Work {
        proxy,
        dns,
        resolver,
        sink,
        queue,
        in_flight,
        pins_file,
        pins_save_interval,
        pins_at_start,
    } = work;
    let forwarding = tokio::spawn(forward(queue, resolver, dns, sink, in_flight));
    let saving = tokio::spawn(save_pins_periodically(
        proxy.policy.clone(),
        pins_file,
        pins_save_interval,
        pins_at_start,
    ));
    tollgate_mitm::serve(listener, proxy, async move {
        let _ = stopped.await;
    })
    .await;
    forwarding.abort();
    // The write runs on this thread, so it has finished before `stop` joins the thread and
    // saves the pins itself.
    saving.abort();
}

/// Saves the learned pins every `interval` if they differ from `saved`, the last pins
/// written, so pins survive an extension that ends without `stop` (jetsam, a crash).
async fn save_pins_periodically(
    policy: Arc<Policy>,
    path: PathBuf,
    interval: Duration,
    mut saved: String,
) {
    let mut ticks = tokio::time::interval(interval.max(Duration::from_millis(1)));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick completes at once.
    ticks.tick().await;
    loop {
        ticks.tick().await;
        let json = policy.learned_pins_json();
        if json != saved && save_pins(&path, &json) {
            log::debug!("saved learned pins");
            saved = json;
        }
    }
}

/// Resolves queued queries, at most `in_flight` at once, one task each.
async fn forward(
    mut queue: mpsc::Receiver<ForwardJob>,
    resolver: DohResolver,
    dns: Arc<DnsHandler>,
    sink: Arc<dyn PacketSink>,
    in_flight: usize,
) {
    let permits = Arc::new(Semaphore::new(in_flight));
    loop {
        // Take the permit first, so a job waits in the queue, where it counts against the
        // queue's capacity, not in this loop.
        let Ok(permit) = permits.clone().acquire_owned().await else {
            return;
        };
        let Some(job) = queue.recv().await else {
            return;
        };
        let (resolver, dns, sink) = (resolver.clone(), dns.clone(), sink.clone());
        tokio::spawn(async move {
            let answer = resolver.resolve(job.query()).await;
            let packet = dns.complete(job, answer, clock::now_secs());
            drop(permit);
            deliver(sink.as_ref(), vec![packet]);
        });
    }
}

fn deliver(sink: &dyn PacketSink, packets: Vec<Vec<u8>>) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| sink.write_packets(packets))) {
        log::error!(
            "PacketSink.write_packets panicked: {}",
            panic_message(payload.as_ref())
        );
    }
}

#[cfg(test)]
mod tests {
    use tollgate_policy::RejectionKind;

    use super::*;

    struct NullSink;

    impl PacketSink for NullSink {
        fn write_packets(&self, _packets: Vec<Vec<u8>>) {}
    }

    #[test]
    fn learned_pins_are_saved_while_running() {
        let dir = tempfile::tempdir().unwrap();
        let options = EngineOptions {
            pins_save_interval: Duration::from_millis(50),
            ..EngineOptions::default()
        };
        let engine = Engine::with_options("{}", dir.path(), options).unwrap();
        engine.start(Arc::new(NullSink)).unwrap();
        let now = tollgate_common::clock::unix_secs();
        let policy = &engine.proxy.policy;
        assert!(!policy.record_client_rejection("pinned.example", RejectionKind::UnknownCa, now));
        assert!(policy.record_client_rejection("pinned.example", RejectionKind::UnknownCa, now));

        let path = dir.path().join(LEARNED_PINS_FILE);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !std::fs::read_to_string(&path).is_ok_and(|json| json.contains("pinned.example")) {
            assert!(
                std::time::Instant::now() < deadline,
                "the pins were not saved"
            );
            thread::sleep(Duration::from_millis(10));
        }
        assert!(engine.port().is_some(), "saved while the engine runs");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            engine.learned_pins_json()
        );
        engine.stop();
    }

    #[test]
    fn a_poisoned_running_lock_is_recovered() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap().to_string();
        let engine = Engine::new("{}".to_string(), path).unwrap();
        let poisoner = engine.clone();
        let _ = thread::spawn(move || {
            let _guard = poisoner.running.lock().unwrap();
            panic!("poisoning the lock on purpose");
        })
        .join();
        assert!(engine.running.is_poisoned());

        assert_eq!(
            engine.handle_packets(Vec::new()).unwrap(),
            Vec::<Vec<u8>>::new()
        );
        let port = engine.start(Arc::new(NullSink)).unwrap();
        assert_eq!(engine.port(), Some(port));
        engine.stop();
        assert_eq!(engine.port(), None);
    }
}
