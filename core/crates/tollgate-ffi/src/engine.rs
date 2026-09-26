//! The engine the tunnel runs: DNS answers on the packet path, and the proxy plus the DNS
//! forwarder on one runtime thread.

use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, TryLockError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use arc_swap::ArcSwapOption;
use rustls::pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{Semaphore, mpsc, oneshot};
use tollgate_common::clock;
use tollgate_common::events::EventLog;
use tollgate_common::stats::{Stats as Counters, StatsSnapshot};
use tollgate_dns::{
    DnsHandler, DohError, DohResolver, ForwardJob, HostResolver, LocalRecord, Outcome,
};
use tollgate_filter::{DOMAINS_FILE, DomainSet, ENGINE_FILE, FilterEngine, FilterError};
use tollgate_mitm::{CertAuthority, ProxyContext, ServeOptions};
use tollgate_policy::{Config, HostPattern, Policy};

use crate::ca::{load_ca, write_private};
use crate::controls::{BlockEvent, LearnedPin, count, learned_pins};
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
/// Threads tokio may start for blocking work (the proxy's `getaddrinfo` calls, and writing
/// the learned pins).
const MAX_BLOCKING_THREADS: usize = 4;
/// How long `stop` waits for blocking work such as a hung `getaddrinfo`.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);

/// Most local network lookups waiting for [`Engine::complete_local`]; queries for further
/// questions get SERVFAIL at once.
pub const LOCAL_PENDING: usize = 64;
/// Most queries waiting on one local lookup (clients repeat a query that takes long);
/// further ones get SERVFAIL at once.
const LOCAL_JOBS_PER_LOOKUP: usize = 16;
/// Default for [`EngineOptions::local_deadline`].
pub const LOCAL_DEADLINE: Duration = Duration::from_secs(5);

/// Implemented in Swift over `NEPacketTunnelFlow.writePackets`. Called on the runtime
/// thread with the answers to forwarded DNS queries, so it must only hand the packets off.
#[uniffi::export(foreign)]
pub trait PacketSink: Send + Sync {
    fn write_packets(&self, packets: Vec<Vec<u8>>);
}

/// Implemented in Swift: looks up names only the local network knows (`nas.lan`, private
/// reverse zones, bare device names) with the resolver of the current physical interface,
/// never with the tunnel's. Called from `handle_packets`, so it must only start the lookup.
/// Each call must be followed by exactly one [`Engine::complete_local`] with the same `id`;
/// a query not completed within [`EngineOptions::local_deadline`] gets SERVFAIL.
#[uniffi::export(foreign)]
pub trait LocalResolver: Send + Sync {
    /// `name` is in presentation form with the final dot; `rtype` and `rclass` are the
    /// numeric record type and class of the question.
    fn resolve(&self, id: u64, name: String, rtype: u16, rclass: u16);
}

/// One record from the local network's resolver: type, class, TTL and the record data in
/// wire form, with any names in it uncompressed (as `DNSServiceQueryRecord` returns it).
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct DnsRecord {
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub data: Vec<u8>,
}

impl From<DnsRecord> for LocalRecord {
    fn from(r: DnsRecord) -> LocalRecord {
        LocalRecord {
            rtype: r.rtype,
            rclass: r.rclass,
            ttl: r.ttl,
            data: r.data,
        }
    }
}

/// A question's name in lowercase, its type and its class.
type LocalQuestion = (String, u16, u16);

/// One lookup handed to the [`LocalResolver`] and the queries waiting for it.
struct LocalLookup {
    question: LocalQuestion,
    jobs: Vec<ForwardJob>,
    since: Instant,
}

/// Local network lookups handed to the [`LocalResolver`], by id. A query for a question
/// already being looked up waits for that lookup. Besides saving work, this ends a lookup
/// that comes back through the tunnel (on a network whose resolver the system cannot scope
/// to the interface), which would otherwise start a new lookup for itself again and again.
#[derive(Default)]
struct LocalJobs {
    next_id: u64,
    waiting: HashMap<u64, LocalLookup>,
    by_question: HashMap<LocalQuestion, u64>,
}

impl LocalJobs {
    fn remove(&mut self, id: u64) -> Option<LocalLookup> {
        let lookup = self.waiting.remove(&id)?;
        self.by_question.remove(&lookup.question);
        Some(lookup)
    }
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
    /// How long a local network query waits for [`Engine::complete_local`] before it is
    /// answered SERVFAIL (checked when the next local query arrives).
    pub local_deadline: Duration,
}

impl Default for EngineOptions {
    fn default() -> EngineOptions {
        EngineOptions {
            doh_roots: Vec::new(),
            forward_queue: FORWARD_QUEUE,
            forward_in_flight: tollgate_dns::MAX_IN_FLIGHT,
            pins_save_interval: PINS_SAVE_INTERVAL,
            local_deadline: LOCAL_DEADLINE,
        }
    }
}

struct Running {
    port: u16,
    jobs: mpsc::Sender<ForwardJob>,
    /// Shares its connections with the runtime's resolver, for `reset_connections`.
    resolver: DohResolver,
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
    pins: Arc<PinsFile>,
    pins_save_interval: Duration,
}

/// The tunnel's Rust side: DNS answers, the DNS forwarder and the HTTPS proxy.
#[derive(uniffi::Object)]
pub struct Engine {
    data_dir: PathBuf,
    config: Config,
    options: EngineOptions,
    mitm_active: bool,
    stats: Arc<Counters>,
    /// The blocked log, shared by the DNS handler and the proxy.
    events: Arc<EventLog>,
    dns: Arc<DnsHandler>,
    proxy: Arc<ProxyContext>,
    pins: Arc<PinsFile>,
    running: Mutex<Option<Running>>,
    local_resolver: Mutex<Option<Arc<dyn LocalResolver>>>,
    local_jobs: Mutex<LocalJobs>,
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
            // One set for both: the proxy checks the hosts proxied clients never look up.
            self.proxy.domains.store(domains.clone());
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

    /// Up to `limit` of the last 500 blocks, newest first.
    pub fn recent_events(&self, limit: u32) -> Vec<BlockEvent> {
        catch_panic(|| {
            let limit = usize::try_from(limit).unwrap_or(usize::MAX);
            Ok(self
                .events
                .recent(limit)
                .into_iter()
                .map(BlockEvent::from)
                .collect())
        })
        .unwrap_or_default()
    }

    /// Empties the blocked log. The counters are kept.
    pub fn clear_events(&self) {
        let _ = catch_panic(|| {
            self.events.clear();
            Ok(())
        });
    }

    /// The learned pins, sorted by host.
    pub fn learned_pins(&self) -> Vec<LearnedPin> {
        catch_panic(|| Ok(learned_pins(&self.proxy.policy))).unwrap_or_default()
    }

    /// Forgets the learned pins (and pending rejections) for these hosts, then saves
    /// `learned-pins.json` at once. Returns how many pins were removed.
    pub fn forget_pins(&self, hosts: Vec<String>) -> u32 {
        catch_panic(|| {
            let removed = self.proxy.policy.forget_pins(&hosts);
            self.pins.save(true);
            Ok(count(removed))
        })
        .unwrap_or_default()
    }

    /// Drops the proxy's pooled upstream connections and the DoH connections (used by
    /// the DNS forwarder and the proxy's name lookups), so the next requests and queries
    /// connect again. Call it when the device wakes and when the network path changes:
    /// connections from before usually still look open while their path is gone.
    pub fn reset_connections(&self) {
        let _ = catch_panic(|| {
            self.proxy.reset_upstream_connections();
            // Clone and release the lock at once, so stop() never waits on us.
            let resolver = self.running().as_ref().map(|r| r.resolver.clone());
            if let Some(resolver) = resolver {
                log::info!("dropping DoH connections");
                resolver.reset_connections();
            }
            Ok(())
        });
    }

    /// Where local network names are looked up; `None` answers them SERVFAIL. They are
    /// never sent to the DoH upstreams, which only know that they do not exist.
    pub fn set_local_resolver(&self, resolver: Option<Arc<dyn LocalResolver>>) {
        let _ = catch_panic(|| {
            *lock(&self.local_resolver) = resolver;
            Ok(())
        });
    }

    /// Names the network the local resolver answers for, such as the interface name and
    /// its gateways. A different name drops the local answers kept so far.
    pub fn set_network(&self, network: String) {
        let _ = catch_panic(|| {
            self.dns.set_network(&network);
            Ok(())
        });
    }

    /// Answers the local network query `id` from a [`LocalResolver::resolve`] call:
    /// `records` holds the records found (empty when the name or type does not exist
    /// there), `None` means the lookup failed or timed out. Returns the reply packet to
    /// write to the tunnel, or nothing when `id` was already answered or has expired.
    pub fn complete_local(&self, id: u64, records: Option<Vec<DnsRecord>>) -> Vec<Vec<u8>> {
        catch_panic(|| {
            let Some(lookup) = lock(&self.local_jobs).remove(id) else {
                return Ok(Vec::new());
            };
            let records: Option<Vec<LocalRecord>> =
                records.map(|records| records.into_iter().map(LocalRecord::from).collect());
            let now = clock::now_secs();
            Ok(lookup
                .jobs
                .into_iter()
                .map(|job| self.dns.complete_local(job, records.as_deref(), now))
                .collect())
        })
        .unwrap_or_default()
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
        let allowlist = config
            .allowlist
            .iter()
            .map(|p| HostPattern::parse(p))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| TollgateError::Config {
                message: e.to_string(),
            })?;
        let stats = Arc::new(Counters::default());
        let events = Arc::new(EventLog::new());
        let proxy = Arc::new(ProxyContext {
            policy: Arc::new(policy),
            filter: ArcSwapOption::new(filter),
            domains: ArcSwapOption::new(domains.clone()),
            ca: Arc::new(ca),
            stats: stats.clone(),
            max_intercepted: config.max_intercepted_connections as usize,
            available_memory,
            events: Some(events.clone()),
            upstream_resets: Default::default(),
        });
        let dns = Arc::new(DnsHandler::new(domains, stats.clone()));
        dns.set_allowlist(allowlist);
        dns.set_events(Some(events.clone()));
        let pins = Arc::new(PinsFile::new(
            data_dir.join(LEARNED_PINS_FILE),
            proxy.policy.clone(),
        ));
        Ok(Arc::new(Engine {
            data_dir: data_dir.to_path_buf(),
            config,
            options,
            mitm_active,
            stats,
            events,
            dns,
            proxy,
            pins,
            running: Mutex::new(None),
            local_resolver: Mutex::new(None),
            local_jobs: Mutex::new(LocalJobs::default()),
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
        let mut local = Vec::new();
        for packet in packets {
            match self.dns.handle_packet(packet, now) {
                Outcome::Reply(reply) => replies.push(reply),
                Outcome::Drop => {}
                Outcome::Local(job) => local.push(job),
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
        if !local.is_empty() {
            replies.extend(self.resolve_locally(local, now));
        }
        replies
    }

    /// Hands local network queries to the [`LocalResolver`], one lookup per question.
    /// Returns SERVFAIL replies for queries that cannot wait (no resolver, [`LOCAL_PENDING`]
    /// lookups already waiting) and for waiting ones past their deadline.
    fn resolve_locally(&self, jobs: Vec<ForwardJob>, now: u64) -> Vec<Vec<u8>> {
        let resolver = lock(&self.local_resolver).clone();
        let mut failed = Vec::new();
        let mut calls = Vec::new();
        {
            let mut local = lock(&self.local_jobs);
            let deadline = self.options.local_deadline;
            let expired: Vec<u64> = local
                .waiting
                .iter()
                .filter(|(_, lookup)| lookup.since.elapsed() >= deadline)
                .map(|(&id, _)| id)
                .collect();
            for id in expired {
                if let Some(lookup) = local.remove(id) {
                    log::debug!("local DNS lookup {id} got no answer in time");
                    failed.extend(lookup.jobs);
                }
            }
            for job in jobs {
                if resolver.is_none() {
                    failed.push(job);
                    continue;
                }
                let (rtype, rclass) = job.record_type_and_class();
                let question = (job.name().to_ascii_lowercase(), rtype, rclass);
                if let Some(&id) = local.by_question.get(&question) {
                    let lookup = local.waiting.get_mut(&id).expect("indexed lookups wait");
                    if lookup.jobs.len() < LOCAL_JOBS_PER_LOOKUP {
                        lookup.jobs.push(job);
                    } else {
                        failed.push(job);
                    }
                    continue;
                }
                if local.waiting.len() >= LOCAL_PENDING {
                    failed.push(job);
                    continue;
                }
                let id = local.next_id;
                local.next_id += 1;
                calls.push((id, job.name().to_string(), rtype, rclass));
                local.by_question.insert(question.clone(), id);
                let lookup = LocalLookup {
                    question,
                    jobs: vec![job],
                    since: Instant::now(),
                };
                local.waiting.insert(id, lookup);
            }
        }
        // Outside the lock: Swift may answer from inside the call.
        if let Some(resolver) = resolver {
            for (id, name, rtype, rclass) in calls {
                let call = AssertUnwindSafe(|| resolver.resolve(id, name, rtype, rclass));
                if let Err(payload) = catch_unwind(call) {
                    log::error!(
                        "LocalResolver.resolve panicked: {}",
                        panic_message(payload.as_ref())
                    );
                }
            }
        }
        failed
            .into_iter()
            .map(|job| self.dns.complete_local(job, None, now))
            .collect()
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
        // Before any socket is opened: the extension starts with a soft limit of 256.
        crate::fds::raise_open_file_limit();
        let (jobs, queue) = mpsc::channel(self.options.forward_queue.max(1));
        let resolver = self.resolver()?;
        let work = Work {
            proxy: self.proxy.clone(),
            dns: self.dns.clone(),
            resolver: resolver.clone(),
            sink,
            queue,
            in_flight: self.options.forward_in_flight.max(1),
            pins: self.pins.clone(),
            pins_save_interval: self.options.pins_save_interval,
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
                    resolver,
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
            resolver: _,
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
        self.pins.save(true);
        log::info!("engine stopped, proxy port {port} closed");
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop();
    }
}

fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
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

/// The learned pins file. A save takes its snapshot of the pins while holding `saved`, so
/// a save still running on the blocking pool when `stop` saves can never replace newer pins
/// with older ones.
struct PinsFile {
    path: PathBuf,
    policy: Arc<Policy>,
    /// The pins the file holds: the ones written last, or the ones loaded at creation.
    saved: Mutex<String>,
}

impl PinsFile {
    fn new(path: PathBuf, policy: Arc<Policy>) -> PinsFile {
        let saved = Mutex::new(policy.learned_pins_json());
        PinsFile {
            path,
            policy,
            saved,
        }
    }

    /// Whether the pins differ from the ones last saved. `false` while a save is running;
    /// a later check sees what it missed.
    fn changed(&self) -> bool {
        let saved = match self.saved.try_lock() {
            Ok(saved) => saved,
            Err(TryLockError::Poisoned(e)) => e.into_inner(),
            Err(TryLockError::WouldBlock) => return false,
        };
        *saved != self.policy.learned_pins_json()
    }

    /// Writes the pins if they changed since the last save, or in any case when `always`.
    /// Blocks on the file system.
    fn save(&self, always: bool) {
        let mut saved = self.saved.lock().unwrap_or_else(PoisonError::into_inner);
        let json = self.policy.learned_pins_json();
        if (always || json != *saved) && save_pins(&self.path, &json) {
            log::debug!("saved learned pins");
            *saved = json;
        }
    }
}

/// Where each `save_pins` call ran: the file and the name of the thread.
#[cfg(test)]
static PIN_SAVES: Mutex<Vec<(PathBuf, Option<String>)>> = Mutex::new(Vec::new());

fn save_pins(path: &Path, json: &str) -> bool {
    #[cfg(test)]
    PIN_SAVES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push((
            path.to_path_buf(),
            thread::current().name().map(String::from),
        ));
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
        pins,
        pins_save_interval,
    } = work;
    // The proxy looks upstream names up over the same DoH connections, so they do not go
    // to the network's resolver in plain text, whatever iOS does with the extension's own
    // lookups. getaddrinfo stays the fallback.
    let options = ServeOptions {
        resolver: Some(Arc::new(HostResolver::new(resolver.clone()))),
        ..ServeOptions::default()
    };
    let forwarding = tokio::spawn(forward(queue, resolver, dns, sink, in_flight));
    let saving = tokio::spawn(save_pins_periodically(pins, pins_save_interval));
    tollgate_mitm::serve_with_options(listener, proxy, options, async move {
        let _ = stopped.await;
    })
    .await;
    forwarding.abort();
    // A write already on the blocking pool keeps running; `stop` saves after it, on the
    // same lock, with pins at least as new.
    saving.abort();
}

/// Saves the learned pins every `interval` if they changed, so pins survive an extension
/// that ends without `stop` (jetsam, a crash).
async fn save_pins_periodically(pins: Arc<PinsFile>, interval: Duration) {
    let mut ticks = tokio::time::interval(interval.max(Duration::from_millis(1)));
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick completes at once.
    ticks.tick().await;
    loop {
        ticks.tick().await;
        if pins.changed() {
            let pins = pins.clone();
            // The write ends with an fsync, too slow for the runtime's only thread.
            let _ = tokio::task::spawn_blocking(move || pins.save(false)).await;
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

    /// Starts an engine in `dir` that saves pins every 50 ms, and makes it learn a pin for
    /// `pinned.example`.
    fn engine_learning_a_pin(dir: &Path) -> Arc<Engine> {
        let options = EngineOptions {
            pins_save_interval: Duration::from_millis(50),
            ..EngineOptions::default()
        };
        let engine = Engine::with_options("{}", dir, options).unwrap();
        engine.start(Arc::new(NullSink)).unwrap();
        let now = tollgate_common::clock::unix_secs();
        let policy = &engine.proxy.policy;
        assert!(!policy.record_client_rejection("pinned.example", RejectionKind::UnknownCa, now));
        assert!(policy.record_client_rejection("pinned.example", RejectionKind::UnknownCa, now));
        engine
    }

    /// Waits until the pins file in `dir` holds the pin for `pinned.example`.
    fn wait_for_saved_pin(dir: &Path) {
        let path = dir.join(LEARNED_PINS_FILE);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !std::fs::read_to_string(&path).is_ok_and(|json| json.contains("pinned.example")) {
            assert!(
                std::time::Instant::now() < deadline,
                "the pins were not saved"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn learned_pins_are_saved_while_running() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_learning_a_pin(dir.path());
        wait_for_saved_pin(dir.path());
        let path = dir.path().join(LEARNED_PINS_FILE);
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

    /// Writing the file ends with an fsync, which must not stall the proxy and the DNS
    /// forwarder on the runtime's only thread.
    #[test]
    fn learned_pins_are_written_off_the_runtime_thread() {
        let dir = tempfile::tempdir().unwrap();
        let engine = engine_learning_a_pin(dir.path());
        wait_for_saved_pin(dir.path());
        let path = dir.path().join(LEARNED_PINS_FILE);
        let threads: Vec<Option<String>> = PIN_SAVES
            .lock()
            .unwrap()
            .iter()
            .filter(|(saved, _)| *saved == path)
            .map(|(_, thread)| thread.clone())
            .collect();
        assert!(!threads.is_empty());
        assert!(
            threads.iter().all(|t| t.as_deref() != Some(RUNTIME_THREAD)),
            "saved on {threads:?}"
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
