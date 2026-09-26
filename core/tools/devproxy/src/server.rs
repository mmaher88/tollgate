//! Preparing the data directory and running the DNS responder and the proxy.

use std::fmt::Write as _;
use std::future::Future;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, UdpSocket};
use tollgate_common::events::{BlockEvent, EventKind, EventLog};
use tollgate_common::stats::{Stats, StatsSnapshot};
use tollgate_dns::{DnsHandler, DohResolver};
use tollgate_ffi::{
    CA_CERT_FILE, LEARNED_PINS_FILE, ListFormat, ListInput, ListTarget, compile_lists, generate_ca,
    load_ca,
};
use tollgate_filter::{DOMAINS_FILE, DomainSet, ENGINE_FILE, FilterEngine, FilterError};
use tollgate_mitm::ProxyContext;
use tollgate_policy::{Config, HostPattern, Policy};

use crate::args::{Args, ListKind};
use crate::fetch::{Fetcher, load_source};
use crate::udp::{PayloadHandler, serve_dns};

/// Blocks printed when devproxy exits.
pub const EVENTS_ON_EXIT: usize = 20;

/// What [`DevProxy::serve`] returns: the final counters and the last blocks.
#[derive(Debug)]
pub struct Summary {
    pub stats: StatsSnapshot,
    /// At most [`EVENTS_ON_EXIT`] blocks, newest first.
    pub events: Vec<BlockEvent>,
}

/// Everything bound and loaded, ready to serve.
pub struct DevProxy {
    data_dir: PathBuf,
    dns_socket: UdpSocket,
    proxy_listener: TcpListener,
    ctx: Arc<ProxyContext>,
    dns: Arc<DnsHandler>,
    resolver: DohResolver,
}

fn text<E: std::fmt::Display>(context: impl std::fmt::Display) -> impl FnOnce(E) -> String {
    move |e| format!("{context}: {e}")
}

fn optional<T>(result: Result<T, FilterError>) -> Result<Option<T>, String> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(FilterError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// Downloads or reads the lists and compiles them into `data_dir`.
async fn compile(args: &Args, data_dir: &str) -> Result<(), String> {
    let fetcher = Fetcher::new();
    let mut inputs = Vec::new();
    for spec in &args.lists {
        let text = load_source(&fetcher, &spec.source).await?;
        log::info!("{}: {} bytes", spec.source, text.len());
        let (format, target) = match spec.kind {
            ListKind::Url => (ListFormat::Adblock, ListTarget::Url),
            ListKind::Dns => (ListFormat::Adblock, ListTarget::Dns),
            ListKind::Hosts => (ListFormat::Hosts, ListTarget::Dns),
        };
        inputs.push(ListInput {
            name: spec.source.clone(),
            text,
            format,
            target,
        });
    }
    let report = compile_lists(inputs, data_dir.to_string()).map_err(|e| e.to_string())?;
    log::info!(
        "compiled {} network rules ({} bytes) and {} DNS names ({} bytes)",
        report.network_rules,
        report.engine_bytes,
        report.domain_entries,
        report.domains_bytes
    );
    Ok(())
}

/// Binds with `SO_REUSEADDR`, so the responder can take `127.0.0.1:5353` while an mDNS
/// responder (avahi, systemd-resolved) holds `0.0.0.0:5353`; unicast queries to
/// `127.0.0.1` reach the more specific socket.
fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

impl DevProxy {
    /// Compiles the lists (when any are given), makes sure a CA exists, loads the data
    /// directory the way the tunnel does and binds both listeners.
    pub async fn prepare(args: &Args) -> Result<DevProxy, String> {
        // Absolute, so the printed certificate path works from any directory.
        let dir = &std::path::absolute(&args.data_dir).map_err(text(args.data_dir.display()))?;
        std::fs::create_dir_all(dir).map_err(text(dir.display()))?;
        let dir_str = dir.to_str().ok_or("the data directory must be UTF-8")?;
        let config = match &args.config {
            Some(path) => {
                let json = std::fs::read_to_string(path).map_err(text(path.display()))?;
                Config::from_json(&json).map_err(text(path.display()))?
            }
            None => Config::default(),
        };
        if !args.lists.is_empty() {
            compile(args, dir_str).await?;
        }
        let info = generate_ca(dir_str.to_string()).map_err(|e| e.to_string())?;
        if info.created {
            log::info!("generated a new root CA, import it into the browser");
        }
        let ca = load_ca(dir)
            .map_err(|e| e.to_string())?
            .ok_or("the CA disappeared from the data directory")?;
        let filter = optional(FilterEngine::load(&dir.join(ENGINE_FILE)))?;
        let domains = optional(DomainSet::load(&dir.join(DOMAINS_FILE)))?;
        if filter.is_none() {
            log::warn!(
                "no {ENGINE_FILE}: nothing is intercepted; pass --url-list or --default-lists"
            );
        }
        if domains.is_none() {
            log::warn!("no {DOMAINS_FILE}: DNS answers nothing locally");
        }
        // Like the tunnel: interception needs a filter engine.
        let policy_config = Config {
            mitm_enabled: config.mitm_enabled && filter.is_some(),
            ..config.clone()
        };
        let pins = std::fs::read_to_string(dir.join(LEARNED_PINS_FILE)).ok();
        let policy = Policy::new(&policy_config, pins.as_deref()).map_err(|e| e.to_string())?;
        let allowlist = config
            .allowlist
            .iter()
            .map(|p| HostPattern::parse(p))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let domains = domains.map(Arc::new);
        let stats = Arc::new(Stats::default());
        // One blocked log for the proxy and the DNS responder, like the tunnel.
        let events = Arc::new(EventLog::new());
        let ctx = Arc::new(ProxyContext {
            policy: Arc::new(policy),
            filter: ArcSwapOption::new(filter.map(Arc::new)),
            // The same set as the DNS responder, like the tunnel.
            domains: ArcSwapOption::new(domains.clone()),
            ca: Arc::new(ca),
            stats: stats.clone(),
            max_intercepted: config.max_intercepted_connections as usize,
            available_memory: || None,
            events: Some(events.clone()),
            upstream_resets: Default::default(),
        });
        let dns = Arc::new(DnsHandler::new(domains, stats));
        dns.set_allowlist(allowlist);
        dns.set_events(Some(events));
        let dns_socket = bind_udp(args.dns).map_err(text(format!("DNS listener {}", args.dns)))?;
        let proxy_listener = TcpListener::bind(args.proxy)
            .await
            .map_err(text(format!("proxy listener {}", args.proxy)))?;
        Ok(DevProxy {
            data_dir: dir.clone(),
            dns_socket,
            proxy_listener,
            ctx,
            dns,
            resolver: DohResolver::new(config.doh_upstreams),
        })
    }

    pub fn dns_addr(&self) -> SocketAddr {
        self.dns_socket.local_addr().expect("a bound socket")
    }

    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy_listener.local_addr().expect("a bound listener")
    }

    pub fn ca_path(&self) -> PathBuf {
        self.data_dir.join(CA_CERT_FILE)
    }

    /// Serves until `shutdown` resolves, then saves the learned pins and returns the
    /// final counters and the last blocks. Must run on a current-thread runtime.
    pub async fn serve(self, shutdown: impl Future<Output = ()>) -> Summary {
        let DevProxy {
            data_dir,
            dns_socket,
            proxy_listener,
            ctx,
            dns,
            resolver,
        } = self;
        let responder = tokio::spawn(serve_dns(dns_socket, PayloadHandler::new(dns), resolver));
        tollgate_mitm::serve(proxy_listener, ctx.clone(), shutdown).await;
        responder.abort();
        let pins = data_dir.join(LEARNED_PINS_FILE);
        if let Err(e) = std::fs::write(&pins, ctx.policy.learned_pins_json()) {
            log::warn!("{}: {e}", pins.display());
        }
        Summary {
            stats: ctx.stats.snapshot(),
            events: ctx
                .events
                .as_ref()
                .map(|events| events.recent(EVENTS_ON_EXIT))
                .unwrap_or_default(),
        }
    }
}

/// The blocks as printed on exit: time, kind, then the URL for requests (with the page
/// host when known) or the name for DNS, one per line.
pub fn format_events(events: &[BlockEvent]) -> String {
    if events.is_empty() {
        return "No blocks recorded.\n".to_string();
    }
    let mut out = format!("Last {} blocks, newest first:\n", events.len());
    for event in events {
        let kind = match event.kind {
            EventKind::Dns => "dns",
            EventKind::Request => "request",
        };
        let what = event.url.as_deref().unwrap_or(&event.host);
        let _ = write!(out, "  {}  {kind:<7}  {what}", event.unix_secs);
        if let Some(page) = &event.source_host {
            let _ = write!(out, "  (page {page})");
        }
        out.push('\n');
    }
    out
}

/// What to do in Firefox, printed once everything listens.
pub fn instructions(proxy: SocketAddr, dns: SocketAddr, ca_path: &Path) -> String {
    let (proxy_host, proxy_port) = (proxy.ip(), proxy.port());
    let (dns_host, dns_port) = (dns.ip(), dns.port());
    let ca = ca_path.display();
    format!(
        "\
Tollgate devproxy is running.

  HTTP and HTTPS proxy  {proxy}
  DNS over UDP          {dns}
  Root certificate      {ca}

Firefox, in a separate profile (firefox -P tollgate-dev --no-remote):
  1. Settings, General, Network Settings, Settings...: Manual proxy configuration,
     HTTP Proxy {proxy_host}, Port {proxy_port}, tick \"Also use this proxy for HTTPS\".
  2. Settings, Privacy & Security, Certificates, View Certificates..., Authorities,
     Import...: choose {ca} and tick \"Trust this CA to identify websites\".
  3. about:config: set network.trr.mode to 5 (Firefox's own DNS over HTTPS off) and
     network.dns.echconfig.enabled to false, so no Encrypted Client Hello hides the
     server name from the proxy.

DNS check: dig @{dns_host} -p {dns_port} doubleclick.net A
Stop with Ctrl-C; learned pins are saved in the data directory.
"
    )
}
