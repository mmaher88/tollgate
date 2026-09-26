import Foundation
import NetworkExtension
import os

/// Runs the Rust core inside the packet tunnel.
///
/// Only the tunnel DNS addresses are routed into the tunnel. DNS queries arrive as packets
/// and are answered by the core (blocked names, cache, DNS over HTTPS). When HTTPS filtering
/// is active, the system proxy settings point proxy-aware clients at the core's local proxy,
/// which filters requests and passes pinned and Apple hosts through untouched.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = Logger(subsystem: "dev.tollgate.tunnel", category: "provider")
    /// Read from the packet-flow callback queue and written from the provider queue. The
    /// packet read loop ends once it is nil.
    private let engineState = OSAllocatedUnfairLock<Engine?>(initialState: nil)

    private var engine: Engine? { engineState.withLock { $0 } }
    /// Watches `defaultPath` while the core runs.
    private var pathObservation: NSKeyValueObservation?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        setLogger(logger: OSLogCoreLogger(subsystem: "dev.tollgate.core"), maxLevel: .info)

        guard let directory = AppGroup.coreDirectory else {
            log.error("App Group container unavailable")
            completionHandler(TunnelError.appGroupUnavailable)
            return
        }
        guard Self.protectedDataReadable(in: directory) else {
            // Started by on-demand after a reboot, before the first unlock: the shared files
            // cannot be read yet. Bring the tunnel up without redirecting DNS and start the
            // core once they can, so it never runs without its lists, CA and learned pins.
            log.info("protected data unavailable, waiting for first unlock")
            setTunnelNetworkSettings(NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")) { error in
                completionHandler(error)
            }
            waitForProtectedData(in: directory)
            return
        }
        startCore(in: directory, completionHandler: completionHandler)
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.info("stopTunnel reason=\(reason.rawValue, privacy: .public)")
        // Always stop explicitly: the runtime thread holds the packet sink, so relying on
        // deinit would leave the core running.
        pathObservation?.invalidate()
        pathObservation = nil
        takeAndStopEngine()
        completionHandler()
    }

    /// Pooled upstream connections and DoH connections from before sleep usually still look
    /// open, but after a network change while asleep their path is gone and a request or
    /// query sent on one would hang. The core drops both.
    override func wake() {
        log.info("wake: dropping pooled upstream connections")
        engine?.resetConnections()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let message = TunnelMessage(messageData)
        switch message.command {
        case .ping:
            completionHandler?(Data("pong \(coreVersion())".utf8))
        case .stats:
            completionHandler?(try? JSONEncoder().encode(currentStats()))
        case .reloadLists:
            do {
                try engine?.reloadLists()
                log.info("lists reloaded")
                completionHandler?(Data("ok".utf8))
            } catch {
                log.error("reload failed: \(String(describing: error), privacy: .public)")
                completionHandler?(Data(String(describing: error).utf8))
            }
        case .events:
            let events = (engine?.recentEvents(limit: 500) ?? []).map { TunnelEvent($0) }
            completionHandler?(try? JSONEncoder().encode(events))
        case .clearEvents:
            engine?.clearEvents()
            completionHandler?(Data("ok".utf8))
        case .pins:
            // No engine yet (waiting for the first unlock): no answer, so the app does not
            // mistake an empty list for the real one.
            guard let engine else { completionHandler?(nil); return }
            let pins = engine.learnedPins().map { PinEntry(host: $0.host, learnedAt: $0.learnedAt) }
            completionHandler?(try? JSONEncoder().encode(pins))
        case .forgetPins:
            guard let engine else { completionHandler?(nil); return }
            let hosts = (try? JSONDecoder().decode([String].self, from: message.payload)) ?? []
            let forgotten = engine.forgetPins(hosts: hosts)
            log.info("forgot \(forgotten, privacy: .public) learned pins")
            completionHandler?(Data(String(forgotten).utf8))
        case .probeMemory:
            completionHandler?(Data("probing, watch the logs".utf8))
            probeMemory()
        case nil:
            log.error("unknown app message")
            completionHandler?(nil)
        }
    }

    // MARK: - Core lifecycle

    /// Creates and starts the engine, then applies the full network settings. Also used
    /// after the first unlock on a tunnel that is already up with minimal settings.
    private func startCore(in directory: URL, completionHandler: @escaping (Error?) -> Void) {
        var config = CoreConfig.load()
        // The core rejects the whole configuration when one pattern is invalid, which would
        // keep protection off; drop such entries instead.
        config.allowlist = validPatterns(config.allowlist, list: "allowlist")
        config.passthrough = validPatterns(config.passthrough, list: "passthrough")
        if config.mitmEnabled, !RootTrust.isTrustedForTLS(coreDirectory: directory) {
            // Trust was never granted or was removed in Settings: intercepting now would
            // break every HTTPS site, so run DNS blocking only.
            log.warning("HTTPS filtering is on but the certificate is not trusted; DNS only")
            config.mitmEnabled = false
        }

        let engine: Engine
        let port: UInt16
        do {
            engine = try Engine(configJson: config.json(), dataDir: directory.path)
            port = try engine.start(sink: FlowSink(flow: packetFlow))
        } catch {
            log.error("engine start failed: \(String(describing: error), privacy: .public)")
            completionHandler(error)
            return
        }
        engineState.withLock { $0 = engine }

        let filtering = engine.mitmActive()
        let version = coreVersion()
        let available = os_proc_available_memory()
        log.info("startTunnel core=\(version, privacy: .public) proxy=\(port, privacy: .public) https_filtering=\(filtering, privacy: .public) available=\(available, privacy: .public)")
        try? TunnelHeartbeat(
            startedAt: Date(), coreVersion: version,
            sha256Probe: sha256Hex(data: Data("tollgate".utf8)), availableMemoryBytes: available
        ).write()

        setTunnelNetworkSettings(Self.networkSettings(proxyPort: filtering ? port : nil)) { [weak self] error in
            guard let self else { return }
            if let error {
                self.log.error("setTunnelNetworkSettings failed: \(error.localizedDescription, privacy: .public)")
                self.takeAndStopEngine()
                completionHandler(error)
                return
            }
            self.log.info("tunnel up")
            self.observeNetworkChanges()
            // Started only now that engineState is set, so the first batch finds the engine.
            Self.readPackets(engineState: self.engineState, flow: self.packetFlow, log: self.log)
            completionHandler(nil)
        }
    }

    /// Drops the proxy's pooled upstream connections and the DoH connections when the
    /// default path changes (for example from Wi-Fi to cellular), like apps connecting
    /// directly would lose theirs.
    /// The first value and changes to an unsatisfied path are ignored.
    private func observeNetworkChanges() {
        pathObservation?.invalidate()
        pathObservation = observe(\.defaultPath, options: [.old, .new]) { [weak self] _, change in
            guard let self,
                  let old = change.oldValue ?? nil,
                  let new = change.newValue ?? nil,
                  new.status == .satisfied,
                  !new.isEqual(to: old)
            else { return }
            self.log.info("network path changed: dropping pooled upstream connections")
            self.engine?.resetConnections()
        }
    }

    private func validPatterns(_ patterns: [String], list: String) -> [String] {
        patterns.filter { pattern in
            do {
                try validateHostPattern(pattern: pattern)
                return true
            } catch {
                log.warning("ignoring invalid \(list, privacy: .public) entry \(pattern, privacy: .public)")
                return false
            }
        }
    }

    /// Clears the reference under the lock, then stops outside it (stop joins a thread).
    private func takeAndStopEngine() {
        let running = engineState.withLock { state -> Engine? in
            defer { state = nil }
            return state
        }
        running?.stop()
    }

    private func waitForProtectedData(in directory: URL) {
        DispatchQueue.main.asyncAfter(deadline: .now() + 10) { [weak self] in
            guard let self, self.engine == nil else { return }
            guard Self.protectedDataReadable(in: directory) else {
                self.waitForProtectedData(in: directory)
                return
            }
            self.log.info("protected data available, starting the core")
            self.startCore(in: directory) { [weak self] error in
                if let error { self?.cancelTunnelWithError(error) }
            }
        }
    }

    /// Opening a file fails while its data protection class is locked; fileExists only reads
    /// metadata and cannot tell.
    private static func protectedDataReadable(in directory: URL) -> Bool {
        for name in [CoreConfig.fileName, "ca.key", FilterLists.engineFile, FilterLists.domainsFile] {
            let url = directory.appendingPathComponent(name)
            guard FileManager.default.fileExists(atPath: url.path) else { continue }
            return (try? FileHandle(forReadingFrom: url)) != nil
        }
        return true // nothing written yet: a fresh install has nothing to protect
    }

    // MARK: - Packets

    /// DNS packets go to the core. Answers it can give at once are written here; answers
    /// that need an upstream lookup arrive later through `FlowSink`. The loop captures only
    /// the engine's lock and a weak flow, never the provider or the engine: the read that is
    /// still pending after stopTunnel keeps neither the stopped engine (with its lists) nor
    /// the flow alive, and ends the loop when it completes.
    private static func readPackets(engineState: OSAllocatedUnfairLock<Engine?>,
                                    flow: NEPacketTunnelFlow, log: Logger) {
        flow.readPackets { [weak flow] packets, _ in
            // Copy the engine out and call it outside the lock: takeAndStopEngine takes the
            // same lock on the provider queue.
            guard let flow, let engine = engineState.withLock({ $0 }) else { return }
            do {
                let replies = try engine.handlePackets(packets: packets)
                if !replies.isEmpty {
                    flow.writePackets(replies, withProtocols: replies.map(PacketFamily.of))
                }
            } catch {
                log.error("handlePackets failed: \(String(describing: error), privacy: .public)")
            }
            readPackets(engineState: engineState, flow: flow, log: log)
        }
    }

    static func networkSettings(proxyPort: UInt16?) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")

        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.2"], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: "198.18.0.1", subnetMask: "255.255.255.255")]
        settings.ipv4Settings = ipv4

        let ipv6 = NEIPv6Settings(addresses: ["fd00:7467::2"], networkPrefixLengths: [128])
        ipv6.includedRoutes = [NEIPv6Route(destinationAddress: "fd00:7467::1", networkPrefixLength: 128)]
        settings.ipv6Settings = ipv6

        let dns = NEDNSSettings(servers: ["198.18.0.1", "fd00:7467::1"])
        dns.matchDomains = [""]
        settings.dnsSettings = dns

        if let proxyPort {
            let server = NEProxyServer(address: "127.0.0.1", port: Int(proxyPort))
            let proxy = NEProxySettings()
            proxy.httpEnabled = true
            proxy.httpServer = server
            proxy.httpsEnabled = true
            proxy.httpsServer = server
            proxy.matchDomains = [""]
            proxy.excludeSimpleHostnames = true
            proxy.exceptionList = ["*.local", "localhost", "127.0.0.1"]
            settings.proxySettings = proxy
        }

        settings.mtu = 1500
        return settings
    }

    private func currentStats() -> TunnelStats {
        guard let engine else { return TunnelStats(availableMemoryBytes: os_proc_available_memory()) }
        let s = engine.stats()
        return TunnelStats(
            dnsQueries: s.dnsQueries, dnsBlocked: s.dnsBlocked, dnsCacheHits: s.dnsCacheHits,
            dnsForwarded: s.dnsForwarded, dnsFailed: s.dnsFailed, packetsDropped: s.packetsDropped,
            httpRequests: s.httpRequests, httpBlocked: s.httpBlocked,
            connectionsIntercepted: s.connectionsIntercepted, connectionsPassthrough: s.connectionsPassthrough,
            tlsClientRejections: s.tlsClientRejections, tlsAbandonedAfterHandshake: s.tlsAbandonedAfterHandshake,
            httpsFilteringActive: engine.mitmActive(), availableMemoryBytes: os_proc_available_memory())
    }

    /// Experiment E3. Allocates and dirties 4 MiB per step until jetsam kills the process.
    private func probeMemory() {
        let log = self.log
        DispatchQueue.global(qos: .utility).async {
            let chunk = 4 * 1024 * 1024
            var held: [UnsafeMutableRawPointer] = []
            for step in 1...64 {
                let block = UnsafeMutableRawPointer.allocate(byteCount: chunk, alignment: 16)
                arc4random_buf(block, chunk)
                held.append(block)
                log.info("probe step=\(step, privacy: .public) allocated_mib=\(step * 4, privacy: .public) available=\(os_proc_available_memory(), privacy: .public)")
                Thread.sleep(forTimeInterval: 0.25)
            }
            log.info("probe finished without termination, held=\(held.count, privacy: .public)")
        }
    }
}

extension TunnelEvent {
    init(_ event: BlockEvent) {
        self.init(
            unixSecs: event.unixSecs,
            kind: event.kind == .dns ? .dns : .request,
            host: event.host, url: event.url, sourceHost: event.sourceHost)
    }
}

enum TunnelError: Error {
    case appGroupUnavailable
}

/// Delivers answers produced on the core's runtime thread. Captures only the packet flow,
/// never the provider, so the provider and the engine can be released.
final class FlowSink: PacketSink, @unchecked Sendable {
    private let flow: NEPacketTunnelFlow

    init(flow: NEPacketTunnelFlow) {
        self.flow = flow
    }

    func writePackets(packets: [Data]) {
        flow.writePackets(packets, withProtocols: packets.map(PacketFamily.of))
    }
}

enum PacketFamily {
    /// The protocol family `writePackets` needs, read from the IP version nibble.
    static func of(_ packet: Data) -> NSNumber {
        NSNumber(value: (packet.first ?? 0) >> 4 == 6 ? AF_INET6 : AF_INET)
    }
}
