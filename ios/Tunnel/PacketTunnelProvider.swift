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
    private var engine: Engine?

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        setLogger(logger: OSLogCoreLogger(subsystem: "dev.tollgate.core"), maxLevel: .info)

        guard let directory = AppGroup.coreDirectory else {
            log.error("App Group container unavailable")
            completionHandler(TunnelError.appGroupUnavailable)
            return
        }

        let engine: Engine
        let port: UInt16
        do {
            engine = try Engine(configJson: CoreConfig.json(), dataDir: directory.path)
            port = try engine.start(sink: FlowSink(flow: packetFlow))
        } catch {
            log.error("engine start failed: \(String(describing: error), privacy: .public)")
            completionHandler(error)
            return
        }
        self.engine = engine

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
                self.engine?.stop()
                self.engine = nil
                completionHandler(error)
                return
            }
            self.log.info("tunnel up")
            self.readPackets()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.info("stopTunnel reason=\(reason.rawValue, privacy: .public)")
        // Always stop explicitly: the runtime thread holds the packet sink, so relying on
        // deinit would leave the core running.
        engine?.stop()
        engine = nil
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let text = String(decoding: messageData, as: UTF8.self)
        switch TunnelCommand(rawValue: text) {
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
        case .probeMemory:
            completionHandler?(Data("probing, watch the logs".utf8))
            probeMemory()
        case nil:
            log.error("unknown app message: \(text, privacy: .public)")
            completionHandler?(nil)
        }
    }

    // MARK: - Packets

    /// DNS packets go to the core. Answers it can give at once come back here; answers that
    /// need an upstream lookup arrive later through `FlowSink`.
    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self, let engine = self.engine else { return }
            do {
                let replies = try engine.handlePackets(packets: packets)
                if !replies.isEmpty {
                    self.packetFlow.writePackets(replies, withProtocols: replies.map(PacketFamily.of))
                }
            } catch {
                self.log.error("handlePackets failed: \(String(describing: error), privacy: .public)")
            }
            self.readPackets()
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
