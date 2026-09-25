import Foundation
import NetworkExtension
import os

/// Owns the single NETunnelProviderManager for the Tollgate tunnel.
@MainActor
final class TunnelController: ObservableObject {
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var stats: TunnelStats?
    @Published private(set) var lastReply: String?
    @Published private(set) var lastError: String?

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private var configurationObserver: NSObjectProtocol?
    private let log = Logger(subsystem: "dev.tollgate.app", category: "tunnel")

    private var tunnelBundleIdentifier: String {
        (Bundle.main.bundleIdentifier ?? "") + ".tunnel"
    }

    var isOn: Bool { status == .connected || status == .connecting || status == .reasserting }

    init() {
        // Settings can change or delete the configuration (turning the VPN off there also
        // turns off Connect On Demand); keep the in-memory copy current.
        configurationObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNConfigurationChange, object: nil, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in await self?.load() }
        }
    }

    /// Loads the existing configuration. With `createIfMissing`, creates and saves one,
    /// which shows the system "Add VPN Configurations" prompt; that only happens when the
    /// user turns protection on.
    func load(createIfMissing: Bool = false) async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            if let existing = managers.first {
                attach(existing)
                return
            }
            guard createIfMissing else {
                manager = nil
                status = .invalid
                return
            }
            let manager = NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = tunnelBundleIdentifier
            proto.serverAddress = "On-device"
            manager.protocolConfiguration = proto
            manager.localizedDescription = "Tollgate"
            manager.isEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            attach(manager)
        } catch {
            report(error, context: createIfMissing ? "turn on" : "load")
        }
    }

    /// Turns protection on and keeps it on: the on-demand rule reconnects the tunnel after
    /// network changes, reboots and crashes.
    func start() async {
        await load(createIfMissing: true)
        guard let manager else { return }
        do {
            manager.isEnabled = true
            manager.onDemandRules = [NEOnDemandRuleConnect()]
            manager.isOnDemandEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            try manager.connection.startVPNTunnel()
            lastError = nil
        } catch {
            report(error, context: "turn on")
        }
    }

    /// Turns protection off. On-demand is disabled first, otherwise iOS reconnects at once.
    func stop() async {
        await load()
        guard let manager else { return }
        do {
            manager.isOnDemandEnabled = false
            try await manager.saveToPreferences()
            lastError = nil
        } catch {
            report(error, context: "turn off")
        }
        manager.connection.stopVPNTunnel()
    }

    /// Restarts a running tunnel so it picks up a new configuration, and waits until it is
    /// connected again. With `clearingLearnedPins`, forgets hosts learned as pinned while the
    /// old configuration was running (for example while the certificate was untrusted).
    func restartIfRunning(clearingLearnedPins: Bool = false) async {
        guard isOn, let manager else {
            if clearingLearnedPins { Self.removeLearnedPins() }
            return
        }
        manager.connection.stopVPNTunnel()
        for _ in 0..<50 where manager.connection.status != .disconnected {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        if clearingLearnedPins { Self.removeLearnedPins() }
        do {
            try manager.connection.startVPNTunnel()
        } catch {
            report(error, context: "restart")
            return
        }
        for _ in 0..<100 where manager.connection.status != .connected {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
    }

    /// Applies freshly compiled lists. The core only enables HTTPS filtering when the engine
    /// is created (it needs engine.dat then), so a running engine that could not enable it,
    /// or one that was still starting, is restarted; otherwise the lists are reloaded in place.
    func listsUpdated() async {
        switch status {
        case .connected:
            await refreshStats()
            if CoreConfig.load().mitmEnabled, stats?.httpsFilteringActive == false {
                await restartIfRunning()
            } else if let data = await send(.reloadLists) {
                let reply = String(decoding: data, as: UTF8.self)
                if reply != "ok" { lastError = "reload lists: \(reply)" }
            }
        case .connecting, .reasserting:
            await restartIfRunning()
        default:
            break // off: the next start loads the new files
        }
    }

    func refreshStats() async {
        guard status == .connected, let data = await send(.stats) else { return }
        stats = try? JSONDecoder().decode(TunnelStats.self, from: data)
    }

    func sendForDisplay(_ command: TunnelCommand) async {
        let data = await send(command)
        lastReply = data.map { String(decoding: $0, as: UTF8.self) } ?? "(no reply)"
    }

    func showError(_ message: String) {
        lastError = message
    }

    /// True when an HTTPS request from this app fails certificate validation. With HTTPS
    /// filtering on, the app's own requests go through the tunnel's proxy like Safari's, so
    /// this checks end to end that the root is trusted for websites.
    nonisolated static func httpsBrokenByUntrustedCertificate() async -> Bool {
        var request = URLRequest(url: URL(string: "https://example.com/")!, timeoutInterval: 15)
        request.httpMethod = "HEAD"
        let session = URLSession(configuration: .ephemeral)
        defer { session.finishTasksAndInvalidate() }
        do {
            _ = try await session.data(for: request)
            return false
        } catch let error as URLError {
            let trustFailures: [URLError.Code] = [
                .serverCertificateUntrusted, .serverCertificateHasUnknownRoot,
                .serverCertificateHasBadDate, .serverCertificateNotYetValid, .secureConnectionFailed,
            ]
            return trustFailures.contains(error.code)
        } catch {
            return false
        }
    }

    /// Recent blocks, newest first; nil when the tunnel is not running.
    func events() async -> [TunnelEvent]? {
        guard status == .connected, let data = await send(.events) else { return nil }
        return try? JSONDecoder().decode([TunnelEvent].self, from: data)
    }

    func clearEvents() async {
        guard status == .connected else { return }
        _ = await send(.clearEvents)
    }

    /// Learned pins from the running engine; nil when the tunnel is not running.
    func pins() async -> [PinEntry]? {
        guard status == .connected, let data = await send(.pins) else { return nil }
        return try? JSONDecoder().decode([PinEntry].self, from: data)
    }

    /// Returns false when the tunnel is not running (the caller then edits the stored file).
    func forgetPins(_ hosts: [String]) async -> Bool {
        guard status == .connected, let payload = try? JSONEncoder().encode(hosts) else { return false }
        return await send(.forgetPins, payload: payload) != nil
    }

    private func send(_ command: TunnelCommand, payload: Data? = nil) async -> Data? {
        guard let session = manager?.connection as? NETunnelProviderSession else { return nil }
        let message = TunnelMessage.encode(command, payload: payload)
        return await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(message) { reply in
                    continuation.resume(returning: reply)
                }
            } catch {
                continuation.resume(returning: nil)
            }
        }
    }

    private func attach(_ manager: NETunnelProviderManager) {
        self.manager = manager
        status = manager.connection.status
        if let statusObserver {
            NotificationCenter.default.removeObserver(statusObserver)
        }
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: manager.connection, queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self, let manager = self.manager else { return }
                self.status = manager.connection.status
                if self.status != .connected { self.stats = nil }
            }
        }
    }

    private static func removeLearnedPins() {
        guard let directory = AppGroup.coreDirectory else { return }
        try? FileManager.default.removeItem(at: directory.appendingPathComponent("learned-pins.json"))
    }

    private func report(_ error: Error, context: String) {
        log.error("\(context, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
        lastError = "\(context): \(error.localizedDescription)"
    }
}
