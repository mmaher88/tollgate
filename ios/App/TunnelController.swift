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
    private let log = Logger(subsystem: "dev.tollgate.app", category: "tunnel")

    private var tunnelBundleIdentifier: String {
        (Bundle.main.bundleIdentifier ?? "") + ".tunnel"
    }

    var isOn: Bool { status == .connected || status == .connecting || status == .reasserting }

    /// Loads the existing configuration, or creates and saves one. Saving the first time
    /// shows the system "Add VPN Configurations" prompt.
    func load() async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences()
            if let existing = managers.first {
                attach(existing)
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
            report(error, context: "load")
        }
    }

    /// Turns protection on and keeps it on: the on-demand rule reconnects the tunnel after
    /// network changes, reboots and crashes.
    func start() async {
        if manager == nil { await load() }
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
            report(error, context: "start")
        }
    }

    /// Turns protection off. On-demand is disabled first, otherwise iOS reconnects at once.
    func stop() async {
        guard let manager else { return }
        do {
            manager.isOnDemandEnabled = false
            try await manager.saveToPreferences()
        } catch {
            report(error, context: "stop")
        }
        manager.connection.stopVPNTunnel()
    }

    /// Restarts a running tunnel so it picks up a new configuration (HTTPS filtering on or
    /// off, a new certificate). Does nothing when protection is off.
    func restartIfRunning() async {
        guard isOn, let manager else { return }
        manager.connection.stopVPNTunnel()
        for _ in 0..<50 where manager.connection.status != .disconnected {
            try? await Task.sleep(nanoseconds: 100_000_000)
        }
        do {
            try manager.connection.startVPNTunnel()
        } catch {
            report(error, context: "restart")
        }
    }

    func refreshStats() async {
        guard status == .connected, let data = await send(.stats) else { return }
        stats = try? JSONDecoder().decode(TunnelStats.self, from: data)
    }

    func reloadLists() async {
        guard status == .connected, let data = await send(.reloadLists) else { return }
        let reply = String(decoding: data, as: UTF8.self)
        if reply != "ok" { lastError = "reload lists: \(reply)" }
    }

    func sendForDisplay(_ command: TunnelCommand) async {
        let data = await send(command)
        lastReply = data.map { String(decoding: $0, as: UTF8.self) } ?? "(no reply)"
    }

    private func send(_ command: TunnelCommand) async -> Data? {
        guard let session = manager?.connection as? NETunnelProviderSession else { return nil }
        return await withCheckedContinuation { continuation in
            do {
                try session.sendProviderMessage(Data(command.rawValue.utf8)) { reply in
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

    private func report(_ error: Error, context: String) {
        log.error("\(context, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
        lastError = "\(context): \(error.localizedDescription)"
    }
}
