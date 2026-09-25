import Foundation
import NetworkExtension
import os

/// Owns the single NETunnelProviderManager for the Tollgate tunnel.
@MainActor
final class TunnelController: ObservableObject {
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var lastReply: String?
    @Published private(set) var lastError: String?

    private var manager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?
    private let log = Logger(subsystem: "dev.tollgate.app", category: "tunnel")

    private var tunnelBundleIdentifier: String {
        (Bundle.main.bundleIdentifier ?? "") + ".tunnel"
    }

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

    func start() async {
        if manager == nil { await load() }
        guard let manager else { return }
        do {
            if !manager.isEnabled {
                manager.isEnabled = true
                try await manager.saveToPreferences()
                try await manager.loadFromPreferences()
            }
            try manager.connection.startVPNTunnel()
            lastError = nil
        } catch {
            report(error, context: "start")
        }
    }

    func stop() {
        manager?.connection.stopVPNTunnel()
    }

    func send(_ command: TunnelCommand) {
        guard let session = manager?.connection as? NETunnelProviderSession else {
            lastError = "Tunnel is not configured"
            return
        }
        do {
            try session.sendProviderMessage(Data(command.rawValue.utf8)) { [weak self] reply in
                let text = reply.map { String(decoding: $0, as: UTF8.self) } ?? "(no reply)"
                Task { @MainActor in self?.lastReply = text }
            }
        } catch {
            report(error, context: "send \(command.rawValue)")
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
            Task { @MainActor in self?.status = manager.connection.status }
        }
    }

    private func report(_ error: Error, context: String) {
        log.error("\(context, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
        lastError = "\(context): \(error.localizedDescription)"
    }
}
