import Foundation
import NetworkExtension
import UIKit
import os

/// Owns the single NETunnelProviderManager for the Tollgate tunnel.
@MainActor
final class TunnelController: ObservableObject {
    @Published private(set) var status: NEVPNStatus = .invalid
    @Published private(set) var stats: TunnelStats?
    @Published private(set) var lastReply: String?
    @Published private(set) var lastError: String?
    /// True while `start()` or `stop()` runs; the Turn on/off button is disabled meanwhile.
    @Published private(set) var busy = false

    private var manager: NETunnelProviderManager?
    /// The last `load` call. Loads run one after another, so two of them never both create
    /// a configuration, or both remove duplicates and keep different ones.
    private var loading: Task<Void, Never>?
    /// The last `restartIfRunning` call, so restarts do not overlap.
    private var restarting: Task<Void, Never>?
    /// True while `restartNow` has Connect On Demand turned off on purpose, so `loadNow`
    /// (run by the configuration-change observer meanwhile) does not turn it back on.
    private var restartInProgress = false
    /// True from `.connecting` until the tunnel connects or stops, to tell a failed start
    /// from a tunnel that was turned off.
    private var startPending = false
    /// True after `stop()` until the tunnel stops, so that stop is not reported as a failure.
    private var stopRequested = false
    /// The message shown for the last failed start; cleared once the tunnel connects.
    private var startFailure: String?
    private var statusObserver: NSObjectProtocol?
    private var configurationObserver: NSObjectProtocol?
    private let log = Logger(subsystem: "dev.tollgate.app", category: "tunnel")

    /// Set while a restart has Connect On Demand turned off. If the app is suspended or
    /// killed before the restart turns it back on, the next load does, so the tunnel does
    /// not stay off until the user notices.
    private static let onDemandPausedKey = "tunnel.onDemandPausedForRestart"
    /// Set when new lists were compiled in the background and the tunnel needed a restart
    /// to use them; the next time the app is active, `applyPendingListUpdate` does it.
    private static let listsPendingKey = "tunnel.listsPendingRestart"

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
    /// user turns protection on. Waits for any earlier load to finish first.
    func load(createIfMissing: Bool = false) async {
        let previous = loading
        let task = Task { @MainActor in
            await previous?.value
            await self.loadNow(createIfMissing: createIfMissing)
        }
        loading = task
        await task.value
    }

    private func loadNow(createIfMissing: Bool) async {
        do {
            let managers = try await NETunnelProviderManager.loadAllFromPreferences().filter {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier
                    == tunnelBundleIdentifier
            }
            if let existing = Self.preferred(managers) {
                // Duplicates (from an older build that could create two) are removed with
                // their on-demand rules, so none can keep a tunnel running that the app
                // does not track.
                for duplicate in managers where duplicate !== existing {
                    log.info("removing a duplicate VPN configuration")
                    try? await duplicate.removeFromPreferences()
                }
                attach(existing)
                await restoreOnDemandAfterInterruptedRestart(existing)
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

    /// Turns Connect On Demand back on, and starts the tunnel, when a restart turned it off
    /// and did not get to turn it on again (the app was suspended or killed meanwhile).
    private func restoreOnDemandAfterInterruptedRestart(_ manager: NETunnelProviderManager) async {
        let defaults = UserDefaults.standard
        guard !restartInProgress, defaults.bool(forKey: Self.onDemandPausedKey) else { return }
        defaults.removeObject(forKey: Self.onDemandPausedKey)
        guard !manager.isOnDemandEnabled else { return }
        log.info("turning Connect On Demand back on after an interrupted restart")
        do {
            manager.isEnabled = true
            manager.onDemandRules = [NEOnDemandRuleConnect()]
            manager.isOnDemandEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            if manager.connection.status == .disconnected || manager.connection.status == .invalid {
                try manager.connection.startVPNTunnel()
            }
        } catch {
            report(error, context: "turning protection back on")
        }
    }

    /// The configuration to keep: a running one, else an enabled one, else the first.
    private static func preferred(_ managers: [NETunnelProviderManager]) -> NETunnelProviderManager? {
        let running = managers.first {
            $0.connection.status != .disconnected && $0.connection.status != .invalid
        }
        return running ?? managers.first { $0.isEnabled } ?? managers.first
    }

    /// Turns protection on and keeps it on: the on-demand rule reconnects the tunnel after
    /// network changes, reboots and crashes. A call while `start()` or `stop()` runs does
    /// nothing.
    func start() async {
        guard !busy else { return }
        busy = true
        defer { busy = false }
        stopRequested = false
        lastError = nil
        await load(createIfMissing: true)
        guard let manager else { return }
        do {
            manager.isEnabled = true
            manager.onDemandRules = [NEOnDemandRuleConnect()]
            manager.isOnDemandEnabled = true
            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            // Only queues the start: a failure arrives later as a status change (see
            // `track`), and the message shows then.
            try manager.connection.startVPNTunnel()
        } catch {
            report(error, context: "turn on")
        }
    }

    /// Turns protection off. On-demand is disabled first, otherwise iOS reconnects at once.
    /// A call while `start()` or `stop()` runs does nothing.
    func stop() async {
        guard !busy else { return }
        busy = true
        defer { busy = false }
        // An explicit Turn off wins over an interrupted restart, so the load below does not
        // turn Connect On Demand back on first.
        UserDefaults.standard.removeObject(forKey: Self.onDemandPausedKey)
        await load()
        guard let manager else { return }
        stopRequested = true
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
    /// Restarts run one after another, and never at the same time as `start()` or `stop()`.
    func restartIfRunning(clearingLearnedPins: Bool = false) async {
        let previous = restarting
        let task = Task { @MainActor in
            await previous?.value
            await self.restartNow(clearingLearnedPins: clearingLearnedPins)
        }
        restarting = task
        await task.value
    }

    private func restartNow(clearingLearnedPins: Bool) async {
        while busy { try? await Task.sleep(nanoseconds: 100_000_000) }
        busy = true
        defer { busy = false }
        await load()
        guard let manager else {
            if clearingLearnedPins { Self.removeLearnedPins() }
            return
        }
        switch manager.connection.status {
        case .connected, .connecting, .reasserting:
            break
        case .disconnecting:
            // Being turned off: no restart, but the stopping engine saves its pins on the
            // way out, so the file is removed only once it is gone.
            if clearingLearnedPins {
                if await wait(for: .disconnected, on: manager, tries: 50) {
                    Self.removeLearnedPins()
                } else {
                    lastError = "Learned certificate pins were not cleared: the tunnel is still stopping."
                }
            }
            return
        default:
            if clearingLearnedPins { Self.removeLearnedPins() }
            return
        }

        // The restart must finish even if the user leaves the app right away (as after
        // "Never block"); if iOS still suspends it, the next load turns on-demand back on.
        let backgroundTime = BackgroundTime(name: "tunnel-restart")
        defer { backgroundTime.end() }
        if clearingLearnedPins, manager.connection.status == .connected,
           case .engine(let learned) = await pins(), !learned.isEmpty {
            // A second safeguard: the engine saves the empty set at once and again on stop.
            _ = await forgetPins(learned.map(\.host))
        }
        // Without this, iOS starts a new tunnel as soon as this one stops, and its engine
        // would read learned-pins.json before it is removed.
        let onDemand = manager.isOnDemandEnabled
        restartInProgress = true
        defer { restartInProgress = false }
        if onDemand {
            UserDefaults.standard.set(true, forKey: Self.onDemandPausedKey)
            manager.isOnDemandEnabled = false
            do {
                try await manager.saveToPreferences()
            } catch {
                manager.isOnDemandEnabled = true
                UserDefaults.standard.removeObject(forKey: Self.onDemandPausedKey)
                report(error, context: "restart")
                return
            }
        }
        manager.connection.stopVPNTunnel()
        let stopped = await wait(for: .disconnected, on: manager, tries: 50)
        if clearingLearnedPins {
            if stopped {
                Self.removeLearnedPins()
            } else {
                lastError = "Learned certificate pins were not cleared: the tunnel did not stop in time."
            }
        }
        if onDemand {
            manager.onDemandRules = [NEOnDemandRuleConnect()]
            manager.isOnDemandEnabled = true
            do {
                try await manager.saveToPreferences()
                UserDefaults.standard.removeObject(forKey: Self.onDemandPausedKey)
                try await manager.loadFromPreferences()
            } catch {
                // The flag stays set, so the next load tries again.
                report(error, context: "restart: turning Connect On Demand back on")
            }
        }
        do {
            try manager.connection.startVPNTunnel()
        } catch {
            report(error, context: "restart")
            return
        }
        let connected = await wait(for: .connected, on: manager, tries: 100)
        let status = manager.connection.status
        if !connected, status == .disconnected || status == .invalid {
            // Reported here, since the status observer ignores changes during a restart.
            startPending = false
            reportFailedStart(manager)
        }
    }

    /// Polls every 100 ms until the tunnel reaches `wanted`, at most `tries` times. True when
    /// it did.
    private func wait(for wanted: NEVPNStatus, on manager: NETunnelProviderManager, tries: Int) async -> Bool {
        var polls = 0
        while manager.connection.status != wanted, polls < tries {
            try? await Task.sleep(nanoseconds: 100_000_000)
            polls += 1
        }
        return manager.connection.status == wanted
    }

    /// Applies freshly compiled lists. The core only enables HTTPS filtering when the engine
    /// is created (it needs engine.dat then), so a running engine that could not enable it,
    /// or one that was still starting, is restarted; otherwise the lists are reloaded in place.
    /// In the background (the refresh task) a restart is left for the next time the app is
    /// active (`applyPendingListUpdate`): it could be cut short when the background time
    /// runs out, and would leave protection off until then.
    func listsUpdated() async {
        UserDefaults.standard.removeObject(forKey: Self.listsPendingKey)
        switch status {
        case .connected:
            await refreshStats()
            if CoreConfig.load().mitmEnabled, stats?.httpsFilteringActive == false {
                await restartUnlessInBackground()
            } else if let data = await send(.reloadLists) {
                let reply = String(decoding: data, as: UTF8.self)
                if reply != "ok" { lastError = "reload lists: \(reply)" }
            }
        case .connecting, .reasserting:
            await restartUnlessInBackground()
        default:
            break // off: the next start loads the new files
        }
    }

    private func restartUnlessInBackground() async {
        if UIApplication.shared.applicationState == .background {
            log.info("new lists need a tunnel restart; leaving it for the next time the app is active")
            UserDefaults.standard.set(true, forKey: Self.listsPendingKey)
            return
        }
        await restartIfRunning()
    }

    /// Applies lists compiled in the background whose restart was left for later. Call it
    /// when the app becomes active.
    func applyPendingListUpdate() async {
        guard UserDefaults.standard.bool(forKey: Self.listsPendingKey) else { return }
        await load()
        await listsUpdated()
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

    enum PinSource {
        /// The running engine answered.
        case engine([PinEntry])
        /// No engine can be running: read or edit learned-pins.json directly.
        case storedFile
        /// The tunnel is starting or stopping; an engine may be alive and would overwrite a
        /// file edit when it saves. Try again in a moment.
        case unavailable
    }

    /// Learned pins, from the engine while it runs.
    func pins() async -> PinSource {
        switch status {
        case .connected, .reasserting:
            guard let data = await send(.pins),
                  let pins = try? JSONDecoder().decode([PinEntry].self, from: data)
            else { return .unavailable }
            return .engine(pins)
        case .disconnected, .invalid:
            return .storedFile
        default:
            return .unavailable
        }
    }

    enum PinEditResult {
        case done
        case editStoredFile
        case unavailable
    }

    /// Forgets pins in the running engine, or tells the caller to edit the stored file when
    /// no engine can be running.
    func forgetPins(_ hosts: [String]) async -> PinEditResult {
        switch status {
        case .connected, .reasserting:
            guard let payload = try? JSONEncoder().encode(hosts),
                  await send(.forgetPins, payload: payload) != nil
            else { return .unavailable }
            return .done
        case .disconnected, .invalid:
            return .editStoredFile
        default:
            return .unavailable
        }
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
                self.track(self.status, on: manager)
            }
        }
    }

    /// Notices a start that failed: the tunnel went from `.connecting` to `.disconnected`
    /// without `stop()` or a restart asking for it. `startVPNTunnel()` only queues the start,
    /// so this is where the tunnel's error (engine, App Group, network settings) shows up.
    private func track(_ status: NEVPNStatus, on manager: NETunnelProviderManager) {
        switch status {
        case .connecting:
            startPending = true
        case .connected:
            startPending = false
            stopRequested = false
            if let startFailure, lastError == startFailure { lastError = nil }
            startFailure = nil
        case .disconnected, .invalid:
            let failed = startPending && !stopRequested && !restartInProgress
            startPending = false
            stopRequested = false
            if failed { reportFailedStart(manager) }
        default:
            break
        }
    }

    /// Shows why the last start failed: the reason the tunnel recorded in the App Group,
    /// else the error iOS kept for the connection. Nothing when neither says anything.
    private func reportFailedStart(_ manager: NETunnelProviderManager) {
        if let reason = TunnelStartFailure.take() {
            showStartFailure(reason)
            return
        }
        manager.connection.fetchLastDisconnectError { [weak self] error in
            guard let error else { return }
            let underlying = (error as NSError).userInfo[NSUnderlyingErrorKey] as? Error
            let reason = (underlying ?? error).localizedDescription
            Task { @MainActor in self?.showStartFailure(reason) }
        }
    }

    /// One message per failure: on-demand retries that fail the same way do not change it.
    private func showStartFailure(_ reason: String) {
        let message = "Protection could not start: \(reason)"
        guard message != lastError else { return }
        log.error("\(message, privacy: .public)")
        startFailure = message
        lastError = message
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
