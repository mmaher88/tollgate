import NetworkExtension
import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var tunnel: TunnelController
    @EnvironmentObject private var lists: ListUpdater
    @EnvironmentObject private var certificate: CertificateManager
    @Environment(\.scenePhase) private var scenePhase
    @State private var httpsFiltering = CoreConfig.load().mitmEnabled
    @State private var heartbeat: TunnelHeartbeat?

    var body: some View {
        NavigationStack {
            List {
                protectionSection
                setupSection
                if tunnel.status == .connected {
                    activitySection
                }
                diagnosticsSection
            }
            .navigationTitle("Tollgate")
            .task {
                await tunnel.load()
                await certificate.prepare()
                enforceTrust()
                updateListsIfMissing()
            }
            .task(id: tunnel.status) {
                heartbeat = TunnelHeartbeat.read()
                if tunnel.status == .connected { updateListsIfMissing() }
                while tunnel.status == .connected, !Task.isCancelled {
                    await tunnel.refreshStats()
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                }
            }
            .onChange(of: scenePhase) { _, phase in
                guard phase == .active else { return }
                Task {
                    await certificate.refreshTrust()
                    enforceTrust()
                    updateListsIfMissing()
                }
            }
        }
    }

    // MARK: - Protection

    private var protectionSection: some View {
        Section {
            HStack(spacing: 14) {
                Image(systemName: tunnel.isOn ? "checkmark.shield.fill" : "shield.slash")
                    .font(.system(size: 34))
                    .foregroundStyle(tunnel.isOn ? .green : .secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text(tunnel.isOn ? "Protected" : "Protection off").font(.headline)
                    Text(protectionDetail).font(.subheadline).foregroundStyle(.secondary)
                }
            }
            .padding(.vertical, 6)
            Button(tunnel.isOn ? "Turn off" : "Turn on") {
                Task {
                    if tunnel.isOn { await tunnel.stop() } else { await tunnel.start() }
                }
            }
            .disabled(tunnel.busy)
            if let error = tunnel.lastError {
                Text(error).font(.footnote).foregroundStyle(.red)
            }
        }
    }

    private var protectionDetail: String {
        switch tunnel.status {
        case .connected:
            if !lists.compiled { return "On, but the filter lists are not downloaded yet" }
            return (tunnel.stats?.httpsFilteringActive ?? false)
                ? "Blocking ad and tracker domains and requests"
                : "Blocking ad and tracker domains"
        case .connecting, .reasserting: return "Starting"
        case .disconnecting: return "Stopping"
        default: return "Ads and trackers are not blocked"
        }
    }

    /// Downloads the lists when they are missing (offline at first launch, a failed first
    /// attempt) or more than a day old, then hands them to the tunnel. Not awaited: the
    /// download belongs to AppModel, so switching tabs or a tunnel status change does not
    /// cancel it.
    private func updateListsIfMissing() {
        AppModel.shared.startRefreshIfNeeded()
    }

    /// HTTPS filtering with an untrusted root breaks every intercepted site, so it is turned
    /// off whenever trust is missing (the toggle's onChange saves and restarts the tunnel).
    /// Only after a real trust check: at launch the scene can become active before the
    /// certificate is loaded, and "not checked yet" must not turn the setting off.
    private func enforceTrust() {
        guard certificate.evaluated else { return }
        if httpsFiltering, !certificate.trusted { httpsFiltering = false }
    }

    private func applyHttpsFiltering(_ enabled: Bool) {
        var config = CoreConfig.load()
        guard config.mitmEnabled != enabled else { return }
        config.mitmEnabled = enabled
        do {
            try config.save()
        } catch {
            tunnel.showError("HTTPS filtering: \(error.localizedDescription)")
            httpsFiltering = !enabled
            return
        }
        Task {
            await tunnel.restartIfRunning(clearingLearnedPins: enabled)
            if enabled, tunnel.status == .connected,
               await TunnelController.httpsBrokenByUntrustedCertificate() {
                httpsFiltering = false
                tunnel.showError("HTTPS filtering was turned off: iOS does not trust the Tollgate certificate for websites yet. Turn on full trust in Settings, General, About, Certificate Trust Settings.")
            }
        }
    }

    // MARK: - Setup

    private var setupSection: some View {
        Section {
            listsRow
            certificateRows
            Toggle("HTTPS filtering", isOn: $httpsFiltering)
                // Can always be turned off; turning on needs a trusted root and compiled lists.
                .disabled(!httpsFiltering && (!certificate.trusted || !lists.compiled))
                .onChange(of: httpsFiltering) { _, enabled in applyHttpsFiltering(enabled) }
                .onChange(of: certificate.trusted) { _, _ in enforceTrust() }
        } header: {
            Text("Setup")
        } footer: {
            Text("Domain blocking works as soon as protection is on. HTTPS filtering also blocks individual ad requests on sites that serve ads from their own domains; it needs the Tollgate certificate to be installed and trusted. Apple services, banking apps and apps that pin certificates are never filtered.")
        }
    }

    private var listsRow: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Label("Filter lists", systemImage: "list.bullet.rectangle")
                Spacer()
                Button("Update") {
                    Task {
                        if await lists.update() { await tunnel.listsUpdated() }
                    }
                }
                .disabled(lists.isBusy)
            }
            Text(listsDetail).font(.footnote).foregroundStyle(.secondary)
        }
    }

    private var listsDetail: String {
        switch lists.state {
        case let .downloading(done, total): return "Downloading \(done + 1) of \(total)"
        case .compiling: return "Compiling"
        case let .failed(message): return "Update failed: \(message)"
        case .idle:
            if let report = lists.lastReport {
                return "\(report.networkRules.formatted()) request rules, \(report.domainEntries.formatted()) blocked domains"
            }
            if let date = lists.lastUpdated {
                return "Updated \(date.formatted(date: .abbreviated, time: .shortened))"
            }
            return lists.compiled ? "Installed" : "Not downloaded yet"
        }
    }

    @ViewBuilder
    private var certificateRows: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Label("Certificate", systemImage: certificate.trusted ? "checkmark.seal.fill" : "seal")
                Spacer()
                Text(certificate.trusted ? "Trusted" : "Not trusted yet")
                    .foregroundStyle(certificate.trusted ? .green : .orange)
            }
            if !certificate.trusted {
                Text("1. Tap Install profile and allow the download in Safari. If another browser opens, use Share profile instead, save it to Files and open it there.\n2. Open Settings, tap Profile Downloaded, then Install.\n3. Open Settings, General, About, Certificate Trust Settings and turn on Tollgate Root CA.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
            if let error = certificate.lastError {
                Text(error).font(.footnote).foregroundStyle(.red)
            }
        }
        if !certificate.trusted {
            Button("Install profile") { certificate.installProfile() }
            if let url = certificate.profileURL {
                ShareLink("Share profile instead", item: url)
            }
            Button("Check trust again") {
                Task {
                    await certificate.refreshTrust()
                    enforceTrust()
                }
            }
        }
    }

    // MARK: - Activity

    private var activitySection: some View {
        Section("Activity") {
            let stats = tunnel.stats ?? TunnelStats()
            LabeledContent("Domains blocked", value: stats.dnsBlocked.formatted())
            LabeledContent("Requests blocked", value: stats.httpBlocked.formatted())
            LabeledContent("DNS queries", value: stats.dnsQueries.formatted())
            LabeledContent("Connections filtered", value: stats.connectionsIntercepted.formatted())
            LabeledContent("Connections passed through", value: stats.connectionsPassthrough.formatted())
        }
    }

    // MARK: - Diagnostics

    /// "<CI run number> (<short commit>)", or "1 (local)" for a local build.
    private static var buildLabel: String {
        let info = Bundle.main.infoDictionary
        let number = info?["CFBundleVersion"] as? String ?? "?"
        let commit = info?["TollgateBuildCommit"] as? String ?? "?"
        return "\(number) (\(commit))"
    }

    private var diagnosticsSection: some View {
        Section("Diagnostics") {
            LabeledContent("Core version", value: coreVersion())
            LabeledContent("Build", value: Self.buildLabel)
            if let stats = tunnel.stats {
                LabeledContent("Tunnel memory available",
                               value: ByteCountFormatter.string(fromByteCount: Int64(stats.availableMemoryBytes), countStyle: .memory))
                LabeledContent("DNS failures", value: stats.dnsFailed.formatted())
                LabeledContent("Certificate rejections", value: stats.tlsClientRejections.formatted())
            }
            if let heartbeat {
                LabeledContent("Tunnel started", value: heartbeat.startedAt.formatted(date: .omitted, time: .standard))
            }
            Button("Ping tunnel") { Task { await tunnel.sendForDisplay(.ping) } }
                .disabled(tunnel.status != .connected)
            Button("Probe memory (kills the tunnel)", role: .destructive) {
                Task { await tunnel.sendForDisplay(.probeMemory) }
            }
            .disabled(tunnel.status != .connected)
            if let reply = tunnel.lastReply {
                LabeledContent("Reply", value: reply)
            }
            Button("Refresh") {
                heartbeat = TunnelHeartbeat.read()
                Task { await tunnel.refreshStats() }
            }
        }
    }
}

extension NEVPNStatus {
    var label: String {
        switch self {
        case .invalid: "Not configured"
        case .disconnected: "Off"
        case .connecting: "Starting"
        case .connected: "On"
        case .reasserting: "Reconnecting"
        case .disconnecting: "Stopping"
        @unknown default: "Unknown"
        }
    }
}
