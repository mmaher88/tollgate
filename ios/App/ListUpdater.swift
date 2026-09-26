import Foundation
import os

/// Downloads the filter lists and compiles them with the Rust core into the shared
/// directory, where the tunnel loads them.
///
/// Every successful download is kept in `core/list-cache/`. A list that fails to download
/// falls back to its cached copy, so one broken list never stops the others, and settings
/// changes (toggles, custom lists, My rules) can be applied without the network.
@MainActor
final class ListUpdater: ObservableObject {
    enum State: Equatable {
        case idle
        case downloading(done: Int, total: Int)
        case compiling
        case failed(String)
    }

    @Published private(set) var state: State = .idle
    @Published private(set) var lastReport: CompileReport?
    /// When every enabled list was last downloaded and compiled.
    @Published private(set) var lastUpdated: Date?
    /// When the last full update (downloading every list) ran, whatever its outcome.
    /// Staleness is based on this, so a list that keeps failing does not make every
    /// foreground and every reconnect download everything again.
    @Published private(set) var lastAttempt: Date?
    /// The last full update could not download every list (or failed altogether).
    @Published private(set) var lastAttemptPartial = false
    /// Lists that could not be downloaded in the last run (a cached copy may have been used).
    /// Kept across launches, so the reason for a retry backoff stays visible.
    @Published private(set) var warnings: [String] = [] {
        didSet { UserDefaults.standard.set(warnings, forKey: Self.warningsKey) }
    }
    /// Whether compiled lists exist, observable by the UI.
    @Published private(set) var compiled = FilterLists.compiled
    /// Settings changed since the last successful compile; applied at the next opportunity.
    @Published private(set) var pendingSettingsChange: Bool

    private let log = Logger(subsystem: "dev.tollgate.app", category: "lists")
    private static let lastUpdatedKey = "lists.lastUpdated"
    private static let lastAttemptKey = "lists.lastAttempt"
    private static let lastAttemptPartialKey = "lists.lastAttemptPartial"
    private static let warningsKey = "lists.warnings"
    private static let pendingKey = "lists.pendingSettingsChange"

    /// Lists older than this are refreshed on launch, on returning to the foreground and by
    /// the background refresh task.
    nonisolated static let maxAge: TimeInterval = 24 * 60 * 60
    /// Retry delay after a full update that could not download some lists.
    static let partialRetry: TimeInterval = 60 * 60
    /// Retry delay while no compiled lists exist (offline at first launch).
    static let missingRetry: TimeInterval = 15 * 60
    /// A last attempt this far in the future means the clock was set back (for example
    /// after moving the date forward to test updates); the lists then count as stale.
    static let clockTolerance: TimeInterval = 5 * 60

    init() {
        let defaults = UserDefaults.standard
        let updated = defaults.object(forKey: Self.lastUpdatedKey) as? Date
        pendingSettingsChange = defaults.bool(forKey: Self.pendingKey)
        lastUpdated = updated
        // Installs from before attempts were recorded: their last success was an attempt.
        lastAttempt = defaults.object(forKey: Self.lastAttemptKey) as? Date ?? updated
        lastAttemptPartial = defaults.bool(forKey: Self.lastAttemptPartialKey)
        warnings = defaults.stringArray(forKey: Self.warningsKey) ?? []
    }

    /// Whether an automatic full update is due. Based on the last attempt, not the last
    /// success: after a partial or failed attempt it retries after an hour (15 minutes
    /// while nothing is compiled), otherwise after a day. The Update buttons call
    /// `update()` directly and are not held back.
    var isStale: Bool {
        guard let lastAttempt else { return true }
        let age = Date().timeIntervalSince(lastAttempt)
        if age < -Self.clockTolerance { return true }
        if !compiled { return age > Self.missingRetry }
        if lastAttemptPartial { return age > Self.partialRetry }
        return age > Self.maxAge
    }

    var needsWork: Bool { isStale || pendingSettingsChange }

    var isBusy: Bool {
        switch state {
        case .downloading, .compiling: true
        case .idle, .failed: false
        }
    }

    /// Records that list settings changed; `applySettings()` or the next refresh compiles them.
    func settingsChanged() {
        pendingSettingsChange = true
        UserDefaults.standard.set(true, forKey: Self.pendingKey)
    }

    /// Downloads every enabled list (falling back to cached copies) and compiles them.
    @discardableResult
    func update(deadline: Date? = nil) async -> Bool {
        await run(refresh: true, deadline: deadline)
    }

    /// Compiles the current settings from cached copies, downloading only lists that have
    /// never been downloaded. Used after toggles, custom list and My rules edits.
    @discardableResult
    func applySettings() async -> Bool {
        await run(refresh: false, deadline: nil)
    }

    private struct Source {
        let cacheKey: String
        let name: String
        let url: URL
        let format: ListFormat
        let target: ListTarget
    }

    private func run(refresh: Bool, deadline: Date?) async -> Bool {
        guard !isBusy else { return false }
        guard let directory = AppGroup.coreDirectory else {
            state = .failed("App Group container unavailable")
            return false
        }
        let settings = ListSettings.load()
        var problems: [String] = []
        var sources = FilterLists.defaults.filter(settings.isEnabled).map {
            Source(cacheKey: $0.id, name: $0.name, url: $0.url, format: $0.format, target: $0.target)
        }
        for list in settings.custom {
            guard let url = URL(string: list.url), url.scheme?.lowercased() == "https", url.host != nil else {
                problems.append("\(list.name): only https:// lists are supported")
                continue
            }
            sources.append(Source(cacheKey: "custom-" + list.id, name: list.name, url: url,
                                  format: list.kind.format, target: list.kind.target))
        }

        let cache = directory.appendingPathComponent("list-cache", isDirectory: true)
        try? FileManager.default.createDirectory(at: cache, withIntermediateDirectories: true)
        var inputs: [ListInput] = []
        var allDownloaded = true
        for (index, source) in sources.enumerated() {
            state = .downloading(done: index, total: sources.count)
            let cached = cache.appendingPathComponent(source.cacheKey + ".txt")
            var text: String?
            if !refresh { text = try? String(contentsOf: cached, encoding: .utf8) }
            if text == nil {
                do {
                    let fresh = try await Self.download(source.url)
                    try? fresh.write(to: cached, atomically: true, encoding: .utf8)
                    text = fresh
                } catch {
                    if Self.isCancellation(error) {
                        log.info("list update cancelled")
                        state = .idle
                        return false
                    }
                    allDownloaded = false
                    log.error("download \(source.name, privacy: .public) failed: \(String(describing: error), privacy: .public)")
                    text = try? String(contentsOf: cached, encoding: .utf8)
                    problems.append(text == nil
                        ? "\(source.name): \(error.localizedDescription)"
                        : "\(source.name): using the last downloaded copy (\(error.localizedDescription))")
                }
            }
            if let text {
                inputs.append(ListInput(name: source.name, text: text, format: source.format, target: source.target))
            }
        }
        if !sources.isEmpty, inputs.isEmpty {
            warnings = problems
            if refresh { recordAttempt(partial: true) }
            state = .failed(problems.first ?? "No list could be downloaded")
            return false
        }

        let myRules = settings.myRules.trimmingCharacters(in: .whitespacesAndNewlines)
        if !myRules.isEmpty {
            // The user's rules block requests and, for ||domain^ rules, DNS names too.
            inputs.append(ListInput(name: "My rules", text: myRules, format: .adblock, target: .url))
            inputs.append(ListInput(name: "My rules (DNS)", text: myRules, format: .adblock, target: .dns))
        }

        // The compile cannot be interrupted, so do not start it when time is up.
        if Task.isCancelled || (deadline.map { Date() > $0 } ?? false) {
            state = .idle
            return false
        }
        state = .compiling
        do {
            let path = directory.path
            let snapshot = inputs
            let report = try await Task.detached(priority: .userInitiated) {
                try compileLists(sources: snapshot, dataDir: path)
            }.value
            lastReport = report
            compiled = true
            warnings = problems
            if refresh {
                recordAttempt(partial: !allDownloaded)
                if allDownloaded {
                    let now = Date()
                    lastUpdated = now
                    UserDefaults.standard.set(now, forKey: Self.lastUpdatedKey)
                }
            }
            if ListSettings.load() == settings {
                pendingSettingsChange = false
                UserDefaults.standard.set(false, forKey: Self.pendingKey)
            }
            log.info("lists compiled: \(report.networkRules, privacy: .public) rules, \(report.domainEntries, privacy: .public) domains")
            state = .idle
            return true
        } catch {
            log.error("list compile failed: \(String(describing: error), privacy: .public)")
            if refresh { recordAttempt(partial: true) }
            state = .failed("Compile: \(error.localizedDescription)")
            return false
        }
    }

    private func recordAttempt(partial: Bool) {
        let now = Date()
        lastAttempt = now
        lastAttemptPartial = partial
        UserDefaults.standard.set(now, forKey: Self.lastAttemptKey)
        UserDefaults.standard.set(partial, forKey: Self.lastAttemptPartialKey)
    }

    private static func isCancellation(_ error: Error) -> Bool {
        Task.isCancelled || error is CancellationError || (error as? URLError)?.code == .cancelled
    }

    private static func download(_ url: URL) async throws -> String {
        var request = URLRequest(url: url, timeoutInterval: 60)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        let (data, response) = try await URLSession.shared.data(for: request)
        let code = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else {
            throw URLError(.badServerResponse, userInfo: [
                NSURLErrorFailingURLErrorKey: url,
                NSLocalizedDescriptionKey: "HTTP \(code)",
            ])
        }
        return String(decoding: data, as: UTF8.self)
    }
}
