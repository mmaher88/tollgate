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
    @Published private(set) var lastUpdated: Date?
    /// Lists that could not be downloaded in the last run (a cached copy may have been used).
    @Published private(set) var warnings: [String] = []
    /// Whether compiled lists exist, observable by the UI.
    @Published private(set) var compiled = FilterLists.compiled
    /// Settings changed since the last successful compile; applied at the next opportunity.
    @Published private(set) var pendingSettingsChange: Bool

    private let log = Logger(subsystem: "dev.tollgate.app", category: "lists")
    private static let lastUpdatedKey = "lists.lastUpdated"
    private static let pendingKey = "lists.pendingSettingsChange"

    /// Lists older than this are refreshed on launch, on returning to the foreground and by
    /// the background refresh task.
    static let maxAge: TimeInterval = 24 * 60 * 60

    init() {
        lastUpdated = UserDefaults.standard.object(forKey: Self.lastUpdatedKey) as? Date
        pendingSettingsChange = UserDefaults.standard.bool(forKey: Self.pendingKey)
    }

    var isStale: Bool {
        guard compiled, let lastUpdated else { return true }
        return Date().timeIntervalSince(lastUpdated) > Self.maxAge
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
            if refresh && allDownloaded {
                let now = Date()
                lastUpdated = now
                UserDefaults.standard.set(now, forKey: Self.lastUpdatedKey)
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
            state = .failed("Compile: \(error.localizedDescription)")
            return false
        }
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
