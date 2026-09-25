import Foundation
import os

/// Downloads the filter lists and compiles them with the Rust core into the shared
/// directory, where the tunnel loads them.
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
    /// Whether compiled lists exist, observable by the UI.
    @Published private(set) var compiled = FilterLists.compiled

    private let log = Logger(subsystem: "dev.tollgate.app", category: "lists")
    private static let lastUpdatedKey = "lists.lastUpdated"

    init() {
        lastUpdated = UserDefaults.standard.object(forKey: Self.lastUpdatedKey) as? Date
    }

    /// Lists older than this are refreshed on launch, on returning to the foreground and by
    /// the background refresh task.
    static let maxAge: TimeInterval = 24 * 60 * 60

    var isStale: Bool {
        guard compiled, let lastUpdated else { return true }
        return Date().timeIntervalSince(lastUpdated) > Self.maxAge
    }

    var isBusy: Bool {
        switch state {
        case .downloading, .compiling: true
        case .idle, .failed: false
        }
    }

    /// Returns true when new lists were compiled.
    @discardableResult
    func update() async -> Bool {
        guard !isBusy else { return false }
        guard let directory = AppGroup.coreDirectory else {
            state = .failed("App Group container unavailable")
            return false
        }
        let settings = ListSettings.load()
        var sources: [(name: String, url: URL, format: ListFormat, target: ListTarget)] =
            FilterLists.defaults.filter(settings.isEnabled).map { ($0.name, $0.url, $0.format, $0.target) }
        for list in settings.custom {
            guard let url = URL(string: list.url), url.scheme == "https" || url.scheme == "http" else {
                state = .failed("\(list.name): not a valid URL")
                return false
            }
            sources.append((list.name, url, list.kind.format, list.kind.target))
        }
        var inputs: [ListInput] = []
        for (index, source) in sources.enumerated() {
            state = .downloading(done: index, total: sources.count)
            do {
                inputs.append(ListInput(
                    name: source.name, text: try await Self.download(source.url),
                    format: source.format, target: source.target))
            } catch {
                log.error("download \(source.name, privacy: .public) failed: \(String(describing: error), privacy: .public)")
                state = .failed("\(source.name): \(error.localizedDescription)")
                return false
            }
        }
        let myRules = settings.myRules.trimmingCharacters(in: .whitespacesAndNewlines)
        if !myRules.isEmpty {
            // The user's rules block requests and, for ||domain^ rules, DNS names too.
            inputs.append(ListInput(name: "My rules", text: myRules, format: .adblock, target: .url))
            inputs.append(ListInput(name: "My rules (DNS)", text: myRules, format: .adblock, target: .dns))
        }
        state = .compiling
        do {
            let path = directory.path
            let sources = inputs
            let report = try await Task.detached(priority: .userInitiated) {
                try compileLists(sources: sources, dataDir: path)
            }.value
            lastReport = report
            let now = Date()
            lastUpdated = now
            compiled = true
            UserDefaults.standard.set(now, forKey: Self.lastUpdatedKey)
            log.info("lists compiled: \(report.networkRules, privacy: .public) rules, \(report.domainEntries, privacy: .public) domains")
            state = .idle
            return true
        } catch {
            log.error("list compile failed: \(String(describing: error), privacy: .public)")
            state = .failed("Compile: \(error.localizedDescription)")
            return false
        }
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
