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

    private let log = Logger(subsystem: "dev.tollgate.app", category: "lists")
    private static let lastUpdatedKey = "lists.lastUpdated"

    init() {
        lastUpdated = UserDefaults.standard.object(forKey: Self.lastUpdatedKey) as? Date
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
        let lists = FilterLists.defaults
        var inputs: [ListInput] = []
        do {
            for (index, list) in lists.enumerated() {
                state = .downloading(done: index, total: lists.count)
                inputs.append(ListInput(
                    name: list.name, text: try await Self.download(list.url),
                    format: list.format, target: list.target))
            }
            state = .compiling
            let path = directory.path
            let sources = inputs
            let report = try await Task.detached(priority: .userInitiated) {
                try compileLists(sources: sources, dataDir: path)
            }.value
            lastReport = report
            let now = Date()
            lastUpdated = now
            UserDefaults.standard.set(now, forKey: Self.lastUpdatedKey)
            log.info("lists compiled: \(report.networkRules, privacy: .public) rules, \(report.domainEntries, privacy: .public) domains")
            state = .idle
            return true
        } catch {
            log.error("list update failed: \(String(describing: error), privacy: .public)")
            state = .failed(String(describing: error))
            return false
        }
    }

    private static func download(_ url: URL) async throws -> String {
        var request = URLRequest(url: url, timeoutInterval: 60)
        request.cachePolicy = .reloadIgnoringLocalCacheData
        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw URLError(.badServerResponse, userInfo: [NSURLErrorFailingURLErrorKey: url])
        }
        return String(decoding: data, as: UTF8.self)
    }
}
