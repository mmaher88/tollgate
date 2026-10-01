import Foundation
import os

/// Downloads the filter lists and compiles them with the Rust core into the shared
/// directory, where the tunnel loads them.
///
/// Every successful download is kept in `core/list-cache/`. A list that fails to download
/// falls back to its cached copy, so one broken list never stops the others, and settings
/// changes (toggles, custom lists, My rules) can be applied without the network.
///
/// A custom list with the same address as an enabled built-in list, feeding the same file,
/// is skipped (see `ListSettings.builtInDuplicate`). A built-in list never downloaded
/// starts from the cached copy of a custom list with its address, if one has any: after an
/// update that makes a list the user had added built in, the first compile does not depend
/// on downloading it, and keeps what the custom copy blocked. A custom list whose content
/// does not match its type (a hosts file added as Request rules, say) is compiled as the
/// type its content has, and that type is saved in lists.json.
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
    /// Lists that could not be downloaded in the last run (a cached copy may have been used),
    /// and custom lists whose type the last run changed to match their content. Kept across
    /// launches, so the reason for a retry backoff stays visible.
    @Published private(set) var warnings: [String] = [] {
        didSet { UserDefaults.standard.set(warnings, forKey: Self.warningsKey) }
    }
    /// Whether compiled lists exist, observable by the UI.
    @Published private(set) var compiled = FilterLists.compiled
    /// Settings changed since the last successful compile; applied at the next opportunity.
    /// Also set at the first launch after an app update, whose compiled files another
    /// build wrote (see `appBuildChanged`), perhaps from other built-in lists (see
    /// `builtInListsChanged`).
    @Published private(set) var pendingSettingsChange: Bool
    /// Counts the times this updater rewrote lists.json itself (to correct a custom list's
    /// type), so a view that keeps a copy of the settings can load them again.
    @Published private(set) var settingsRevision = 0

    private let log = Logger(subsystem: "dev.tollgate.app", category: "lists")
    private static let lastUpdatedKey = "lists.lastUpdated"
    private static let lastAttemptKey = "lists.lastAttempt"
    private static let lastAttemptPartialKey = "lists.lastAttemptPartial"
    private static let warningsKey = "lists.warnings"
    private static let pendingKey = "lists.pendingSettingsChange"
    private static let knownDefaultsKey = "lists.knownDefaults"
    private static let knownBuildKey = "lists.knownBuild"

    /// Lists older than this are refreshed on launch, on returning to the foreground and by
    /// the background refresh task.
    nonisolated static let maxAge: TimeInterval = 24 * 60 * 60
    /// Retry delay after a full update that could not download some lists.
    nonisolated static let partialRetry: TimeInterval = 60 * 60
    /// Retry delay while no compiled lists exist (offline at first launch).
    static let missingRetry: TimeInterval = 15 * 60
    /// A last attempt this far in the future means the clock was set back (for example
    /// after moving the date forward to test updates); the lists then count as stale.
    static let clockTolerance: TimeInterval = 5 * 60
    /// The soonest the background refresh is asked for.
    static let minimumRefreshDelay: TimeInterval = 60

    init() {
        let defaults = UserDefaults.standard
        let updated = defaults.object(forKey: Self.lastUpdatedKey) as? Date
        // Both checks run, since each records what it compares with next time.
        let buildChanged = Self.appBuildChanged()
        let listsChanged = Self.builtInListsChanged()
        if buildChanged || listsChanged { defaults.set(true, forKey: Self.pendingKey) }
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

    /// When the background refresh task should next run: when `needsWork` becomes true,
    /// with the same backoff as `isStale` (15 minutes while nothing is compiled, an hour
    /// after a partial attempt, otherwise a day), and at least a minute from now.
    var nextRefreshDate: Date {
        let now = Date()
        let soonest = now.addingTimeInterval(Self.minimumRefreshDelay)
        guard let lastAttempt, !pendingSettingsChange,
              now.timeIntervalSince(lastAttempt) >= -Self.clockTolerance
        else { return soonest }
        let delay = !compiled ? Self.missingRetry
            : lastAttemptPartial ? Self.partialRetry
            : Self.maxAge
        return max(lastAttempt.addingTimeInterval(delay), soonest)
    }

    var isBusy: Bool {
        switch state {
        case .downloading, .compiling: true
        case .idle, .failed: false
        }
    }

    /// Whether another build of the app ran before this one, and records this build either
    /// way. The compiled files were then written by that build's core, whose compiler may
    /// have read the lists differently (skipped rules this one reads, or left out a section
    /// domains.bin now has), so they are compiled again like after a settings change: at
    /// the next opportunity (launch, foreground or the background refresh), from the cached
    /// copies. The tunnel uses the old files until then. Keyed on the build number
    /// (CFBundleVersion, which CI sets to its run number), so a change to the compiler
    /// needs no version bumped by hand to reach existing installs; the cost is one compile
    /// from the cached copies after each update. Any other build counts, an older one
    /// included, since an older core may not read what a newer one wrote. Local builds all
    /// have build number 1, so for them only `builtInListsChanged` and the daily update
    /// apply.
    ///
    /// Installs from before the build was recorded have none. If they have compiled lists,
    /// an older build wrote them, so they count as changed. A fresh install has nothing
    /// compiled, and its first update downloads every list anyway.
    private static func appBuildChanged() -> Bool {
        let defaults = UserDefaults.standard
        let current = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? ""
        let known = defaults.string(forKey: knownBuildKey)
        defaults.set(current, forKey: knownBuildKey)
        guard let known else { return FilterLists.compiled }
        return known != current
    }

    /// Whether this version of the app ships other built-in lists than the version that ran
    /// before it, and records the current ids either way. The compiled files then hold the
    /// old set, so the change is applied like a settings change: at the next opportunity
    /// (launch, foreground or the background refresh), from the cached copies, downloading
    /// only lists never downloaded before. Without this a new built-in list, which is on for
    /// existing installs (`ListSettings` stores only the lists switched off), would wait for
    /// the next daily update. A new list that fails to download is retried like any other:
    /// the run records a partial attempt, so a full update follows within an hour.
    ///
    /// Installs from before the ids were recorded have none. If they have compiled lists,
    /// those predate at least the StevenBlack list, so they count as changed. A fresh
    /// install has nothing compiled, and its first update downloads every list anyway.
    private static func builtInListsChanged() -> Bool {
        let defaults = UserDefaults.standard
        let current = FilterLists.defaults.map(\.id)
        let known = defaults.stringArray(forKey: knownDefaultsKey)
        defaults.set(current, forKey: knownDefaultsKey)
        guard let known else { return FilterLists.compiled }
        return Set(current) != Set(known)
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
        /// Whether the core leaves out the list's blocks of hosts of sensitive services and
        /// banks (`FilterList.exemptSensitiveHosts`); false for custom lists.
        var exemptSensitiveHosts = false
        /// The custom list this source comes from, whose type is checked against its
        /// content; nil for a built-in list.
        var custom: CustomList? = nil
    }

    /// A custom list compiled as another type than the one lists.json gives it.
    private struct KindCorrection {
        let list: CustomList
        let kind: CustomList.Kind
    }

    private func run(refresh: Bool, deadline: Date?) async -> Bool {
        guard !isBusy else { return false }
        // Every entry point (launch and foreground refresh, Update, Apply changes now, My
        // rules) can be followed by the user leaving the app; without this iOS suspends it
        // mid-download and the list in flight fails with a lost connection.
        let backgroundTime = BackgroundTime(name: "lists")
        defer { backgroundTime.end() }
        guard let directory = AppGroup.coreDirectory else {
            state = .failed("App Group container unavailable")
            return false
        }
        var settings = ListSettings.load()
        var problems: [String] = []
        var sources = FilterLists.defaults.filter(settings.isEnabled).map {
            Source(cacheKey: $0.id, name: $0.name, url: $0.url, format: $0.format, target: $0.target,
                   exemptSensitiveHosts: $0.exemptSensitiveHosts)
        }
        for list in settings.custom {
            // Settings shows the reason on the list's row.
            if let builtIn = settings.builtInDuplicate(of: list) {
                log.info("\(list.name, privacy: .public) skipped: same address as \(builtIn.name, privacy: .public)")
                continue
            }
            guard let url = URL(string: list.url), url.scheme?.lowercased() == "https", url.host != nil else {
                problems.append("\(list.name): only https:// lists are supported")
                continue
            }
            sources.append(Source(cacheKey: "custom-" + list.id, name: list.name, url: url,
                                  format: list.kind.format, target: list.kind.target, custom: list))
        }

        let cache = directory.appendingPathComponent("list-cache", isDirectory: true)
        try? FileManager.default.createDirectory(at: cache, withIntermediateDirectories: true)
        seedBuiltInCaches(settings: settings, cache: cache)
        var inputs: [ListInput] = []
        var corrections: [KindCorrection] = []
        var allDownloaded = true
        /// A list that could not be downloaded and has no cached copy, so it is left out.
        var missingList = false
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
                    if text == nil { missingList = true }
                    problems.append(text == nil
                        ? "\(source.name): \(error.localizedDescription)"
                        : "\(source.name): using the last downloaded copy (\(error.localizedDescription))")
                }
            }
            guard let listText = text else { continue }
            var format = source.format
            var target = source.target
            if let list = source.custom, let detected = await Self.detectFormat(listText) {
                let kind = list.kind.corrected(for: detected)
                if kind != list.kind {
                    corrections.append(KindCorrection(list: list, kind: kind))
                    let content = detected == .hosts ? "a hosts file" : "written in adblock syntax"
                    problems.append("\(list.name) is \(content), so its type was changed from \(list.kind.label) to \(kind.label).")
                    format = kind.format
                    target = kind.target
                }
            }
            // The core refuses the exemption on a request list, which would fail the compile.
            inputs.append(ListInput(name: source.name, text: listText, format: format, target: target,
                                    exemptSensitiveHosts: source.exemptSensitiveHosts && target == .dns))
        }
        if !sources.isEmpty, inputs.isEmpty {
            warnings = problems
            if refresh || missingList { recordAttempt(partial: true) }
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
            } else if missingList {
                // A newly added list could not be downloaded (Apply changes now): show the
                // partial status and retry with a full update in an hour, not in a day.
                recordAttempt(partial: true)
            }
            // Saved only now, so a run that stops before its compile leaves lists.json alone
            // and the next run finds (and reports) the same corrections.
            if !corrections.isEmpty { settings = saveCorrections(corrections, loaded: settings) }
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

    /// Gives each enabled built-in list that has no cached copy the cached copy of a custom
    /// list with the same address, of any type (the cached text is the list as downloaded),
    /// when one has it. That custom list was added before the list was built in, and is now
    /// skipped as a duplicate or compiled beside it; its copy lets `applySettings()` compile
    /// the built-in list without downloading it, and `update()` fall back to it when the
    /// download fails, instead of leaving the list out. The next successful download
    /// replaces it.
    private func seedBuiltInCaches(settings: ListSettings, cache: URL) {
        let fileManager = FileManager.default
        for builtIn in FilterLists.defaults where settings.isEnabled(builtIn) {
            let own = cache.appendingPathComponent(builtIn.id + ".txt")
            if fileManager.fileExists(atPath: own.path) { continue }
            for list in settings.custom where FilterLists.sameAddress(builtIn.url, list.url) {
                let copy = cache.appendingPathComponent("custom-" + list.id + ".txt")
                guard fileManager.fileExists(atPath: copy.path) else { continue }
                do {
                    try fileManager.copyItem(at: copy, to: own)
                    log.info("\(builtIn.name, privacy: .public) starts from the cached copy of \(list.name, privacy: .public)")
                } catch {
                    log.error("copying the cached copy of \(list.name, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
                }
                break
            }
        }
    }

    /// How `text` is written, by the core's detector; nil when its lines give no verdict.
    /// Off the main actor, since the detector reads the whole list.
    private static func detectFormat(_ text: String) async -> ListFormat? {
        await Task.detached(priority: .userInitiated) { detectListFormat(text: text) }.value
    }

    /// Saves the corrected types in lists.json, so the rows in Settings show them and the
    /// next run has nothing to correct. A list is changed only while it still has the type
    /// and address this run compiled it with: a type the user picked meanwhile wins.
    /// Returns the settings the compiled files now stand for: `loaded` with the
    /// corrections when lists.json still held `loaded`; otherwise the user changed
    /// something meanwhile, and `loaded` is returned as it was, so the check after the
    /// compile keeps that change pending.
    private func saveCorrections(_ corrections: [KindCorrection], loaded: ListSettings) -> ListSettings {
        var current = ListSettings.load()
        let unchanged = current == loaded
        for correction in corrections {
            guard let index = current.custom.firstIndex(where: { $0.id == correction.list.id }),
                  current.custom[index].kind == correction.list.kind,
                  current.custom[index].url == correction.list.url
            else { continue }
            current.custom[index].kind = correction.kind
        }
        do {
            try current.save()
        } catch {
            log.error("saving corrected list types failed: \(error.localizedDescription, privacy: .public)")
            return loaded
        }
        settingsRevision += 1
        return unchanged ? current : loaded
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

    /// Downloads `url`, retrying once after a lost connection or a timeout, which is what
    /// a suspension (the background time ran out, or the app was suspended before it got
    /// any) leaves behind. Other failures, such as no network or an HTTP error, are not
    /// retried, so the cached copy is used at once.
    private static func download(_ url: URL) async throws -> String {
        do {
            return try await fetch(url)
        } catch let error as URLError where error.code == .networkConnectionLost || error.code == .timedOut {
            if Task.isCancelled { throw error }
            return try await fetch(url)
        }
    }

    private static func fetch(_ url: URL) async throws -> String {
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
