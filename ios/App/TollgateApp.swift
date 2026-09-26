import BackgroundTasks
import SwiftUI

/// The app's long-lived objects, shared by the UI and the background refresh task.
@MainActor
final class AppModel {
    static let shared = AppModel()

    let tunnel = TunnelController()
    let lists = ListUpdater()
    let certificate = CertificateManager()

    /// The refresh in flight, shared by every caller.
    private var refreshTask: Task<Bool, Never>?

    /// Starts refreshing stale or missing lists, or compiling pending settings changes,
    /// then hands the result to the tunnel. Returns the refresh in flight (a new one or the
    /// one already running), or nil when there is nothing to do. The work runs in its own
    /// task, so views going away or the tunnel status changing do not cancel a download;
    /// callers that want to cancel it (the background task) cancel the returned task. A
    /// deadline keeps the uninterruptible compile from starting when a background task is
    /// about to run out of time.
    @discardableResult
    func startRefreshIfNeeded(deadline: Date? = nil) -> Task<Bool, Never>? {
        if let refreshTask { return refreshTask }
        guard lists.needsWork, !lists.isBusy else { return nil }
        let task = Task { @MainActor in
            defer { self.refreshTask = nil }
            if tunnel.status == .invalid { await tunnel.load() }
            let compiled: Bool
            if lists.isStale {
                compiled = await lists.update(deadline: deadline)
            } else {
                compiled = await lists.applySettings()
            }
            if compiled { await tunnel.listsUpdated() }
            return compiled
        }
        refreshTask = task
        return task
    }

    /// The background refresh task's work: waits for the refresh and cancels it when the
    /// background task expires.
    func refreshInBackground(deadline: Date) async {
        guard let task = startRefreshIfNeeded(deadline: deadline) else { return }
        _ = await withTaskCancellationHandler {
            await task.value
        } onCancel: {
            task.cancel()
        }
    }
}

enum ListRefresh {
    static let identifier = "dev.tollgate.lists-refresh"

    /// Asks iOS to run the refresh task in about a day. Resubmitting replaces the request.
    static func schedule() {
        let request = BGAppRefreshTaskRequest(identifier: identifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: ListUpdater.maxAge)
        try? BGTaskScheduler.shared.submit(request)
    }
}

@main
struct TollgateApp: App {
    @Environment(\.scenePhase) private var scenePhase

    init() {
        setLogger(logger: OSLogCoreLogger(subsystem: "dev.tollgate.core"), maxLevel: .info)
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(AppModel.shared.tunnel)
                .environmentObject(AppModel.shared.lists)
                .environmentObject(AppModel.shared.certificate)
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { ListRefresh.schedule() }
        }
        .backgroundTask(.appRefresh(ListRefresh.identifier)) {
            ListRefresh.schedule()
            await AppModel.shared.refreshInBackground(deadline: Date().addingTimeInterval(20))
        }
    }
}

struct RootView: View {
    var body: some View {
        TabView {
            ContentView()
                .tabItem { Label("Home", systemImage: "shield.lefthalf.filled") }
            BlockLogView()
                .tabItem { Label("Activity", systemImage: "list.bullet.rectangle") }
            SettingsView()
                .tabItem { Label("Settings", systemImage: "gearshape") }
        }
    }
}
