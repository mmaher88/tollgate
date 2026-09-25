import BackgroundTasks
import SwiftUI

/// The app's long-lived objects, shared by the UI and the background refresh task.
@MainActor
final class AppModel {
    static let shared = AppModel()

    let tunnel = TunnelController()
    let lists = ListUpdater()
    let certificate = CertificateManager()

    /// Refreshes stale or missing lists, or compiles pending settings changes, then hands
    /// the result to the tunnel. A deadline keeps the uninterruptible compile from starting
    /// when a background task is about to run out of time.
    func refreshListsIfNeeded(deadline: Date? = nil) async {
        guard lists.needsWork, !lists.isBusy else { return }
        if tunnel.status == .invalid { await tunnel.load() }
        let compiled: Bool
        if lists.isStale {
            compiled = await lists.update(deadline: deadline)
        } else {
            compiled = await lists.applySettings()
        }
        if compiled { await tunnel.listsUpdated() }
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
            await AppModel.shared.refreshListsIfNeeded(deadline: Date().addingTimeInterval(20))
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
