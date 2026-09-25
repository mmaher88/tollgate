import BackgroundTasks
import SwiftUI

/// The app's long-lived objects, shared by the UI and the background refresh task.
@MainActor
final class AppModel {
    static let shared = AppModel()

    let tunnel = TunnelController()
    let lists = ListUpdater()
    let certificate = CertificateManager()

    /// Updates the lists when they are missing or stale and hands them to the tunnel.
    func refreshListsIfNeeded() async {
        guard lists.isStale, !lists.isBusy else { return }
        if tunnel.status == .invalid { await tunnel.load() }
        if await lists.update() { await tunnel.listsUpdated() }
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
            await AppModel.shared.refreshListsIfNeeded()
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
