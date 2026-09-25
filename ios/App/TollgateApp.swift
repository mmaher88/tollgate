import SwiftUI

@main
struct TollgateApp: App {
    @StateObject private var tunnel = TunnelController()
    @StateObject private var lists = ListUpdater()
    @StateObject private var certificate = CertificateManager()

    init() {
        setLogger(logger: OSLogCoreLogger(subsystem: "dev.tollgate.core"), maxLevel: .info)
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(tunnel)
                .environmentObject(lists)
                .environmentObject(certificate)
        }
    }
}
