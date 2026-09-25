import Foundation
import os
import UIKit

/// The Tollgate root certificate: created by the Rust core in the shared directory,
/// installed by the user as a configuration profile, then trusted in Settings.
@MainActor
final class CertificateManager: ObservableObject {
    @Published private(set) var info: CaInfo?
    /// True once iOS trusts the root for TLS (full trust enabled in Settings).
    @Published private(set) var trusted = false
    @Published private(set) var lastError: String?
    /// A copy of the profile for the share sheet, written once by `prepare()`.
    @Published private(set) var profileURL: URL?

    private var server: ProfileServer?
    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid
    private let log = Logger(subsystem: "dev.tollgate.app", category: "certificate")

    /// Creates the CA on first use (idempotent) and checks trust.
    func prepare() async {
        guard let directory = AppGroup.coreDirectory else {
            lastError = "App Group container unavailable"
            return
        }
        do {
            info = try generateCa(dataDir: directory.path)
            profileURL = writeProfileFile()
        } catch {
            report(error, context: "certificate")
        }
        await refreshTrust()
    }

    func refreshTrust() async {
        guard info != nil, let directory = AppGroup.coreDirectory else {
            trusted = false
            return
        }
        trusted = await Task.detached(priority: .userInitiated) {
            RootTrust.isTrustedForTLS(coreDirectory: directory)
        }.value
    }

    /// Serves the profile from a short-lived local web server and opens it in Safari, the
    /// only place iOS accepts a configuration profile download from.
    func installProfile() {
        guard let directory = AppGroup.coreDirectory else { return }
        finishServing() // a repeated tap replaces the previous server and background task
        do {
            let profile = try caMobileconfig(dataDir: directory.path)
            let server = try ProfileServer(body: profile)
            self.server = server
            // Safari takes the foreground; keep the server alive long enough to be fetched.
            backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "profile") { [weak self] in
                MainActor.assumeIsolated { self?.finishServing() }
            }
            server.start { [weak self] url in
                Task { @MainActor in
                    guard let self, self.server === server else { return }
                    guard let url else {
                        self.lastError = "Could not start the local profile server"
                        self.finishServing()
                        return
                    }
                    self.log.info("serving profile at \(url.absoluteString, privacy: .public)")
                    await Self.openInSafari(url)
                    try? await Task.sleep(nanoseconds: 60_000_000_000)
                    if self.server === server { self.finishServing() }
                }
            }
        } catch {
            report(error, context: "profile")
        }
    }

    /// `open(_:)` sends http URLs to the default browser, which may not accept profile
    /// downloads; the x-safari scheme forces Safari, with the default browser as fallback.
    private static func openInSafari(_ url: URL) async {
        if let safari = URL(string: "x-safari-" + url.absoluteString),
           await UIApplication.shared.open(safari) {
            return
        }
        _ = await UIApplication.shared.open(url)
    }

    /// Writes the profile for the share sheet, the fallback when Safari does not offer to
    /// download it.
    private func writeProfileFile() -> URL? {
        guard let directory = AppGroup.coreDirectory,
              let profile = try? caMobileconfig(dataDir: directory.path) else { return nil }
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("Tollgate.mobileconfig")
        do {
            try profile.write(to: url, options: .atomic)
            return url
        } catch {
            report(error, context: "profile file")
            return nil
        }
    }

    private func finishServing() {
        server?.stop()
        server = nil
        if backgroundTask != .invalid {
            UIApplication.shared.endBackgroundTask(backgroundTask)
            backgroundTask = .invalid
        }
    }

    private func report(_ error: Error, context: String) {
        log.error("\(context, privacy: .public) failed: \(String(describing: error), privacy: .public)")
        lastError = "\(context): \(error.localizedDescription)"
    }
}
