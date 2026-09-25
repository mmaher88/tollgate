import Foundation
import os
import Security
import UIKit

/// The Tollgate root certificate: created by the Rust core in the shared directory,
/// installed by the user as a configuration profile, then trusted in Settings.
@MainActor
final class CertificateManager: ObservableObject {
    @Published private(set) var info: CaInfo?
    @Published private(set) var trusted = false
    @Published private(set) var lastError: String?
    /// A copy of the profile for the share sheet, written once by `prepare()`.
    @Published private(set) var profileURL: URL?

    private var server: ProfileServer?
    private var backgroundTask: UIBackgroundTaskIdentifier = .invalid
    private let log = Logger(subsystem: "dev.tollgate.app", category: "certificate")

    /// Creates the CA on first use (idempotent) and refreshes the trust state.
    func prepare() {
        guard let directory = AppGroup.coreDirectory else {
            lastError = "App Group container unavailable"
            return
        }
        do {
            info = try generateCa(dataDir: directory.path)
            profileURL = writeProfileFile()
            refreshTrust()
        } catch {
            report(error, context: "certificate")
        }
    }

    func refreshTrust() {
        guard let info else {
            trusted = false
            return
        }
        trusted = Self.isTrustedRoot(pem: info.certPem)
    }

    /// Serves the profile from a short-lived local web server and opens it in Safari, the
    /// only place iOS accepts a configuration profile download from.
    func installProfile() {
        guard let directory = AppGroup.coreDirectory else { return }
        do {
            let profile = try caMobileconfig(dataDir: directory.path)
            server?.stop()
            let server = try ProfileServer(body: profile)
            self.server = server
            // Safari takes the foreground; keep the server alive long enough to be fetched.
            backgroundTask = UIApplication.shared.beginBackgroundTask(withName: "profile") { [weak self] in
                MainActor.assumeIsolated { self?.finishServing() }
            }
            server.start { [weak self] url in
                Task { @MainActor in
                    guard let url else {
                        self?.lastError = "Could not start the local profile server"
                        self?.finishServing()
                        return
                    }
                    self?.log.info("serving profile at \(url.absoluteString, privacy: .public)")
                    _ = await UIApplication.shared.open(url)
                    try? await Task.sleep(nanoseconds: 60_000_000_000)
                    self?.finishServing()
                }
            }
        } catch {
            report(error, context: "profile")
        }
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
        lastError = "\(context): \(String(describing: error))"
    }

    /// True when the certificate is a trusted anchor, which for a user-installed root means
    /// full trust is enabled in Settings, General, About, Certificate Trust Settings.
    static func isTrustedRoot(pem: String) -> Bool {
        let base64 = pem
            .components(separatedBy: .newlines)
            .filter { !$0.hasPrefix("-----") }
            .joined()
        guard let der = Data(base64Encoded: base64),
              let certificate = SecCertificateCreateWithData(nil, der as CFData) else { return false }
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certificate, SecPolicyCreateBasicX509(), &trust) == errSecSuccess,
              let trust else { return false }
        return SecTrustEvaluateWithError(trust, nil)
    }
}
