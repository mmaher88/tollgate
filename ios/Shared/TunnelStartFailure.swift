import Foundation

/// Why the tunnel last failed to start. The tunnel writes it to the App Group before it
/// reports the failure and removes it once a start succeeds; the app shows it, since the
/// error the tunnel completes `startTunnel` with may not reach the app intact.
enum TunnelStartFailure {
    static let fileName = "last-start-error.txt"

    static var fileURL: URL? {
        AppGroup.coreDirectory?.appendingPathComponent(fileName)
    }

    /// Called by the tunnel.
    static func record(_ reason: String) {
        guard let url = fileURL else { return }
        try? Data(reason.utf8).write(to: url, options: .atomic)
    }

    /// Called by the tunnel after a successful start.
    static func clear() {
        guard let url = fileURL else { return }
        try? FileManager.default.removeItem(at: url)
    }

    /// The recorded reason, removed so it is shown once. Called by the app.
    static func take() -> String? {
        guard let url = fileURL, let data = try? Data(contentsOf: url) else { return nil }
        try? FileManager.default.removeItem(at: url)
        let reason = String(decoding: data, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return reason.isEmpty ? nil : reason
    }
}
