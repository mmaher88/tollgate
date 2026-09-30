import Foundation

/// The App Group shared by the app and the tunnel extension. The identifier is injected
/// into Info.plist from tooling/config.env when the project is generated.
enum AppGroup {
    static var identifier: String? {
        Bundle.main.object(forInfoDictionaryKey: "TollgateAppGroup") as? String
    }

    static var containerURL: URL? {
        guard let identifier else { return nil }
        return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier)
    }

    /// Directory the Rust core reads and writes: config.json, ca.pem, ca.key, engine.dat,
    /// domains.bin and learned-pins.json. Created on first use.
    static var coreDirectory: URL? {
        guard let base = containerURL else { return nil }
        let directory = base.appendingPathComponent("core", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }
}
