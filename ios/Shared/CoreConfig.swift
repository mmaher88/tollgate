import Foundation

/// The part of the Rust core's configuration the app edits. Keys that are not written here
/// take the core's defaults (DoH upstreams, connection limits).
struct CoreConfig: Codable, Equatable {
    /// HTTPS filtering. Stays off until the user has installed and trusted the certificate.
    var mitmEnabled = false

    enum CodingKeys: String, CodingKey {
        case mitmEnabled = "mitm_enabled"
    }

    static let fileName = "config.json"

    static var fileURL: URL? {
        AppGroup.coreDirectory?.appendingPathComponent(fileName)
    }

    static func load() -> CoreConfig {
        guard let url = fileURL, let data = try? Data(contentsOf: url),
              let config = try? JSONDecoder().decode(CoreConfig.self, from: data)
        else { return CoreConfig() }
        return config
    }

    func save() throws {
        guard let url = Self.fileURL else { throw CocoaError(.fileNoSuchFile) }
        try JSONEncoder().encode(self).write(to: url, options: .atomic)
    }

    /// The JSON the tunnel hands to `Engine(configJson:dataDir:)`.
    static func json() -> String {
        guard let data = try? JSONEncoder().encode(load()) else { return "{}" }
        return String(decoding: data, as: UTF8.self)
    }
}
