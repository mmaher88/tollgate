import Foundation

/// The part of the Rust core's configuration the app edits. Keys that are not written here
/// take the core's defaults (DoH upstreams, connection limits).
struct CoreConfig: Codable, Equatable {
    /// HTTPS filtering. Stays off until the root certificate is trusted for TLS.
    var mitmEnabled = false
    /// Host patterns that are never decrypted (`example.com` or `*.example.com`).
    var passthrough: [String] = []
    /// Host patterns where nothing is blocked.
    var allowlist: [String] = []

    enum CodingKeys: String, CodingKey {
        case mitmEnabled = "mitm_enabled"
        case passthrough
        case allowlist
    }

    init() {}

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mitmEnabled = try container.decodeIfPresent(Bool.self, forKey: .mitmEnabled) ?? false
        passthrough = try container.decodeIfPresent([String].self, forKey: .passthrough) ?? []
        allowlist = try container.decodeIfPresent([String].self, forKey: .allowlist) ?? []
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

    /// The JSON for `Engine(configJson:dataDir:)`. Fails closed: the core's own default for
    /// a missing key is HTTPS filtering on, so the key is always written.
    func json() -> String {
        guard let data = try? JSONEncoder().encode(self) else { return #"{"mitm_enabled":false}"# }
        return String(decoding: data, as: UTF8.self)
    }
}
