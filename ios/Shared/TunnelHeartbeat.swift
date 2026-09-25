import Foundation

/// Written by the tunnel on start, read by the app. Proves the App Group container is
/// shared and records what the tunnel saw.
struct TunnelHeartbeat: Codable {
    var startedAt: Date
    var coreVersion: String
    var sha256Probe: String
    var availableMemoryBytes: Int

    static let fileName = "tunnel-heartbeat.json"

    static var fileURL: URL? {
        AppGroup.containerURL?.appendingPathComponent(fileName)
    }

    func write() throws {
        guard let url = Self.fileURL else { throw CocoaError(.fileNoSuchFile) }
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try encoder.encode(self).write(to: url, options: .atomic)
    }

    static func read() -> TunnelHeartbeat? {
        guard let url = fileURL, let data = try? Data(contentsOf: url) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(TunnelHeartbeat.self, from: data)
    }
}
