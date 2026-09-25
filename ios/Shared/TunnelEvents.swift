import Foundation

/// A block recorded by the tunnel, sent to the app as JSON.
struct TunnelEvent: Codable, Hashable, Identifiable {
    enum Kind: String, Codable {
        case dns
        case request
    }

    var unixSecs: UInt64
    var kind: Kind
    var host: String
    var url: String?
    var sourceHost: String?

    var id: String { "\(unixSecs)|\(kind.rawValue)|\(host)|\(url ?? "")|\(sourceHost ?? "")" }
    var date: Date { Date(timeIntervalSince1970: TimeInterval(unixSecs)) }
}

/// A host the core learned to pass through because its app rejected the Tollgate
/// certificate (certificate pinning).
struct PinEntry: Codable, Hashable, Identifiable {
    var host: String
    var learnedAt: UInt64

    var id: String { host }
    var date: Date { Date(timeIntervalSince1970: TimeInterval(learnedAt)) }
}
