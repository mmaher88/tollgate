import Foundation

/// Counters the tunnel reports to the app. Mirrors the Rust core's `Stats` record plus a
/// few tunnel-side values; sent as JSON because the app and the extension are separate
/// processes.
struct TunnelStats: Codable, Equatable {
    var dnsQueries: UInt64 = 0
    var dnsBlocked: UInt64 = 0
    var dnsCacheHits: UInt64 = 0
    var dnsForwarded: UInt64 = 0
    var dnsFailed: UInt64 = 0
    var packetsDropped: UInt64 = 0
    var httpRequests: UInt64 = 0
    var httpBlocked: UInt64 = 0
    var connectionsIntercepted: UInt64 = 0
    var connectionsPassthrough: UInt64 = 0
    var tlsClientRejections: UInt64 = 0
    var tlsAbandonedAfterHandshake: UInt64 = 0
    var httpsFilteringActive = false
    var availableMemoryBytes = 0
}
