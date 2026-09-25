/// Messages the app sends to the tunnel through `sendProviderMessage`, encoded as UTF-8.
enum TunnelCommand: String {
    /// Tunnel replies with "pong <core version>".
    case ping
    /// Tunnel replies with a JSON-encoded `TunnelStats`.
    case stats
    /// Tunnel reloads engine.dat and domains.bin after the app recompiled the lists; replies
    /// "ok" or the error text.
    case reloadLists = "reload-lists"
    /// Experiment E3: tunnel allocates memory until jetsam kills it.
    case probeMemory = "probe-memory"
}
