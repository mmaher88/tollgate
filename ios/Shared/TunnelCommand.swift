/// Messages the app sends to the tunnel through `sendProviderMessage`, encoded as UTF-8.
enum TunnelCommand: String {
    /// Tunnel replies with "pong <core version>".
    case ping
    /// Experiment E3: tunnel allocates memory until jetsam kills it.
    case probeMemory = "probe-memory"
}
