import Foundation

/// Messages the app sends to the tunnel through `sendProviderMessage`: the command name in
/// UTF-8, optionally followed by a newline and a JSON payload.
enum TunnelCommand: String {
    /// Tunnel replies with "pong <core version>".
    case ping
    /// Tunnel replies with a JSON-encoded `TunnelStats`.
    case stats
    /// Tunnel reloads engine.dat and domains.bin after the app recompiled the lists; replies
    /// "ok" or the error text.
    case reloadLists = "reload-lists"
    /// Tunnel replies with a JSON array of `TunnelEvent`, newest first.
    case events
    /// Tunnel empties its event log; replies "ok".
    case clearEvents = "clear-events"
    /// Tunnel replies with a JSON array of `PinEntry`.
    case pins
    /// Payload: a JSON array of hosts. Tunnel forgets their learned pins and replies with
    /// the number forgotten.
    case forgetPins = "forget-pins"
    /// Experiment E3: tunnel allocates memory until jetsam kills it.
    case probeMemory = "probe-memory"
}

struct TunnelMessage {
    let command: TunnelCommand?
    let payload: Data

    static func encode(_ command: TunnelCommand, payload: Data? = nil) -> Data {
        var data = Data(command.rawValue.utf8)
        if let payload {
            data.append(0x0A)
            data.append(payload)
        }
        return data
    }

    init(_ data: Data) {
        if let newline = data.firstIndex(of: 0x0A) {
            command = TunnelCommand(rawValue: String(decoding: data[data.startIndex..<newline], as: UTF8.self))
            payload = Data(data[data.index(after: newline)...])
        } else {
            command = TunnelCommand(rawValue: String(decoding: data, as: UTF8.self))
            payload = Data()
        }
    }
}
