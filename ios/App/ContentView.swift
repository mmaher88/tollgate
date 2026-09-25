import NetworkExtension
import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var tunnel: TunnelController
    @State private var heartbeat: TunnelHeartbeat?

    var body: some View {
        NavigationStack {
            List {
                Section("Rust core in the app") {
                    LabeledContent("Version", value: coreVersion())
                    LabeledContent("FFI round trip", value: ping(message: "app"))
                }
                Section("Tunnel") {
                    LabeledContent("Status", value: tunnel.status.label)
                    Button(tunnel.status == .connected ? "Stop" : "Start") {
                        Task {
                            if tunnel.status == .connected {
                                tunnel.stop()
                            } else {
                                await tunnel.start()
                            }
                        }
                    }
                    Button("Ping tunnel") { tunnel.send(.ping) }
                        .disabled(tunnel.status != .connected)
                    Button("Probe memory (kills the tunnel)", role: .destructive) { tunnel.send(.probeMemory) }
                        .disabled(tunnel.status != .connected)
                    if let reply = tunnel.lastReply {
                        LabeledContent("Reply", value: reply)
                    }
                    if let error = tunnel.lastError {
                        Text(error).foregroundStyle(.red)
                    }
                }
                Section("Shared container") {
                    if let heartbeat {
                        LabeledContent("Tunnel started", value: heartbeat.startedAt.formatted(date: .omitted, time: .standard))
                        LabeledContent("Core in tunnel", value: heartbeat.coreVersion)
                        LabeledContent("Memory available", value: ByteCountFormatter.string(fromByteCount: Int64(heartbeat.availableMemoryBytes), countStyle: .memory))
                    } else {
                        Text(AppGroup.containerURL == nil ? "App Group unavailable" : "No heartbeat yet")
                    }
                    Button("Refresh") { heartbeat = TunnelHeartbeat.read() }
                }
            }
            .navigationTitle("Tollgate")
            .task {
                await tunnel.load()
                heartbeat = TunnelHeartbeat.read()
            }
        }
    }
}

extension NEVPNStatus {
    var label: String {
        switch self {
        case .invalid: "Not configured"
        case .disconnected: "Off"
        case .connecting: "Starting"
        case .connected: "On"
        case .reasserting: "Reconnecting"
        case .disconnecting: "Stopping"
        @unknown default: "Unknown"
        }
    }
}
