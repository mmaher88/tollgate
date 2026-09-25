import SwiftUI
import UIKit

/// Recent blocks from the tunnel, refreshed while the screen is visible.
struct BlockLogView: View {
    @EnvironmentObject private var tunnel: TunnelController
    @State private var events: [TunnelEvent] = []
    @State private var filter: Filter = .all
    @State private var search = ""
    @State private var selected: TunnelEvent?
    @State private var message: String?

    enum Filter: String, CaseIterable, Identifiable {
        case all = "All"
        case domains = "Domains"
        case requests = "Requests"
        var id: String { rawValue }
    }

    private var shown: [TunnelEvent] {
        events.filter { event in
            switch filter {
            case .all: true
            case .domains: event.kind == .dns
            case .requests: event.kind == .request
            }
        }
        .filter { event in
            search.isEmpty
                || event.host.localizedCaseInsensitiveContains(search)
                || (event.url?.localizedCaseInsensitiveContains(search) ?? false)
                || (event.sourceHost?.localizedCaseInsensitiveContains(search) ?? false)
        }
    }

    var body: some View {
        NavigationStack {
            List {
                Picker("Show", selection: $filter) {
                    ForEach(Filter.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented)
                .listRowBackground(Color.clear)

                if let message {
                    Text(message).font(.footnote).foregroundStyle(.secondary)
                }
                if tunnel.status != .connected {
                    ContentUnavailableView("Protection is off", systemImage: "shield.slash",
                                           description: Text("Blocks appear here while Tollgate is on."))
                } else if shown.isEmpty {
                    ContentUnavailableView("Nothing blocked yet", systemImage: "checkmark.shield",
                                           description: Text("Browse a site with ads and come back."))
                } else {
                    ForEach(shown) { event in
                        Button { selected = event } label: { EventRow(event: event) }
                            .buttonStyle(.plain)
                    }
                }
            }
            .navigationTitle("Activity")
            .searchable(text: $search, prompt: "Domain or address")
            .toolbar {
                Button("Clear") {
                    Task {
                        await tunnel.clearEvents()
                        events = []
                    }
                }
                .disabled(tunnel.status != .connected)
            }
            .task(id: tunnel.status) {
                while tunnel.status == .connected, !Task.isCancelled {
                    if let latest = await tunnel.events() { events = latest }
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                }
            }
            .confirmationDialog(selected?.host ?? "", isPresented: Binding(
                get: { selected != nil }, set: { if !$0 { selected = nil } }
            ), titleVisibility: .visible) {
                if let event = selected {
                    Button("Never block \(event.host)") { allow(event.host) }
                    if let page = event.sourceHost, page != event.host {
                        Button("Allow everything on \(page)") { allow(page) }
                    }
                    Button("Copy \(event.url == nil ? "domain" : "address")") {
                        UIPasteboard.general.string = event.url ?? event.host
                    }
                }
            }
        }
    }

    /// Adds `*.host` (the host and its subdomains) to the allowlist and restarts the tunnel.
    private func allow(_ host: String) {
        var config = CoreConfig.load()
        let pattern = "*." + host
        guard !config.allowlist.contains(pattern) else { return }
        config.allowlist.append(pattern)
        do {
            try config.save()
            message = "\(host) is allowed. Protection restarts to apply it."
            Task { await tunnel.restartIfRunning() }
        } catch {
            message = "Could not save: \(error.localizedDescription)"
        }
    }
}

private struct EventRow: View {
    let event: TunnelEvent

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: event.kind == .dns ? "network.slash" : "xmark.octagon")
                .foregroundStyle(event.kind == .dns ? .orange : .red)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(event.host).font(.body).lineLimit(1)
                if let url = event.url {
                    Text(url).font(.caption).foregroundStyle(.secondary).lineLimit(2)
                }
                HStack(spacing: 6) {
                    Text(event.date, style: .time)
                    if let page = event.sourceHost, page != event.host {
                        Text("on \(page)")
                    }
                }
                .font(.caption2)
                .foregroundStyle(.secondary)
            }
        }
        .contentShape(Rectangle())
    }
}
