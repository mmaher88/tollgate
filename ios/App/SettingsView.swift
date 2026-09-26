import SwiftUI
import UIKit

struct SettingsView: View {
    @EnvironmentObject private var lists: ListUpdater
    @State private var allowCount = 0
    @State private var passthroughCount = 0
    @State private var enabledLists = 0

    var body: some View {
        NavigationStack {
            List {
                Section {
                    NavigationLink {
                        FilterListsView()
                    } label: {
                        LabeledContent("Filter lists", value: "\(enabledLists) enabled")
                    }
                    NavigationLink("My rules") { MyRulesView() }
                } header: {
                    Text("Blocking")
                } footer: {
                    Text("Lists update automatically about once a day.")
                }

                Section {
                    NavigationLink {
                        HostListEditor(
                            title: "Allowed sites",
                            explanation: "Nothing is blocked on these sites or for these domains. Use *.example.com for a site and all its subdomains.",
                            keyPath: \.allowlist)
                    } label: {
                        LabeledContent("Allowed sites", value: "\(allowCount)")
                    }
                    NavigationLink {
                        HostListEditor(
                            title: "Never filtered",
                            explanation: "HTTPS connections to these hosts are never decrypted. Apple services, banks and apps that pin certificates are already on a built-in list.",
                            keyPath: \.passthrough)
                    } label: {
                        LabeledContent("Never filtered", value: "\(passthroughCount)")
                    }
                    NavigationLink("Learned certificate pins") { PinsView() }
                } header: {
                    Text("Exceptions")
                }
            }
            .navigationTitle("Settings")
            // On the List, so it also runs when a pushed editor pops back.
            .onAppear(perform: reload)
        }
    }

    private func reload() {
        let config = CoreConfig.load()
        allowCount = config.allowlist.count
        passthroughCount = config.passthrough.count
        let settings = ListSettings.load()
        enabledLists = FilterLists.defaults.filter(settings.isEnabled).count + settings.custom.count
    }
}

// MARK: - Filter lists

struct FilterListsView: View {
    @EnvironmentObject private var lists: ListUpdater
    @EnvironmentObject private var tunnel: TunnelController
    @State private var settings = ListSettings.load()
    @State private var adding = false
    @State private var saveError: String?

    var body: some View {
        List {
            Section("Built-in") {
                ForEach(FilterLists.defaults) { list in
                    Toggle(isOn: Binding(
                        get: { settings.isEnabled(list) },
                        set: { enabled in
                            settings.disabledDefaults.removeAll { $0 == list.id }
                            if !enabled { settings.disabledDefaults.append(list.id) }
                            save()
                        }
                    )) {
                        VStack(alignment: .leading) {
                            Text(list.name)
                            Text(list.target == .dns ? "Domains" : "Requests")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            }
            Section("Added by you") {
                ForEach(settings.custom) { list in
                    VStack(alignment: .leading) {
                        Text(list.name)
                        Text("\(list.kind.label) · \(list.url)")
                            .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                .onDelete { offsets in
                    settings.custom.remove(atOffsets: offsets)
                    save()
                }
                Button("Add a list") { adding = true }
            }
            Section {
                Button(lists.pendingSettingsChange ? "Apply changes now" : "Update now") {
                    Task {
                        // Changes compile from the cached lists; "Update now" downloads.
                        let compiled: Bool
                        if lists.pendingSettingsChange {
                            compiled = await lists.applySettings()
                        } else {
                            compiled = await lists.update()
                        }
                        if compiled { await tunnel.listsUpdated() }
                    }
                }
                .disabled(lists.isBusy)
                Text(statusText).font(.footnote).foregroundStyle(.secondary)
                ForEach(lists.warnings, id: \.self) { warning in
                    Text(warning).font(.footnote).foregroundStyle(.orange)
                }
                if let saveError {
                    Text("Not saved: \(saveError)").font(.footnote).foregroundStyle(.red)
                }
            }
        }
        .navigationTitle("Filter lists")
        .sheet(isPresented: $adding) {
            AddListView { list in
                settings.custom.append(list)
                save()
            }
        }
    }

    private var statusText: String {
        switch lists.state {
        case let .downloading(done, total): return "Downloading \(done + 1) of \(total)"
        case .compiling: return "Compiling"
        case let .failed(message): return "Update failed: \(message)"
        case .idle:
            if lists.pendingSettingsChange { return "Changes are not applied yet." }
            let updated = lists.lastUpdated?.formatted(date: .abbreviated, time: .shortened)
            if lists.lastAttemptPartial, let attempt = lists.lastAttempt {
                var text = "Checked \(attempt.formatted(date: .abbreviated, time: .shortened)); some lists could not be downloaded and are retried hourly."
                if let updated { text += " All lists were last updated \(updated)." }
                return text
            }
            if let updated { return "Updated \(updated)" }
            return lists.compiled ? "Installed" : "Not downloaded yet"
        }
    }

    private func save() {
        do {
            try settings.save()
            saveError = nil
            lists.settingsChanged()
        } catch {
            saveError = error.localizedDescription
        }
    }
}

struct AddListView: View {
    let onAdd: (CustomList) -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var name = ""
    @State private var url = ""
    @State private var kind: CustomList.Kind = .requestRules

    private var valid: Bool {
        guard let parsed = URL(string: url.trimmingCharacters(in: .whitespaces)) else { return false }
        return parsed.scheme?.lowercased() == "https" && parsed.host != nil
    }

    var body: some View {
        NavigationStack {
            Form {
                TextField("Name", text: $name)
                TextField("https://example.com/list.txt", text: $url)
                    .keyboardType(.URL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                Picker("Type", selection: $kind) {
                    ForEach(CustomList.Kind.allCases) { Text($0.label).tag($0) }
                }
                Text("Request rules use adblock syntax and filter requests (HTTPS sites need HTTPS filtering). Domain rules and hosts files block names for every app.")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            .navigationTitle("Add a list")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        let trimmed = url.trimmingCharacters(in: .whitespaces)
                        let title = name.trimmingCharacters(in: .whitespaces)
                        onAdd(CustomList(name: title.isEmpty ? (URL(string: trimmed)?.host ?? trimmed) : title,
                                         url: trimmed, kind: kind))
                        dismiss()
                    }
                    .disabled(!valid)
                }
            }
        }
    }
}

struct MyRulesView: View {
    @EnvironmentObject private var lists: ListUpdater
    @EnvironmentObject private var tunnel: TunnelController
    @State private var text = ListSettings.load().myRules
    @State private var saved = true
    @State private var saveError: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("One rule per line in adblock syntax, for example ||ads.example.com^ to block a domain or @@||example.com^ to allow one.")
                .font(.footnote).foregroundStyle(.secondary)
                .padding(.horizontal)
            TextEditor(text: $text)
                .font(.system(.body, design: .monospaced))
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .padding(.horizontal, 12)
                .onChange(of: text) { _, _ in saved = false }
            Text(status)
                .font(.footnote)
                .foregroundStyle(saveError != nil || lists.state.isFailure ? .red : .secondary)
                .padding(.horizontal)
                .padding(.bottom, 8)
        }
        .navigationTitle("My rules")
        .toolbar {
            Button(saved && lists.pendingSettingsChange ? "Retry" : "Save") {
                var settings = ListSettings.load()
                settings.myRules = text
                do {
                    try settings.save()
                } catch {
                    saveError = error.localizedDescription
                    return
                }
                saveError = nil
                saved = true
                lists.settingsChanged()
                Task {
                    if await lists.applySettings() { await tunnel.listsUpdated() }
                }
            }
            .disabled((saved && !lists.pendingSettingsChange) || lists.isBusy)
        }
    }

    private var status: String {
        if let saveError { return "Not saved: \(saveError)" }
        switch lists.state {
        case .downloading, .compiling: return "Applying"
        case let .failed(message): return "Not applied yet: \(message)"
        case .idle:
            if !saved { return "Not saved" }
            return lists.pendingSettingsChange ? "Saved, not applied yet" : "Active"
        }
    }
}

extension ListUpdater.State {
    var isFailure: Bool {
        if case .failed = self { return true }
        return false
    }
}

// MARK: - Host lists

/// Edits one list of host patterns in config.json, validated by the core's own parser.
struct HostListEditor: View {
    let title: String
    let explanation: String
    let keyPath: WritableKeyPath<CoreConfig, [String]>

    @EnvironmentObject private var tunnel: TunnelController
    @State private var patterns: [String] = []
    @State private var draft = ""
    @State private var error: String?

    var body: some View {
        List {
            Section {
                HStack {
                    TextField("*.example.com", text: $draft)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .onSubmit(add)
                    // Borderless, so a tap on the text field does not also add the draft.
                    Button("Add", action: add)
                        .buttonStyle(.borderless)
                        .disabled(draft.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                if let error {
                    Text(error).font(.footnote).foregroundStyle(.red)
                }
            } footer: {
                Text(explanation)
            }
            Section {
                ForEach(patterns, id: \.self) { Text($0) }
                    .onDelete { offsets in
                        patterns.remove(atOffsets: offsets)
                        save()
                    }
            }
        }
        .navigationTitle(title)
        .onAppear { patterns = CoreConfig.load()[keyPath: keyPath] }
    }

    private func add() {
        let pattern = draft.trimmingCharacters(in: .whitespaces).lowercased()
        guard !pattern.isEmpty else { return }
        do {
            try validateHostPattern(pattern: pattern)
        } catch {
            self.error = "Not a valid host pattern"
            return
        }
        error = nil
        draft = ""
        guard !patterns.contains(pattern) else { return }
        patterns.append(pattern)
        save()
    }

    private func save() {
        var config = CoreConfig.load()
        config[keyPath: keyPath] = patterns
        do {
            try config.save()
            Task { await tunnel.restartIfRunning() }
        } catch {
            self.error = "Could not save: \(error.localizedDescription)"
        }
    }
}

// MARK: - Learned pins

struct PinsView: View {
    @EnvironmentObject private var tunnel: TunnelController
    @State private var pins: [PinEntry] = []
    @State private var error: String?

    var body: some View {
        List {
            Section {
                if pins.isEmpty {
                    Text("None yet").foregroundStyle(.secondary)
                }
                ForEach(pins) { pin in
                    LabeledContent(pin.host, value: pin.date.formatted(date: .abbreviated, time: .omitted))
                }
                .onDelete { offsets in
                    forget(offsets.map { pins[$0].host })
                }
            } footer: {
                Text("Apps that reject the Tollgate certificate are passed through automatically for 30 days. Forget a host to filter it again.")
            }
            if !pins.isEmpty {
                Button("Forget all", role: .destructive) { forget(pins.map(\.host)) }
            }
            if let error {
                Text(error).font(.footnote).foregroundStyle(.red)
            }
        }
        .navigationTitle("Learned pins")
        .task { await reload() }
        .refreshable { await reload() }
    }

    /// The core keeps a learned pin for 30 days; older entries are still stored but no longer
    /// applied, so they are not shown.
    private static let pinLifetime: TimeInterval = 30 * 24 * 60 * 60
    /// The core also ignores a pin learned more than an hour ahead of its clock (one learned
    /// while the date was set forward), so it is not shown either. Matches
    /// CLOCK_TOLERANCE_SECS in core/crates/policy/src/policy.rs.
    private static let clockTolerance: TimeInterval = 60 * 60

    private func show(_ entries: [PinEntry]) {
        let now = Date()
        pins = entries.filter {
            let age = now.timeIntervalSince($0.date)
            return age >= -Self.clockTolerance && age < Self.pinLifetime
        }
    }

    private func reload() async {
        switch await tunnel.pins() {
        case let .engine(running):
            show(running)
            error = nil
        case .storedFile:
            guard let directory = AppGroup.coreDirectory else { return }
            do {
                show(try storedLearnedPins(dataDir: directory.path)
                    .map { PinEntry(host: $0.host, learnedAt: $0.learnedAt) })
                error = nil
            } catch {
                self.error = "Could not read pins: \(error.localizedDescription)"
            }
        case .unavailable:
            error = "Protection is restarting; pull to refresh in a moment."
        }
    }

    private func forget(_ hosts: [String]) {
        Task {
            switch await tunnel.forgetPins(hosts) {
            case .done:
                error = nil
            case .editStoredFile:
                guard let directory = AppGroup.coreDirectory else { return }
                do {
                    _ = try forgetStoredPins(dataDir: directory.path, hosts: hosts)
                    error = nil
                } catch {
                    self.error = "Could not update pins: \(error.localizedDescription)"
                }
            case .unavailable:
                error = "Protection is restarting; try again in a moment."
                return
            }
            await reload()
        }
    }
}
