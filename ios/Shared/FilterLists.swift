import Foundation

/// A built-in filter list.
struct FilterList: Identifiable {
    let id: String
    let name: String
    let url: URL
    let format: ListFormat
    /// `.url` lists go into the request engine (engine.dat), `.dns` lists into the DNS
    /// blocklist (domains.bin).
    let target: ListTarget
    /// A `.dns` list whose blocks of hosts of sensitive services and banks the core leaves
    /// out (`ListInput.exemptSensitiveHosts`), so that a list added for wider coverage
    /// cannot break a bank or identity app by blocking its telemetry.
    var exemptSensitiveHosts = false
}

enum FilterLists {
    /// The built-in lists, each on unless the user switches it off. `ListSettings` stores
    /// only the ones switched off, so a list added here in an app update is on for existing
    /// installs, and `ListUpdater` downloads and compiles it at the next opportunity rather
    /// than with the next daily update.
    static let defaults: [FilterList] = [
        FilterList(
            id: "easylist", name: "EasyList",
            url: URL(string: "https://easylist.to/easylist/easylist.txt")!,
            format: .adblock, target: .url),
        FilterList(
            id: "easyprivacy", name: "EasyPrivacy",
            url: URL(string: "https://easylist.to/easylist/easyprivacy.txt")!,
            format: .adblock, target: .url),
        FilterList(
            id: "adguard-mobile", name: "AdGuard Mobile Ads",
            url: URL(string: "https://filters.adtidy.org/extension/ublock/filters/11.txt")!,
            format: .adblock, target: .url),
        FilterList(
            id: "adguard-dns", name: "AdGuard DNS filter",
            url: URL(string: "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt")!,
            format: .adblock, target: .dns),
        // Ad and tracker hosts the AdGuard DNS filter does not have; about 270 KB more in
        // domains.bin.
        FilterList(
            id: "stevenblack", name: "StevenBlack hosts",
            url: URL(string: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")!,
            format: .hosts, target: .dns),
        // Two lists built not to break anything, for ad, analytics and telemetry hosts the
        // lists above do not have: together about 22,000 more names and 175 KB more in
        // domains.bin. They also list telemetry hosts of banking apps, which could then
        // break, so unlike the lists above their blocks of hosts of sensitive services and
        // banks are left out.
        FilterList(
            id: "hagezi-light", name: "HaGeZi Multi LIGHT",
            url: URL(string: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/light.txt")!,
            format: .adblock, target: .dns, exemptSensitiveHosts: true),
        FilterList(
            id: "oisd-small", name: "OISD small",
            url: URL(string: "https://small.oisd.nl")!,
            format: .adblock, target: .dns, exemptSensitiveHosts: true),
    ]

    /// Whether `address` names the same list as `url`: the same scheme and host in any
    /// letter case, and the same port, path and query. An empty path counts as `/`, since
    /// both request `/` (OISD small is `https://small.oisd.nl`, and a user may have added
    /// it with the slash). The fragment is ignored, since it is never sent to the server.
    static func sameAddress(_ url: URL, _ address: String) -> Bool {
        guard let a = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let b = URLComponents(string: address.trimmingCharacters(in: .whitespaces))
        else { return false }
        let path = { (components: URLComponents) -> String in
            components.path.isEmpty ? "/" : components.path
        }
        return a.scheme?.lowercased() == b.scheme?.lowercased()
            && a.host?.lowercased() == b.host?.lowercased()
            && a.port == b.port
            && path(a) == path(b)
            && a.query == b.query
    }

    static let engineFile = "engine.dat"
    static let domainsFile = "domains.bin"

    /// True once both compiled files exist in the shared core directory.
    static var compiled: Bool {
        guard let dir = AppGroup.coreDirectory else { return false }
        let fm = FileManager.default
        return fm.fileExists(atPath: dir.appendingPathComponent(engineFile).path)
            && fm.fileExists(atPath: dir.appendingPathComponent(domainsFile).path)
    }
}

/// A list the user added by URL.
struct CustomList: Codable, Hashable, Identifiable {
    enum Kind: String, Codable, CaseIterable, Identifiable {
        /// Adblock syntax, applied to requests (needs HTTPS filtering for HTTPS sites).
        case requestRules
        /// Adblock syntax (`||domain^` rules), applied to DNS.
        case dnsRules
        /// A hosts file (`0.0.0.0 domain`), applied to DNS.
        case hosts

        var id: String { rawValue }

        var label: String {
            switch self {
            case .requestRules: "Request rules"
            case .dnsRules: "Domain rules"
            case .hosts: "Hosts file"
            }
        }

        var format: ListFormat { self == .hosts ? .hosts : .adblock }
        var target: ListTarget { self == .requestRules ? .url : .dns }

        /// The type to compile a list of this type as, when its content is written in
        /// `format` (see `detectListFormat`): itself when the two agree. A hosts file under
        /// Request rules or Domain rules becomes a Hosts file: the DNS parser for adblock
        /// syntax reads none of its lines, and as request rules it would only fill the
        /// tunnel's engine with host blocks that belong in the DNS blocklist. Adblock rules
        /// under Hosts file become Domain rules, which keeps the list in the DNS blocklist
        /// the user chose instead of moving it into the tunnel's engine.
        func corrected(for format: ListFormat) -> Kind {
            switch (self, format) {
            case (.requestRules, .hosts), (.dnsRules, .hosts): .hosts
            case (.hosts, .adblock): .dnsRules
            default: self
            }
        }
    }

    var id = UUID().uuidString
    var name: String
    var url: String
    var kind: Kind
}

/// Which lists the app compiles, stored in the App Group as lists.json. Owned by the app;
/// the tunnel only reads the compiled files.
struct ListSettings: Codable, Equatable {
    /// Ids of built-in lists the user switched off.
    var disabledDefaults: [String] = []
    var custom: [CustomList] = []
    /// The user's own rules in adblock syntax; applied to requests and to DNS.
    var myRules = ""

    static let fileName = "lists.json"

    static var fileURL: URL? {
        AppGroup.coreDirectory?.appendingPathComponent(fileName)
    }

    static func load() -> ListSettings {
        guard let url = fileURL, let data = try? Data(contentsOf: url),
              let settings = try? JSONDecoder().decode(ListSettings.self, from: data)
        else { return ListSettings() }
        return settings
    }

    func save() throws {
        guard let url = Self.fileURL else { throw CocoaError(.fileNoSuchFile) }
        try JSONEncoder().encode(self).write(to: url, options: .atomic)
    }

    func isEnabled(_ list: FilterList) -> Bool {
        !disabledDefaults.contains(list.id)
    }

    /// The enabled built-in list with the same address as `list` and feeding the same file
    /// (engine.dat or domains.bin), if any. Such a custom list is skipped, so the list is
    /// downloaded and compiled once, with the built-in list's type, and Settings says so on
    /// its row so the user can delete it. A custom list at that address that feeds the other
    /// file is used: a copy of EasyPrivacy typed Domain rules puts its hosts in the DNS
    /// blocklist, which the built-in list does not. With the built-in list switched off,
    /// the custom one is used too.
    func builtInDuplicate(of list: CustomList) -> FilterList? {
        FilterLists.defaults.first {
            isEnabled($0) && $0.target == list.kind.target && FilterLists.sameAddress($0.url, list.url)
        }
    }
}
