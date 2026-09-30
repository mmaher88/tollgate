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
}

enum FilterLists {
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
    ]

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
}
