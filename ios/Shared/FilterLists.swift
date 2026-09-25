import Foundation

/// A filter list the app downloads and compiles into the core's data files.
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
