import Foundation

/// The App Group shared by the app and the tunnel extension. The identifier is injected
/// into Info.plist from tooling/config.env when the project is generated.
enum AppGroup {
    static var identifier: String? {
        Bundle.main.object(forInfoDictionaryKey: "TollgateAppGroup") as? String
    }

    static var containerURL: URL? {
        guard let identifier else { return nil }
        return FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier)
    }
}
