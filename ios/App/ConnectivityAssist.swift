import Foundation

/// iOS 27's Connectivity Assist, a Wi-Fi setting that starts a second attempt over cellular
/// data when a connection over Wi-Fi fails or is slow to get ready. That attempt uses the
/// carrier's DNS and no proxy, so a connection Tollgate refuses (a name its DNS blocks, a
/// `CONNECT` it answers with `403`) can load over cellular instead. Tollgate can neither read
/// nor change the setting, so the app only explains how to turn it off: a notice on Home until
/// the owner dismisses it, and the same advice in Settings.
enum ConnectivityAssist {
    /// Whether this iOS version has Connectivity Assist (iOS 27 and later).
    static var isAvailable: Bool {
        if #available(iOS 27, *) { return true }
        return false
    }

    /// UserDefaults key, true once the owner dismissed the Home notice; Settings sets it back
    /// to false to show the notice again.
    static let noticeDismissedKey = "notice.connectivityAssistDismissed"

    /// The Home notice's headline.
    static let title = "Turn off Connectivity Assist"

    /// What the setting does to Tollgate and how to turn it off, for the Home notice and the
    /// Settings footer. Tollgate cannot read the setting, so the text never says whether it
    /// is on.
    static let advice = "When Wi-Fi and cellular data are both on, iOS can retry a blocked connection over cellular data, and the retry goes around Tollgate. Open Settings, Wi-Fi and turn off Connectivity Assist: the main switch, and the one on each network's page. Tollgate cannot read this setting, so it does not know whether the setting is already off."
}
