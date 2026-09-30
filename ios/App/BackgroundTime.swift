import UIKit

/// Background execution time for work that must not stop halfway, such as a tunnel
/// restart or a list update. Ended by `end()` or when the time runs out, whichever comes
/// first.
@MainActor
final class BackgroundTime {
    private var identifier: UIBackgroundTaskIdentifier = .invalid

    init(name: String) {
        identifier = UIApplication.shared.beginBackgroundTask(withName: name) { [weak self] in
            // Out of time: the work goes on when the app is next resumed.
            MainActor.assumeIsolated { self?.end() }
        }
    }

    func end() {
        guard identifier != .invalid else { return }
        UIApplication.shared.endBackgroundTask(identifier)
        identifier = .invalid
    }
}
