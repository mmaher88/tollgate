import os

/// Forwards the Rust core's `log` records to the unified logging system, one category per
/// Rust module target, so `pymobiledevice3 syslog live` shows them with the Swift logs.
final class OSLogCoreLogger: CoreLogger {
    private let subsystem: String

    init(subsystem: String) {
        self.subsystem = subsystem
    }

    func log(level: LogLevel, target: String, message: String) {
        let logger = Logger(subsystem: subsystem, category: target)
        switch level {
        case .error:
            logger.error("\(message, privacy: .public)")
        case .warn:
            logger.warning("\(message, privacy: .public)")
        case .info:
            logger.info("\(message, privacy: .public)")
        case .debug, .trace:
            logger.debug("\(message, privacy: .public)")
        }
    }
}
