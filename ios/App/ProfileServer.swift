import Foundation
import Network

/// A one-file HTTP server on the loopback interface. Any request gets the configuration
/// profile, served with the MIME type that makes Safari offer to install it.
final class ProfileServer: @unchecked Sendable {
    private let listener: NWListener
    private let body: Data
    private let queue = DispatchQueue(label: "dev.tollgate.profile-server")

    init(body: Data) throws {
        self.body = body
        let parameters = NWParameters.tcp
        parameters.requiredInterfaceType = .loopback
        parameters.allowLocalEndpointReuse = true
        listener = try NWListener(using: parameters)
    }

    /// Only touched on `queue`, where the listener delivers its callbacks.
    private var reported = false

    /// Calls `ready` once with the profile URL, or with nil if the listener failed.
    func start(ready: @escaping @Sendable (URL?) -> Void) {
        listener.stateUpdateHandler = { [weak self] state in
            self?.handle(state, ready: ready)
        }
        listener.newConnectionHandler = { [body, queue] connection in
            connection.start(queue: queue)
            connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { _, _, _, _ in
                let header = "HTTP/1.1 200 OK\r\n"
                    + "Content-Type: application/x-apple-aspen-config\r\n"
                    + "Content-Disposition: attachment; filename=\"Tollgate.mobileconfig\"\r\n"
                    + "Content-Length: \(body.count)\r\n"
                    + "Connection: close\r\n\r\n"
                connection.send(content: Data(header.utf8) + body, completion: .contentProcessed { _ in
                    connection.cancel()
                })
            }
        }
        listener.start(queue: queue)
    }

    private func handle(_ state: NWListener.State, ready: @Sendable (URL?) -> Void) {
        guard !reported else { return }
        switch state {
        case .ready:
            reported = true
            let port = listener.port?.rawValue ?? 0
            ready(URL(string: "http://127.0.0.1:\(port)/Tollgate.mobileconfig"))
        case .failed:
            reported = true
            ready(nil)
        default:
            break
        }
    }

    func stop() {
        listener.cancel()
    }
}
