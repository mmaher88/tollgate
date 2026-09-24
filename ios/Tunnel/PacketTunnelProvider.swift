import Foundation
import NetworkExtension
import os

/// M0 first-light provider. Routes only the reserved tunnel address, so the rest of the
/// device's traffic is untouched, and proves the Rust core links and runs in the extension.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private let log = Logger(subsystem: "dev.tollgate.tunnel", category: "provider")
    private var droppedPackets = 0

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        let version = coreVersion()
        let reply = ping(message: "tunnel")
        let probe = sha256Hex(data: Data("tollgate".utf8))
        let available = os_proc_available_memory()
        log.info("startTunnel core=\(version, privacy: .public) ping=\(reply, privacy: .public) sha256=\(probe, privacy: .public) available=\(available, privacy: .public)")

        do {
            try TunnelHeartbeat(startedAt: Date(), coreVersion: version, sha256Probe: probe, availableMemoryBytes: available).write()
        } catch {
            log.error("heartbeat write failed: \(error.localizedDescription, privacy: .public)")
        }

        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        let ipv4 = NEIPv4Settings(addresses: ["198.18.0.2"], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route(destinationAddress: "198.18.0.1", subnetMask: "255.255.255.255")]
        settings.ipv4Settings = ipv4
        settings.mtu = 1500

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                self.log.error("setTunnelNetworkSettings failed: \(error.localizedDescription, privacy: .public)")
                completionHandler(error)
                return
            }
            self.log.info("tunnel up")
            self.readPackets()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.info("stopTunnel reason=\(reason.rawValue, privacy: .public) dropped=\(self.droppedPackets, privacy: .public)")
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let text = String(decoding: messageData, as: UTF8.self)
        switch TunnelCommand(rawValue: text) {
        case .ping:
            completionHandler?(Data("pong \(coreVersion())".utf8))
        case .probeMemory:
            completionHandler?(Data("probing, watch the logs".utf8))
            probeMemory()
        case nil:
            log.error("unknown app message: \(text, privacy: .public)")
            completionHandler?(nil)
        }
    }

    /// Nothing is routed here except 198.18.0.1, so packets are counted and dropped.
    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            self.droppedPackets += packets.count
            self.readPackets()
        }
    }

    /// Experiment E3. Allocates and dirties 4 MiB per step until jetsam kills the process.
    /// The last "probe" line in the log before the kill shows the effective limit.
    private func probeMemory() {
        let log = self.log
        DispatchQueue.global(qos: .utility).async {
            let chunk = 4 * 1024 * 1024
            var held: [UnsafeMutableRawPointer] = []
            for step in 1...64 {
                let block = UnsafeMutableRawPointer.allocate(byteCount: chunk, alignment: 16)
                arc4random_buf(block, chunk)
                held.append(block)
                log.info("probe step=\(step, privacy: .public) allocated_mib=\(step * 4, privacy: .public) available=\(os_proc_available_memory(), privacy: .public)")
                Thread.sleep(forTimeInterval: 0.25)
            }
            log.info("probe finished without termination, held=\(held.count, privacy: .public)")
        }
    }
}
