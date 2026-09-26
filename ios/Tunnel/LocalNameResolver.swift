import Foundation
import Network
import NetworkExtension
import dnssd
import os

/// Looks up the names only the local network knows (`nas.lan`, `fritz.box`, bare device
/// names, reverse lookups of LAN addresses) for the core, which never sends them to the
/// public DoH upstreams.
///
/// Each lookup is a `DNSServiceQueryRecord` scoped to the current physical interface (the
/// first one `NWPathMonitor` reports that is not a tunnel), so it uses the DNS servers that
/// network handed out, never the tunnel's own resolver, which would send the query straight
/// back here. The raw records go to the core, which builds the reply. A lookup that fails
/// or takes longer than 2 s is answered SERVFAIL.
final class LocalNameResolver: LocalResolver, @unchecked Sendable {
    /// Longest wait for the network's resolver.
    static let timeout: TimeInterval = 2
    private static let anyType: UInt16 = 255

    private let log = Logger(subsystem: "dev.tollgate.tunnel", category: "local-dns")
    private let queue = DispatchQueue(label: "dev.tollgate.tunnel.local-dns")
    private let monitor = NWPathMonitor(prohibitedInterfaceTypes: [.other])
    private let engineState: OSAllocatedUnfairLock<Engine?>
    private let flow: NEPacketTunnelFlow

    // Only used on `queue`.
    private var interfaceIndex: UInt32 = 0
    private var lookups: [UInt64: Lookup] = [:]
    private var stopped = false

    /// One running `DNSServiceQueryRecord` and the records it has returned so far.
    fileprivate final class Lookup {
        let id: UInt64
        let rtype: UInt16
        weak var owner: LocalNameResolver?
        var ref: DNSServiceRef?
        var records: [DnsRecord] = []

        init(id: UInt64, rtype: UInt16, owner: LocalNameResolver) {
            self.id = id
            self.rtype = rtype
            self.owner = owner
        }

        /// Ends the query; no callback arrives afterwards. Only on the owner's queue.
        func cancel() {
            if let ref {
                DNSServiceRefDeallocate(ref)
                self.ref = nil
            }
        }
    }

    init(engineState: OSAllocatedUnfairLock<Engine?>, flow: NEPacketTunnelFlow) {
        self.engineState = engineState
        self.flow = flow
    }

    /// Starts following the physical interface. Call once the engine is in `engineState`,
    /// so the first path reaches it.
    func start() {
        monitor.pathUpdateHandler = { [weak self] path in
            self?.pathChanged(path)
        }
        monitor.start(queue: queue)
    }

    /// Stops following the interface and ends every running lookup. The core answers the
    /// queries still waiting SERVFAIL when their deadline passes.
    func stop() {
        monitor.cancel()
        queue.async { [self] in
            stopped = true
            for lookup in lookups.values {
                lookup.cancel()
            }
            lookups.removeAll()
        }
    }

    // MARK: - LocalResolver

    func resolve(id: UInt64, name: String, rtype: UInt16, rclass: UInt16) {
        // Called from handlePackets: only start the lookup.
        queue.async { [weak self] in
            self?.begin(id: id, name: name, rtype: rtype, rclass: rclass)
        }
    }

    // MARK: - On the queue

    private func pathChanged(_ path: Network.NWPath) {
        let interface = path.status == .satisfied
            ? path.availableInterfaces.first(where: { $0.type != .other })
            : nil
        interfaceIndex = interface.map { UInt32(truncatingIfNeeded: $0.index) } ?? 0
        // Changes when the interface or its gateways do, so answers from one network are
        // never served on another.
        let network = interface.map { interface in
            ([interface.name] + path.gateways.map { "\($0)" }).joined(separator: " ")
        } ?? ""
        let name = interface?.name ?? "none"
        let index = interfaceIndex
        log.info("local DNS interface \(name, privacy: .public) index=\(index, privacy: .public)")
        let engine = engineState.withLock { $0 }
        engine?.setNetwork(network: network)
    }

    private func begin(id: UInt64, name: String, rtype: UInt16, rclass: UInt16) {
        guard !stopped, interfaceIndex != 0 else {
            // Without a physical interface an unscoped query would go to the tunnel.
            complete(id: id, records: nil)
            return
        }
        let lookup = Lookup(id: id, rtype: rtype, owner: self)
        var ref: DNSServiceRef?
        let context = Unmanaged.passUnretained(lookup).toOpaque()
        // ReturnIntermediates also reports names and types that do not exist
        // (kDNSServiceErr_NoSuchRecord), instead of waiting until the timeout.
        let flags = DNSServiceFlags(kDNSServiceFlagsReturnIntermediates)
        let error = DNSServiceQueryRecord(
            &ref, flags, interfaceIndex, name, rtype, rclass,
            { _, flags, _, error, _, rrtype, rrclass, rdlen, rdata, ttl, context in
                guard let context else { return }
                let lookup = Unmanaged<LocalNameResolver.Lookup>.fromOpaque(context).takeUnretainedValue()
                let data = rdata.map { Data(bytes: $0, count: Int(rdlen)) } ?? Data()
                let record = DnsRecord(rtype: rrtype, rclass: rrclass, ttl: ttl, data: data)
                lookup.owner?.received(lookup, flags: flags, error: error, record: record)
            },
            context)
        guard Int(error) == Int(kDNSServiceErr_NoError), let ref else {
            log.error("DNSServiceQueryRecord failed: \(error, privacy: .public)")
            complete(id: id, records: nil)
            return
        }
        lookup.ref = ref
        lookups[id] = lookup
        let scheduled = DNSServiceSetDispatchQueue(ref, queue)
        guard Int(scheduled) == Int(kDNSServiceErr_NoError) else {
            log.error("DNSServiceSetDispatchQueue failed: \(scheduled, privacy: .public)")
            finish(lookup, records: nil)
            return
        }
        queue.asyncAfter(deadline: .now() + Self.timeout) { [weak self, weak lookup] in
            guard let self, let lookup, self.lookups[lookup.id] === lookup else { return }
            // Records of the type asked for that arrived in time still make an answer.
            self.finish(lookup, records: lookup.records.isEmpty ? nil : lookup.records)
        }
    }

    fileprivate func received(_ lookup: Lookup, flags: DNSServiceFlags, error: DNSServiceErrorType,
                              record: DnsRecord) {
        guard lookups[lookup.id] === lookup else { return }
        if Int(error) == Int(kDNSServiceErr_NoSuchRecord) {
            // The name or the type does not exist there: an answer without records.
            finish(lookup, records: lookup.records)
            return
        }
        guard Int(error) == Int(kDNSServiceErr_NoError) else {
            log.debug("local lookup failed: \(error, privacy: .public)")
            finish(lookup, records: nil)
            return
        }
        let added = flags & DNSServiceFlags(kDNSServiceFlagsAdd) != 0
        if added, record.rtype == lookup.rtype || lookup.rtype == Self.anyType {
            lookup.records.append(record)
        }
        // A batch of only intermediate records (a CNAME) is followed by the final ones.
        let moreComing = flags & DNSServiceFlags(kDNSServiceFlagsMoreComing) != 0
        if !moreComing, !lookup.records.isEmpty {
            finish(lookup, records: lookup.records)
        }
    }

    private func finish(_ lookup: Lookup, records: [DnsRecord]?) {
        lookup.cancel()
        lookups[lookup.id] = nil
        complete(id: lookup.id, records: records)
    }

    private func complete(id: UInt64, records: [DnsRecord]?) {
        guard let engine = engineState.withLock({ $0 }) else { return }
        let packets = engine.completeLocal(id: id, records: records)
        if !packets.isEmpty {
            flow.writePackets(packets, withProtocols: packets.map(PacketFamily.of))
        }
    }
}
