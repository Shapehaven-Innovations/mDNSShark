// PacketTunnel/MDNSListener.swift
// Shared into the mDNSShark target (pbxproj exception set) so the pure parts (cmsg parsing, datagram assembly, interface selection, meta) are unit-tested.
import Foundation
import Darwin
import notify
import os

/// RFC 3542 IPv6 socket options that Swift cannot see because netinet6/in6.h hides them behind __APPLE_USE_RFC_3542 (values from the iOS SDK header).
enum IPv6SocketOption {
    static let recvPacketInfo: Int32 = 61   // IPV6_RECVPKTINFO
    static let recvHopLimit: Int32 = 37     // IPV6_RECVHOPLIMIT
    static let packetInfo: Int32 = 46       // IPV6_PKTINFO (IPV6_3542PKTINFO), cmsg type carrying in6_pktinfo
    static let hopLimit: Int32 = 47         // IPV6_HOPLIMIT (IPV6_3542HOPLIMIT), cmsg type carrying an Int32
    static let recvTrafficClass: Int32 = 35 // IPV6_RECVTCLASS
    static let trafficClass: Int32 = 36     // IPV6_TCLASS, cmsg type carrying an Int32
}

/// IPv4 socket option that Swift does not import (value from the iOS SDK header).
enum IPv4SocketOption {
    static let recvTOS: Int32 = 27          // IP_RECVTOS, also the cmsg type carrying one byte
}

/// SIOCGIFFUNCTIONALTYPE values from net/if.h (IFRTYPE_FUNCTIONAL_*), the same classification mDNSResponder uses to pick its interfaces.
enum InterfaceFunctionalType {
    static let unknown: UInt32 = 0
    static let loopback: UInt32 = 1
    static let wired: UInt32 = 2
    static let wifiInfra: UInt32 = 3
    static let wifiAWDL: UInt32 = 4
    static let cellular: UInt32 = 5
    static let intcoproc: UInt32 = 6
    static let companionLink: UInt32 = 7
    static let management: UInt32 = 8

    /// _IOWR('i', 173, struct ifreq) with sizeof(struct ifreq) == 32 on arm64 iOS and macOS; Swift does not import _IOWR macros.
    static let ioctlRequest: UInt = 0xC02069AD

    /// Name-prefix fallback for an interface whose functional type could not be read; BSD names are not API, so it only backs up the ioctl.
    static let fallbackExcludedPrefixes = ["awdl", "llw"]

    static func name(_ type: UInt32?) -> String {
        switch type {
        case unknown: return "unknown"
        case loopback: return "loopback"
        case wired: return "wired"
        case wifiInfra: return "wifiInfra"
        case wifiAWDL: return "wifiAWDL"
        case cellular: return "cellular"
        case intcoproc: return "intcoproc"
        case companionLink: return "companionLink"
        case management: return "management"
        case nil: return "unavailable"
        case .some(let other): return "other(\(other))"
        }
    }

    /// AWDL and the internal coprocessor link carry their own discovery traffic and are what mDNSResponder skips (mDNSMacOSX.c, MulticastInterface).
    static func excludes(_ type: UInt32?, name: String) -> Bool {
        guard let type else { return fallbackExcludedPrefixes.contains { name.hasPrefix($0) } }
        return type == wifiAWDL || type == intcoproc
    }
}

/// One interface as getifaddrs plus SIOCGIFFUNCTIONALTYPE describe it; tests build these directly to drive selectInterfaces.
struct InterfaceDescriptor: Equatable {
    var name: String
    var index: UInt32
    var flags: Int32
    /// nil when the ioctl failed for this interface (utun does on macOS), which alone never excludes it.
    var functionalType: UInt32?
    /// IPv4 (4 bytes) and IPv6 (16 bytes) addresses in getifaddrs order.
    var addresses: [[UInt8]]
    /// Netmask per IPv4 address as getifaddrs reports it (missing when the netmask sockaddr was absent or malformed); only the LAN route reads it.
    var ipv4Netmasks: [[UInt8]: [UInt8]] = [:]
}

/// The IPv4 subnet the provider routes into the tunnel for opt-in LAN capture, picked by LANRouteSelection from the listener's interface ranking.
struct LANIPv4Route: Equatable {
    let interfaceName: String
    let address: [UInt8]
    let netmask: [UInt8]

    var networkAddress: [UInt8] { zip(address, netmask).map { $0 & $1 } }
    var addressText: String { Self.dotted(address) }
    var netmaskText: String { Self.dotted(netmask) }
    var networkText: String { Self.dotted(networkAddress) }

    static func dotted(_ bytes: [UInt8]) -> String { bytes.map(String.init).joined(separator: ".") }
}

/// Chooses the LAN subnet route from interface descriptors so the provider never names a BSD interface (en0 is not Wi-Fi on every device, and the Mac app differs again).
enum LANRouteSelection {
    /// 169.254.0.0/16 (RFC 3927), what a USB link to a Mac or an unconfigured Ethernet carries; routing it into the tunnel captures nothing useful.
    static func isLinkLocal(_ ipv4: [UInt8]) -> Bool { ipv4.count == 4 && ipv4[0] == 169 && ipv4[1] == 254 }

    /// The first interface in BSDMDNSListener.selectInterfaces order that is running and has a routable IPv4 with a 4-byte netmask; nil when none has.
    static func route(from descriptors: [InterfaceDescriptor]) -> LANIPv4Route? {
        let byName = Dictionary(grouping: descriptors, by: \.name)
        for iface in BSDMDNSListener.selectInterfaces(descriptors) {
            let entries = byName[iface.name] ?? []
            guard entries.contains(where: { $0.flags & IFF_RUNNING != 0 }) else { continue }
            for address in iface.addresses where address.count == 4 && !isLinkLocal(address) {
                if let mask = entries.lazy.compactMap({ $0.ipv4Netmasks[address] }).first, mask.count == 4 {
                    return LANIPv4Route(interfaceName: iface.name, address: address, netmask: mask)
                }
            }
        }
        return nil
    }
}

/// An interface the listener opens its sockets on.
struct CaptureInterface: Equatable {
    let name: String
    let index: UInt32
    let functionalType: UInt32?
    /// Every IPv4 and IPv6 address on the interface, for the group join and direction matching.
    let addresses: [[UInt8]]

    /// nil when the interface only has IPv6, in which case the v4 socket is skipped.
    var ipv4Bytes: [UInt8]? { addresses.first { $0.count == 4 } }

    var ipv4: in_addr? {
        ipv4Bytes.map { in_addr(s_addr: UInt32($0[0]) | UInt32($0[1]) << 8 | UInt32($0[2]) << 16 | UInt32($0[3]) << 24) }
    }
}

/// Metadata recvmsg delivers alongside an mDNS datagram, decoded from the control buffer.
struct MDNSControlMessages: Equatable {
    var ttl: UInt8?
    /// 4-byte IPv4 destination from IP_RECVDSTADDR.
    var destination: [UInt8]?
    var hopLimit: UInt8?
    /// 16-byte IPv6 destination from IPV6_PKTINFO.
    var destination6: [UInt8]?
    var interfaceIndex: Int?
    /// IP_RECVTOS (IPv4) or IPV6_TCLASS (IPv6) value.
    var trafficClass: UInt8?
    /// SO_TIMESTAMP value: kernel UDP-input time (getmicrotime), not wire time, so it excludes NIC and driver latency.
    var kernelTimestamp: Date?

    static func parse(_ buffer: UnsafeRawBufferPointer, length: Int) -> MDNSControlMessages {
        var out = MDNSControlMessages()
        let headerSize = MemoryLayout<cmsghdr>.size
        var off = 0
        while off + headerSize <= min(length, buffer.count) {
            let h = buffer.loadUnaligned(fromByteOffset: off, as: cmsghdr.self)
            let len = Int(h.cmsg_len)
            guard len >= headerSize, off + len <= length else { break }
            let dataOff = off + headerSize
            let dataLen = len - headerSize
            if h.cmsg_level == IPPROTO_IP {
                if h.cmsg_type == IP_RECVTTL, dataLen >= 1 {
                    out.ttl = buffer.load(fromByteOffset: dataOff, as: UInt8.self)
                } else if h.cmsg_type == IPv4SocketOption.recvTOS, dataLen >= 1 {
                    out.trafficClass = buffer.load(fromByteOffset: dataOff, as: UInt8.self)
                } else if h.cmsg_type == IP_RECVDSTADDR, dataLen >= 4 {
                    out.destination = Array(buffer[dataOff..<dataOff + 4])
                } else if h.cmsg_type == IP_RECVIF, dataLen >= 4 {
                    // sockaddr_dl: sdl_len, sdl_family, then sdl_index in host order.
                    out.interfaceIndex = Int(buffer.loadUnaligned(fromByteOffset: dataOff + 2, as: UInt16.self))
                }
            } else if h.cmsg_level == IPPROTO_IPV6 {
                if h.cmsg_type == IPv6SocketOption.hopLimit, dataLen >= 4 {
                    out.hopLimit = UInt8(clamping: buffer.loadUnaligned(fromByteOffset: dataOff, as: Int32.self))
                } else if h.cmsg_type == IPv6SocketOption.trafficClass, dataLen >= 4 {
                    out.trafficClass = UInt8(exactly: buffer.loadUnaligned(fromByteOffset: dataOff, as: Int32.self))
                } else if h.cmsg_type == IPv6SocketOption.packetInfo, dataLen >= 20 {
                    out.destination6 = Array(buffer[dataOff..<dataOff + 16])
                    out.interfaceIndex = Int(buffer.loadUnaligned(fromByteOffset: dataOff + 16, as: UInt32.self))
                }
            } else if h.cmsg_level == SOL_SOCKET, h.cmsg_type == SCM_TIMESTAMP, dataLen >= MemoryLayout<timeval>.size {
                let tv = buffer.loadUnaligned(fromByteOffset: dataOff, as: timeval.self)
                out.kernelTimestamp = Date(timeIntervalSince1970: Double(tv.tv_sec) + Double(tv.tv_usec) / 1_000_000)
            }
            off += (len + 3) & ~3
        }
        return out
    }
}

/// Per-datagram facts the listener learned that are not part of the frame itself.
struct MDNSReceiveInfo {
    /// Arrival interface from IP_RECVIF or IPV6_PKTINFO, else the socket's interface.
    let interfaceIndex: Int?
    /// The interface whose socket delivered the datagram (each socket is joined on exactly one).
    let socketInterfaceIndex: UInt32
    /// recvmsg reported MSG_CTRUNC, so the other fields may be missing.
    let controlTruncated: Bool
    let kernelStamped: Bool
}

/// What the consumer did with one datagram: `frame` went to the pcap, `unbuildable` means MDNSFrameBuilder.frame returned nil,
/// `discarded` means the consumer is being torn down and the datagram is left out of every drop counter.
enum MDNSDeliveryResult: Equatable { case frame, unbuildable, discarded }

/// Counters for capture-meta.json, updated on the listener queue and read after stop().
/// datagramsReceived = frames + droppedTruncated + droppedUndecodable + droppedUnbuildable, except for datagrams
/// discarded during the consumer's teardown, after which nobody reads these counters.
struct MDNSListenerStats: Equatable {
    /// Every datagram recvmsg returned, whatever happened to it afterwards.
    var datagramsReceived = 0
    /// Datagrams handed on as frames for the pcap.
    var frames = 0
    var ipv4Frames = 0
    var ipv6Frames = 0
    var ownFrames = 0
    /// recvmsg reported MSG_TRUNC; such datagrams are not written.
    var droppedTruncated = 0
    /// makeDatagram could not decode the source address.
    var droppedUndecodable = 0
    /// MDNSFrameBuilder.frame returned nil.
    var droppedUnbuildable = 0
    /// recvmsg reported MSG_CTRUNC, so some control data may be missing.
    var controlTruncatedFrames = 0
    var kernelStamped = 0
    var ttlMissing = 0
    var tosMissing = 0
    var ownAddressRefreshes = 0
    /// The cmsg arrival interface differed from the socket's own interface; expected to stay 0 (see docs/mdns-listener-scope.md section 2.5).
    var interfaceMismatchFrames = 0
    /// Network-change reconciles that opened or closed at least one interface (docs/mdns-listener-scope.md section 2.6).
    var interfaceChanges = 0

    /// Same count as droppedTruncated; kept for the existing meta key.
    var truncatedFrames: Int { droppedTruncated }

    /// Counts one delivered frame.
    mutating func recordDelivered(_ d: MDNSDatagram, own: Bool, kernelStamped stamped: Bool) {
        frames += 1
        if d.source.count == 4 { ipv4Frames += 1 } else { ipv6Frames += 1 }
        if own { ownFrames += 1 }
        if stamped { kernelStamped += 1 }
        if d.ttl == nil { ttlMissing += 1 }
        if d.trafficClass == nil { tosMissing += 1 }
    }
}

enum MDNSListenerStatus: Equatable {
    case idle
    case listening(interface: String, index: UInt32)
    case failed(stage: String, errno: Int32)
    /// The family was skipped on purpose, such as IPv4 on an interface that has no IPv4 address.
    case unavailable(reason: String)
    case stopped
    /// The interface left getifaddrs (or came back under a new index) mid-capture; both families of its report carry this.
    case removed

    /// What the listener reports when getifaddrs lists no usable interface.
    static let noInterface = MDNSListenerStatus.failed(stage: "interface lookup", errno: ENXIO)

    var description: String {
        switch self {
        case .idle: return "idle"
        case .listening(let name, let index): return "listening on \(name) (ifindex \(index))"
        case .failed(let stage, let code): return "failed: \(stage) errno \(code) (\(String(cString: strerror(code))))"
        case .unavailable(let reason): return "unavailable: \(reason)"
        case .stopped: return "stopped"
        case .removed: return "removed (interface went away)"
        }
    }

    var isListening: Bool {
        if case .listening = self { return true }
        return false
    }

    var isFailed: Bool {
        if case .failed = self { return true }
        return false
    }

    var isUnavailable: Bool {
        if case .unavailable = self { return true }
        return false
    }
}

/// One selected interface's sockets and counters; the `interfaces` entries of the meta block.
struct MDNSInterfaceReport: Equatable {
    let name: String
    let index: UInt32
    let functionalType: UInt32?
    var status: MDNSListenerStatus = .idle
    var ipv6Status: MDNSListenerStatus = .idle
    var frames = 0
    var ipv4Frames = 0
    var ipv6Frames = 0

    var isListening: Bool { status.isListening || ipv6Status.isListening }
    /// A report kept for its final counters after the interface went away; never matched against new selections or frames.
    var isRemoved: Bool { status == .removed }

    mutating func recordDelivered(_ d: MDNSDatagram) {
        frames += 1
        if d.source.count == 4 { ipv4Frames += 1 } else { ipv6Frames += 1 }
    }

    /// Both families read "removed" so the meta shows why the counters stopped; the counters themselves are kept.
    mutating func markRemoved() {
        status = .removed
        ipv6Status = .removed
    }

    var dictionary: [String: Any] {
        ["name": name, "index": Int(index), "functionalType": InterfaceFunctionalType.name(functionalType),
         "status": status.description, "ipv6Status": ipv6Status.description,
         "frames": frames, "ipv4Frames": ipv4Frames, "ipv6Frames": ipv6Frames]
    }
}

/// The `mdnsListener` object in capture-meta.json.
enum MDNSListenerMeta {
    /// Header fields the builder invents rather than reads from the socket, machine-readable twin of disclaimerSentence.
    static let synthesizedFields = ["ipv4.identification", "ipv4.flags", "ipv6.flowLabel", "ipv4.headerChecksum", "udp.checksum", "linkLayerHeader"]

    /// Appended to the capture disclaimer and shown in the packet detail view.
    static let disclaimerSentence = "mDNS frames come from a multicast listener, not a wire capture: payload, addresses, ports, TTL/hop limit and TOS/traffic class are from the wire; IPv4 identification (0), flags (DF), IPv6 flow label (0), and both checksums (recomputed) are synthesized; there is no link-layer header."

    /// The first interface still present, else the first ever selected; fills the single-interface keys and leads the status summary.
    static func primary(_ interfaces: [MDNSInterfaceReport]) -> MDNSInterfaceReport? {
        interfaces.first { !$0.isRemoved } ?? interfaces.first
    }

    /// Top-level status, interfaceName and interfaceIndex describe the primary interface for older consumers; `interfaces` has every one, removed ones included.
    static func dictionary(interfaces: [MDNSInterfaceReport], stats: MDNSListenerStats) -> [String: Any] {
        let primary = primary(interfaces)
        var addresses: [String] = []
        if interfaces.contains(where: { $0.status.isListening }) { addresses.append("224.0.0.251:5353") }
        if interfaces.contains(where: { $0.ipv6Status.isListening }) { addresses.append("[ff02::fb]:5353") }
        return [
            "status": (primary?.status ?? .noInterface).description,
            "ipv6Status": (primary?.ipv6Status ?? .noInterface).description,
            "interfaceName": primary?.name ?? "",
            "interfaceIndex": Int(primary?.index ?? 0),
            "interfaces": interfaces.map(\.dictionary),
            "listenAddresses": addresses,
            "framesReceived": stats.datagramsReceived,
            "frames": stats.frames,
            "ipv4Frames": stats.ipv4Frames,
            "ipv6Frames": stats.ipv6Frames,
            "ownFrames": stats.ownFrames,
            "truncatedFrames": stats.truncatedFrames,
            "droppedTruncated": stats.droppedTruncated,
            "droppedUnbuildable": stats.droppedUnbuildable,
            "droppedUndecodable": stats.droppedUndecodable,
            "controlTruncatedFrames": stats.controlTruncatedFrames,
            "interfaceMismatchFrames": stats.interfaceMismatchFrames,
            "interfaceChanges": stats.interfaceChanges,
            "ttlFallbackFrames": stats.ttlMissing,
            "wallclockFallbackFrames": stats.frames - stats.kernelStamped,
            "ownAddressRefreshes": stats.ownAddressRefreshes,
            "ttlSource": stats.frames == 0 ? "n/a" : stats.ttlMissing == 0 ? "received" : "fixed-255 for \(stats.ttlMissing)",
            "tosSource": stats.frames == 0 ? "n/a" : stats.tosMissing == 0 ? "received" : "fixed-0 for \(stats.tosMissing)",
            "timestampSource": stats.frames == 0 ? "n/a" : stats.kernelStamped == stats.frames ? "kernel" : "wallclock for \(stats.frames - stats.kernelStamped)",
            "synthesizedFields": synthesizedFields
        ]
    }

    /// Written when stopTunnel ran before startup reached the listener, so the meta never inherits a previous session's status.
    static let notStartedStatus = "not started (tunnel stopped before startup)"

    /// The block for a session in which no listener object existed; `status` says why it did not start.
    static func dictionary(notStarted status: String) -> [String: Any] {
        ["status": status, "ipv6Status": status, "interfaces": [], "frames": 0]
    }

    /// One line for SharedSettings.mdnsListenerStatus: "listening on en0 (ifindex 13), bridge100 (ifindex 20)[, IPv6 only][; <name> failed: ...][; <name> removed ...]".
    /// MDNSEmptyState parses the interface names out of the "listening on" prefix; rewritten after every reconcile that changed the set.
    static func statusSummary(_ interfaces: [MDNSInterfaceReport]) -> String {
        guard let primary = primary(interfaces) else { return MDNSListenerStatus.noInterface.description }
        let listening = interfaces.filter(\.isListening)
        guard !listening.isEmpty else {
            return (primary.status.isFailed ? primary.status : primary.ipv6Status).description
        }
        var text = "listening on " + listening.map { "\($0.name) (ifindex \($0.index))" }.joined(separator: ", ")
        if !interfaces.contains(where: { $0.status.isListening }) { text += ", IPv6 only" }
        for failed in interfaces where !failed.isListening {
            text += "; \(failed.name) \((failed.status.isFailed ? failed.status : failed.ipv6Status).description)"
        }
        return text
    }
}

/// The selected interfaces' own addresses for direction matching, re-read at most every 30 seconds when a frame arrives from an address it does not know.
struct OwnAddressTracker: Equatable {
    static let minimumRefreshInterval: TimeInterval = 30
    private(set) var addresses: [[UInt8]]
    private(set) var lastRefresh: Date

    init(addresses: [[UInt8]] = [], at date: Date = .distantPast) {
        self.addresses = addresses
        self.lastRefresh = date
    }

    func needsRefresh(for source: [UInt8], at now: Date) -> Bool {
        !addresses.contains(source) && now.timeIntervalSince(lastRefresh) >= Self.minimumRefreshInterval
    }

    mutating func update(_ fresh: [[UInt8]], at now: Date) {
        addresses = fresh
        lastRefresh = now
    }
}

protocol MDNSListener: AnyObject {
    /// Primary (first) interface's statuses, kept for single-interface consumers.
    var status: MDNSListenerStatus { get }
    var ipv6Status: MDNSListenerStatus { get }
    var interfaces: [MDNSInterfaceReport] { get }
    var stats: MDNSListenerStats { get }
    var ownAddresses: [[UInt8]] { get }
    /// onDatagram says whether it turned the datagram into a frame, could not build one, or discarded it while tearing down.
    func start(onDatagram: @escaping (MDNSDatagram, MDNSReceiveInfo) -> MDNSDeliveryResult)
    func stop()
}

/// Multicast receive sockets for 224.0.0.251:5353 and [ff02::fb]:5353 on every multicast-capable interface, next to mDNSResponder (docs/mdns-listener-scope.md sections 2.2 and 2.5).
/// Each interface gets its own v4 and v6 socket; one interface or family failing never affects the others. Interfaces that appear or vanish mid-capture are reconciled on the network-change notification (section 2.6).
final class BSDMDNSListener: MDNSListener {
    static let group4: [UInt8] = [224, 0, 0, 251]
    static let group6: [UInt8] = [0xff, 0x02] + [UInt8](repeating: 0, count: 13) + [0xfb]
    static let port: UInt16 = 5353
    /// Trailing debounce for the network-change notification, which fires several times for one event (link, address, route).
    static let reconcileDelay: TimeInterval = 1.0

    private typealias Socket = (fd: Int32, source: DispatchSourceRead, interfaceIndex: UInt32)

    private let queue = DispatchQueue(label: "com.mDNSShark.mdns-listener")
    private let logger = Logger(subsystem: "com.mDNSShark.PacketTunnel", category: "mDNSListener")
    /// Mutated only while no event handler can run: in start() before any source is resumed, and on the queue (reconcile, stop), which every source shares.
    private var sockets: [Socket] = []
    private var buffer = [UInt8](repeating: 0, count: 65535)
    private var control = [UInt8](repeating: 0, count: 512)
    private var name = [UInt8](repeating: 0, count: MemoryLayout<sockaddr_storage>.size)

    /// Filled in start() before any read source runs, then appended to or marked removed only on the queue; readers go through the queue too.
    private var reports: [MDNSInterfaceReport] = []
    var interfaces: [MDNSInterfaceReport] { queue.sync { reports } }
    /// Snapshot taken in stop() before statuses become .stopped, so the meta shows how the listener ran.
    private var reportsAtStop: [MDNSInterfaceReport]?
    private var lookupStatus: MDNSListenerStatus = .idle
    private(set) var stats = MDNSListenerStats()
    private var own = OwnAddressTracker()
    private var selectedNames: Set<String> = []
    private var networkChangeToken: Int32 = NOTIFY_TOKEN_INVALID
    /// Kept so a reconcile can open sockets for an interface that appeared after start(); nil once stop() ran.
    private var onDatagram: ((MDNSDatagram, MDNSReceiveInfo) -> MDNSDeliveryResult)?
    /// The debounced reconcile waiting on the queue; replaced on every notification so a burst runs it once.
    private var pendingReconcile: DispatchWorkItem?
    var ownAddresses: [[UInt8]] { own.addresses }
    /// Called on the listener queue after a reconcile changed the interface set, with the full report list; the provider rewrites the status line from it.
    var onInterfacesChanged: (([MDNSInterfaceReport]) -> Void)?

    var status: MDNSListenerStatus { interfaces.first?.status ?? lookupStatus }
    var ipv6Status: MDNSListenerStatus { interfaces.first?.ipv6Status ?? lookupStatus }
    var interfaceName: String { interfaces.first?.name ?? "" }
    var interfaceIndex: UInt32 { interfaces.first?.index ?? 0 }
    var interfacesBeforeStop: [MDNSInterfaceReport] { reportsAtStop ?? interfaces }

    deinit {
        pendingReconcile?.cancel()
        for s in sockets { s.source.cancel() }
        if networkChangeToken != NOTIFY_TOKEN_INVALID { notify_cancel(networkChangeToken) }
    }

    func start(onDatagram: @escaping (MDNSDatagram, MDNSReceiveInfo) -> MDNSDeliveryResult) {
        self.onDatagram = onDatagram
        let selected = Self.captureInterfaces()
        guard !selected.isEmpty else {
            // Still watch for changes: an interface that comes up later (Wi-Fi joining after Start) is opened by the reconcile.
            lookupStatus = .noInterface
            logger.error("mDNS listener found no multicast-capable interface")
            registerNetworkChange()
            return
        }
        selectedNames = Set(selected.map(\.name))
        own.update(Self.addressUnion(selected), at: Date())

        // Every socket is opened and its read source created suspended before any source is resumed, so `sockets` and `reports`
        // are complete before the queue can run drain() or touch a counter; a suspended source never fires.
        var created: [Socket] = []
        for iface in selected {
            var report = MDNSInterfaceReport(name: iface.name, index: iface.index, functionalType: iface.functionalType)
            created += openSockets(for: iface, report: &report, families: [.ipv4, .ipv6])
            reports.append(report)
        }
        sockets = created
        registerNetworkChange()
        for s in sockets { s.source.resume() }
    }

    /// Cancels the read sources, which close their sockets in the cancel handler; returns only once no event handler is running.
    func stop() {
        dispatchPrecondition(condition: .notOnQueue(queue))
        queue.sync {
            pendingReconcile?.cancel()
            pendingReconcile = nil
            onDatagram = nil
            for s in sockets { s.source.cancel() }
            sockets = []
            cancelNetworkChange()
            reportsAtStop = reports
            for i in reports.indices {
                if reports[i].status.isListening { reports[i].status = .stopped }
                if reports[i].ipv6Status.isListening { reports[i].ipv6Status = .stopped }
            }
        }
    }

    // MARK: - Interface reconcile (docs/mdns-listener-scope.md section 2.6)

    /// Which selected interfaces to open and which open ones to close; pure so it is unit-tested.
    struct InterfaceChanges: Equatable {
        /// Selected now but not open: open both families and append a report.
        var added: [CaptureInterface] = []
        /// Open but no longer selected, or selected again under a new index: close both families, keep the report with its final counters.
        var removed: [MDNSInterfaceReport] = []
        /// Still open, v4 skipped for lack of an address, and the interface now has an IPv4 (DHCP finishing after the link came up): open v4 only.
        var ipv4Appeared: [CaptureInterface] = []

        var isEmpty: Bool { added.isEmpty && removed.isEmpty && ipv4Appeared.isEmpty }
    }

    /// Diff of the active reports against a fresh selection. Identity is name plus ifindex, so an interface recreated under a new index is closed and reopened; removed reports are ignored on input.
    static func interfaceChanges(active: [MDNSInterfaceReport], selected: [CaptureInterface]) -> InterfaceChanges {
        var changes = InterfaceChanges()
        let open = active.filter { !$0.isRemoved }
        for report in open where !selected.contains(where: { $0.name == report.name && $0.index == report.index }) {
            changes.removed.append(report)
        }
        for iface in selected {
            guard let report = open.first(where: { $0.name == iface.name && $0.index == iface.index }) else {
                changes.added.append(iface)
                continue
            }
            if report.status.isUnavailable, iface.ipv4 != nil { changes.ipv4Appeared.append(iface) }
        }
        return changes
    }

    /// Runs on the queue, so no event handler is executing while `sockets` and `reports` change. Order per interface: cancel the vanished
    /// interfaces' sources (their fds close in the cancel handler, after this block) and forget their sockets, then open the new interfaces'
    /// sockets with suspended sources, append their reports, add them to `sockets`, and only then resume, mirroring start().
    private func reconcileInterfaces() {
        dispatchPrecondition(condition: .onQueue(queue))
        guard onDatagram != nil else { return }
        let selected = Self.captureInterfaces()
        let changes = Self.interfaceChanges(active: reports, selected: selected)
        guard !changes.isEmpty else { return }

        for gone in changes.removed {
            for s in sockets where s.interfaceIndex == gone.index { s.source.cancel() }
            sockets.removeAll { $0.interfaceIndex == gone.index }
            if let i = reports.firstIndex(where: { $0.name == gone.name && $0.index == gone.index && !$0.isRemoved }) {
                reports[i].markRemoved()
                let frames = reports[i].frames
                logger.info("mDNS listener \(gone.name, privacy: .public) (ifindex \(gone.index)) removed after \(frames) frames")
            }
        }

        var created: [Socket] = []
        for iface in changes.added {
            var report = MDNSInterfaceReport(name: iface.name, index: iface.index, functionalType: iface.functionalType)
            created += openSockets(for: iface, report: &report, families: [.ipv4, .ipv6])
            reports.append(report)
        }
        for iface in changes.ipv4Appeared {
            guard let i = reports.firstIndex(where: { $0.name == iface.name && $0.index == iface.index && !$0.isRemoved }) else { continue }
            created += openSockets(for: iface, report: &reports[i], families: [.ipv4])
        }
        sockets += created
        for s in created { s.source.resume() }

        selectedNames = Set(selected.map(\.name))
        own.update(Self.addressUnion(selected), at: Date())
        stats.interfaceChanges += 1
        onInterfacesChanged?(reports)
    }

    private enum Family { case ipv4, ipv6 }

    /// Opens the requested families for one interface, records each outcome in `report` and returns the sockets with suspended sources; failures stay per family.
    private func openSockets(for iface: CaptureInterface, report: inout MDNSInterfaceReport, families: [Family]) -> [Socket] {
        guard let onDatagram else { return [] }
        var created: [Socket] = []
        if families.contains(.ipv4) {
            switch openIPv4(iface) {
            case .success(let fd): created.append(makeSource(fd, interfaceIndex: iface.index, onDatagram)); report.status = .listening(interface: iface.name, index: iface.index)
            case .failure(let failed): report.status = failed.status
            }
        }
        if families.contains(.ipv6) {
            switch openIPv6(iface) {
            case .success(let fd): created.append(makeSource(fd, interfaceIndex: iface.index, onDatagram)); report.ipv6Status = .listening(interface: iface.name, index: iface.index)
            case .failure(let failed): report.ipv6Status = failed.status
            }
        }
        let v4 = report.status.description, v6 = report.ipv6Status.description
        logger.info("mDNS listener \(iface.name, privacy: .public) (\(InterfaceFunctionalType.name(iface.functionalType), privacy: .public)) v4 \(v4, privacy: .public), v6 \(v6, privacy: .public)")
        return created
    }

    // MARK: - Socket setup

    private struct Failure: Error { let status: MDNSListenerStatus }

    private func openIPv4(_ iface: CaptureInterface) -> Result<Int32, Failure> {
        guard let ipv4 = iface.ipv4 else { return .failure(Failure(status: .unavailable(reason: "no IPv4 address on \(iface.name)"))) }
        let sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard sock >= 0 else { return .failure(Failure(status: .failed(stage: "socket", errno: errno))) }
        do {
            try setOptions(sock, [("SO_REUSEADDR", SOL_SOCKET, SO_REUSEADDR), ("SO_REUSEPORT", SOL_SOCKET, SO_REUSEPORT),
                                  ("SO_TIMESTAMP", SOL_SOCKET, SO_TIMESTAMP), ("IP_RECVTTL", IPPROTO_IP, IP_RECVTTL),
                                  ("IP_RECVIF", IPPROTO_IP, IP_RECVIF), ("IP_RECVDSTADDR", IPPROTO_IP, IP_RECVDSTADDR)])
            setOptionalOptions(sock, [("IP_RECVTOS", IPPROTO_IP, IPv4SocketOption.recvTOS)])
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = Self.port.bigEndian
            addr.sin_addr = in_addr(s_addr: UInt32(Self.group4[0]) | UInt32(Self.group4[1]) << 8 | UInt32(Self.group4[2]) << 16 | UInt32(Self.group4[3]) << 24)
            let rc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
            guard rc == 0 else { throw Failure(status: .failed(stage: "bind", errno: errno)) }
            var idx = Int32(iface.index)
            guard setsockopt(sock, IPPROTO_IP, IP_BOUND_IF, &idx, 4) == 0 else { throw Failure(status: .failed(stage: "IP_BOUND_IF", errno: errno)) }
            var mreq = ip_mreq()
            mreq.imr_multiaddr = addr.sin_addr
            mreq.imr_interface = ipv4
            guard setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, socklen_t(MemoryLayout<ip_mreq>.size)) == 0 else {
                throw Failure(status: .failed(stage: "IP_ADD_MEMBERSHIP", errno: errno))
            }
        } catch let f as Failure {
            close(sock); return .failure(f)
        } catch { close(sock); return .failure(Failure(status: .failed(stage: "setup", errno: errno))) }
        return .success(sock)
    }

    private func openIPv6(_ iface: CaptureInterface) -> Result<Int32, Failure> {
        let sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        guard sock >= 0 else { return .failure(Failure(status: .failed(stage: "socket6", errno: errno))) }
        do {
            try setOptions(sock, [("SO_REUSEADDR", SOL_SOCKET, SO_REUSEADDR), ("SO_REUSEPORT", SOL_SOCKET, SO_REUSEPORT),
                                  ("SO_TIMESTAMP", SOL_SOCKET, SO_TIMESTAMP), ("IPV6_V6ONLY", IPPROTO_IPV6, IPV6_V6ONLY),
                                  ("IPV6_RECVPKTINFO", IPPROTO_IPV6, IPv6SocketOption.recvPacketInfo), ("IPV6_RECVHOPLIMIT", IPPROTO_IPV6, IPv6SocketOption.recvHopLimit)])
            setOptionalOptions(sock, [("IPV6_RECVTCLASS", IPPROTO_IPV6, IPv6SocketOption.recvTrafficClass)])
            var addr = sockaddr_in6()
            addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = Self.port.bigEndian
            addr.sin6_scope_id = iface.index
            withUnsafeMutableBytes(of: &addr.sin6_addr) { $0.copyBytes(from: Self.group6) }
            let rc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(sock, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
            }
            guard rc == 0 else { throw Failure(status: .failed(stage: "bind6", errno: errno)) }
            var idx = Int32(iface.index)
            guard setsockopt(sock, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, 4) == 0 else { throw Failure(status: .failed(stage: "IPV6_BOUND_IF", errno: errno)) }
            var mreq = ipv6_mreq()
            mreq.ipv6mr_multiaddr = addr.sin6_addr
            mreq.ipv6mr_interface = iface.index
            guard setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, socklen_t(MemoryLayout<ipv6_mreq>.size)) == 0 else {
                throw Failure(status: .failed(stage: "IPV6_JOIN_GROUP", errno: errno))
            }
        } catch let f as Failure {
            close(sock); return .failure(f)
        } catch { close(sock); return .failure(Failure(status: .failed(stage: "setup6", errno: errno))) }
        return .success(sock)
    }

    private func setOptions(_ sock: Int32, _ options: [(String, Int32, Int32)]) throws {
        var on: Int32 = 1
        for (name, level, option) in options where setsockopt(sock, level, option, &on, 4) != 0 {
            throw Failure(status: .failed(stage: name, errno: errno))
        }
    }

    /// Options whose failure only costs a field (it is reported as missing in the meta), so the socket carries on.
    private func setOptionalOptions(_ sock: Int32, _ options: [(String, Int32, Int32)]) {
        var on: Int32 = 1
        for (name, level, option) in options where setsockopt(sock, level, option, &on, 4) != 0 {
            logger.error("optional socket option \(name, privacy: .public) failed, errno \(errno)")
        }
    }

    /// Returns the socket with a suspended read source; start() resumes every source only after `sockets` holds them all.
    private func makeSource(_ sock: Int32, interfaceIndex: UInt32, _ onDatagram: @escaping (MDNSDatagram, MDNSReceiveInfo) -> MDNSDeliveryResult) -> Socket {
        _ = fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK)
        let src = DispatchSource.makeReadSource(fileDescriptor: sock, queue: queue)
        src.setEventHandler { [weak self] in self?.drain(sock, interfaceIndex: interfaceIndex, onDatagram) }
        // libdispatch needs the fd open until cancellation completes, so the cancel handler owns the close.
        src.setCancelHandler { close(sock) }
        return (sock, src, interfaceIndex)
    }

    // MARK: - Receive

    private func drain(_ sock: Int32, interfaceIndex: UInt32, _ onDatagram: (MDNSDatagram, MDNSReceiveInfo) -> MDNSDeliveryResult) {
        while sockets.contains(where: { $0.fd == sock }) {
            var controlLen = 0
            var flags: Int32 = 0
            let n: ssize_t = buffer.withUnsafeMutableBytes { bp in
                control.withUnsafeMutableBytes { cp in
                    name.withUnsafeMutableBytes { np in
                        var iov = iovec(iov_base: bp.baseAddress, iov_len: bp.count)
                        return withUnsafeMutablePointer(to: &iov) { ip in
                            var msg = msghdr(msg_name: np.baseAddress, msg_namelen: socklen_t(np.count),
                                             msg_iov: ip, msg_iovlen: 1, msg_control: cp.baseAddress, msg_controllen: socklen_t(cp.count), msg_flags: 0)
                            let r = recvmsg(sock, &msg, 0)
                            controlLen = Int(msg.msg_controllen)
                            flags = msg.msg_flags
                            return r
                        }
                    }
                }
            }
            if n < 0 {
                if errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR {
                    logger.error("recvmsg errno \(errno)")
                }
                return
            }
            let received = Date()
            stats.datagramsReceived += 1
            let controlTruncated = flags & MSG_CTRUNC != 0
            if controlTruncated { stats.controlTruncatedFrames += 1 }
            // A truncated payload would be written as a shorter, valid-looking packet, so it is counted instead.
            if flags & MSG_TRUNC != 0 { stats.droppedTruncated += 1; continue }
            let cmsgs = control.withUnsafeBytes { MDNSControlMessages.parse($0, length: controlLen) }
            guard let datagram = Self.makeDatagram(sourceAddress: name, payload: Data(buffer[0..<Int(n)]), cmsgs: cmsgs, received: received) else {
                stats.droppedUndecodable += 1
                continue
            }
            // An unknown source may be a new address of our own (DHCP renewal, IPv6 temporary rotation), so re-read the interfaces, rate limited.
            if own.needsRefresh(for: datagram.source, at: received) { refreshOwnAddresses(at: received) }
            // The kernel only delivers a group datagram to sockets joined on its arrival interface, so this stays 0; counted rather than dropped in case a bridge reports a member's index.
            if let arrival = cmsgs.interfaceIndex, arrival != Int(interfaceIndex) { stats.interfaceMismatchFrames += 1 }
            let info = MDNSReceiveInfo(interfaceIndex: cmsgs.interfaceIndex ?? Int(interfaceIndex), socketInterfaceIndex: interfaceIndex,
                                       controlTruncated: controlTruncated, kernelStamped: cmsgs.kernelTimestamp != nil)
            switch onDatagram(datagram, info) {
            case .frame:
                stats.recordDelivered(datagram, own: ownAddresses.contains(datagram.source), kernelStamped: info.kernelStamped)
                // The active report, since a removed one may still carry this index after the kernel reused it.
                if let i = reports.firstIndex(where: { $0.index == interfaceIndex && !$0.isRemoved }) { reports[i].recordDelivered(datagram) }
            case .unbuildable:
                stats.droppedUnbuildable += 1
            case .discarded:
                break
            }
        }
    }

    /// Re-reads every selected interface's addresses on the listener queue; keeps the old list when getifaddrs fails.
    private func refreshOwnAddresses(at now: Date) {
        own.update(Self.interfaceAddresses(named: selectedNames) ?? own.addresses, at: now)
        stats.ownAddressRefreshes += 1
    }

    /// Wakes on the system's network-change notification: own addresses are re-read at once so a new one is known before its first frame,
    /// and the interface set is reconciled after a debounce so a burst of notifications opens or closes each interface once.
    private func registerNetworkChange() {
        // kNotifySCNetworkChange from SystemConfiguration/SCDynamicStore; Swift does not import the constant.
        // Registered on the queue so the handler never sees the token before it is stored.
        queue.sync {
            var token: Int32 = 0
            let status = notify_register_dispatch("com.apple.system.config.network_change", &token, queue) { [weak self] t in
                guard let self, t == self.networkChangeToken else { return }
                self.refreshOwnAddresses(at: Date())
                self.scheduleReconcile()
            }
            if status == NOTIFY_STATUS_OK {
                networkChangeToken = token
            } else {
                logger.error("network change notification registration failed, status \(status)")
            }
        }
    }

    /// Replaces any waiting reconcile so only the last notification of a burst runs it; stop() cancels the pending item and reconcile checks onDatagram anyway.
    private func scheduleReconcile() {
        pendingReconcile?.cancel()
        let item = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.pendingReconcile = nil
            self.reconcileInterfaces()
        }
        pendingReconcile = item
        queue.asyncAfter(deadline: .now() + Self.reconcileDelay, execute: item)
    }

    private func cancelNetworkChange() {
        guard networkChangeToken != NOTIFY_TOKEN_INVALID else { return }
        notify_cancel(networkChangeToken)
        networkChangeToken = NOTIFY_TOKEN_INVALID
    }

    /// Builds the datagram from one recvmsg result (sockaddr bytes, payload, control data); nil for a family that is not IPv4 or IPv6.
    static func makeDatagram(sourceAddress: [UInt8], payload: Data, cmsgs: MDNSControlMessages, received: Date) -> MDNSDatagram? {
        guard sourceAddress.count >= 2 else { return nil }
        let family = Int32(sourceAddress[1])
        let port = UInt16(sourceAddress.count >= 4 ? sourceAddress[2] : 0) << 8 | UInt16(sourceAddress.count >= 4 ? sourceAddress[3] : 0)
        if family == AF_INET, sourceAddress.count >= 8 {
            return MDNSDatagram(payload: payload, source: Array(sourceAddress[4..<8]), destination: cmsgs.destination ?? group4,
                                sourcePort: port, destinationPort: Self.port, ttl: cmsgs.ttl,
                                trafficClass: cmsgs.trafficClass, timestamp: cmsgs.kernelTimestamp ?? received)
        }
        if family == AF_INET6, sourceAddress.count >= 24 {
            return MDNSDatagram(payload: payload, source: Array(sourceAddress[8..<24]), destination: cmsgs.destination6 ?? group6,
                                sourcePort: port, destinationPort: Self.port, ttl: cmsgs.hopLimit,
                                trafficClass: cmsgs.trafficClass, timestamp: cmsgs.kernelTimestamp ?? received)
        }
        return nil
    }

    // MARK: - Interface selection

    /// The interfaces to listen on right now: getifaddrs plus SIOCGIFFUNCTIONALTYPE, filtered by selectInterfaces.
    static func captureInterfaces() -> [CaptureInterface] {
        selectInterfaces(interfaceDescriptors())
    }

    /// Pure selection mirroring mDNSResponder's MulticastInterface rule: up, IFF_MULTICAST, not point-to-point, not loopback,
    /// not AWDL or the internal coprocessor link, with at least one address. Deduped by name, Wi-Fi infrastructure first, then interfaces with IPv4.
    static func selectInterfaces(_ descriptors: [InterfaceDescriptor]) -> [CaptureInterface] {
        var merged: [InterfaceDescriptor] = []
        for d in descriptors {
            if let i = merged.firstIndex(where: { $0.name == d.name }) {
                merged[i].addresses += d.addresses.filter { !merged[i].addresses.contains($0) }
                merged[i].ipv4Netmasks.merge(d.ipv4Netmasks) { first, _ in first }
            } else {
                merged.append(d)
            }
        }
        let eligible = merged.filter { d in
            d.index != 0
                && d.flags & IFF_UP != 0 && d.flags & IFF_MULTICAST != 0
                && d.flags & IFF_POINTOPOINT == 0 && d.flags & IFF_LOOPBACK == 0
                && !InterfaceFunctionalType.excludes(d.functionalType, name: d.name)
                && !d.addresses.isEmpty
        }
        func rank(_ e: (offset: Int, element: InterfaceDescriptor)) -> (Int, Int, Int) {
            (e.element.functionalType == InterfaceFunctionalType.wifiInfra ? 0 : 1, e.element.addresses.contains { $0.count == 4 } ? 0 : 1, e.offset)
        }
        return eligible.enumerated()
            .sorted { rank($0) < rank($1) }
            .map { CaptureInterface(name: $0.element.name, index: $0.element.index, functionalType: $0.element.functionalType, addresses: $0.element.addresses) }
    }

    /// Every address of the selected interfaces, first occurrence kept, for OwnAddressTracker.
    static func addressUnion(_ interfaces: [CaptureInterface]) -> [[UInt8]] {
        var out: [[UInt8]] = []
        for a in interfaces.flatMap(\.addresses) where !out.contains(a) { out.append(a) }
        return out
    }

    /// One descriptor per interface name in getifaddrs order; nil functional type when the ioctl fails. An IPv4 netmask is kept only when its
    /// sockaddr is a well-formed AF_INET (a lo0 alias has been seen with sa_family 0), so the LAN route fails closed on a malformed one.
    static func interfaceDescriptors() -> [InterfaceDescriptor] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var descriptors: [InterfaceDescriptor] = []
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let name = String(cString: p.pointee.ifa_name)
            if !descriptors.contains(where: { $0.name == name }) {
                descriptors.append(InterfaceDescriptor(name: name, index: if_nametoindex(name), flags: Int32(truncatingIfNeeded: p.pointee.ifa_flags),
                                                       functionalType: nil, addresses: []))
            }
            if let address = address(of: p.pointee.ifa_addr), let i = descriptors.firstIndex(where: { $0.name == name }) {
                descriptors[i].addresses.append(address)
                if address.count == 4, let mask = self.address(of: p.pointee.ifa_netmask), mask.count == 4 {
                    descriptors[i].ipv4Netmasks[address] = mask
                }
            }
        }
        let sock = socket(AF_INET, SOCK_DGRAM, 0)
        defer { if sock >= 0 { close(sock) } }
        if sock >= 0 {
            for i in descriptors.indices { descriptors[i].functionalType = functionalType(of: descriptors[i].name, socket: sock) }
        }
        return descriptors
    }

    /// SIOCGIFFUNCTIONALTYPE for one interface; nil when the kernel refuses it (utun on macOS does).
    static func functionalType(of name: String, socket sock: Int32) -> UInt32? {
        var ifr = ifreq()
        withUnsafeMutableBytes(of: &ifr.ifr_name) { dst in
            name.utf8CString.withUnsafeBytes { src in dst.copyBytes(from: src.prefix(dst.count - 1)) }
        }
        let rc = withUnsafeMutablePointer(to: &ifr) { ioctl(sock, InterfaceFunctionalType.ioctlRequest, $0) }
        return rc == 0 ? ifr.ifr_ifru.ifru_functional_type : nil
    }

    /// Current IPv4 and IPv6 addresses of one interface; nil when getifaddrs fails.
    static func interfaceAddresses(named name: String) -> [[UInt8]]? {
        interfaceAddresses(named: [name])
    }

    /// Current IPv4 and IPv6 addresses of the named interfaces in one getifaddrs pass; nil when it fails.
    static func interfaceAddresses(named names: Set<String>) -> [[UInt8]]? {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return nil }
        defer { freeifaddrs(head) }
        var addresses: [[UInt8]] = []
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) where names.contains(String(cString: p.pointee.ifa_name)) {
            if let a = address(of: p.pointee.ifa_addr), !addresses.contains(a) { addresses.append(a) }
        }
        return addresses
    }

    private static func address(of sa: UnsafeMutablePointer<sockaddr>?) -> [UInt8]? {
        guard let sa else { return nil }
        if sa.pointee.sa_family == UInt8(AF_INET) {
            let a = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
            return [UInt8(a & 0xFF), UInt8(a >> 8 & 0xFF), UInt8(a >> 16 & 0xFF), UInt8(a >> 24 & 0xFF)]
        }
        if sa.pointee.sa_family == UInt8(AF_INET6) {
            var a6 = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
            return withUnsafeBytes(of: &a6) { Array($0) }
        }
        return nil
    }
}
