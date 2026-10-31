// PacketTunnel/MDNSListener.swift
// Shared into the mDNSShark target (pbxproj exception set) so the pure parts (cmsg parsing, datagram assembly, meta) are unit-tested.
import Foundation
import Darwin
import os

/// RFC 3542 IPv6 socket options that Swift cannot see because netinet6/in6.h hides them behind __APPLE_USE_RFC_3542 (values from the iOS SDK header).
enum IPv6SocketOption {
    static let recvPacketInfo: Int32 = 61   // IPV6_RECVPKTINFO
    static let recvHopLimit: Int32 = 37     // IPV6_RECVHOPLIMIT
    static let packetInfo: Int32 = 46       // IPV6_PKTINFO (IPV6_3542PKTINFO), cmsg type carrying in6_pktinfo
    static let hopLimit: Int32 = 47         // IPV6_HOPLIMIT (IPV6_3542HOPLIMIT), cmsg type carrying an Int32
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
    /// SO_TIMESTAMP receive time; the wire time when the socket buffer or the queue was behind.
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
                } else if h.cmsg_type == IP_RECVDSTADDR, dataLen >= 4 {
                    out.destination = Array(buffer[dataOff..<dataOff + 4])
                } else if h.cmsg_type == IP_RECVIF, dataLen >= 4 {
                    // sockaddr_dl: sdl_len, sdl_family, then sdl_index in host order.
                    out.interfaceIndex = Int(buffer.loadUnaligned(fromByteOffset: dataOff + 2, as: UInt16.self))
                }
            } else if h.cmsg_level == IPPROTO_IPV6 {
                if h.cmsg_type == IPv6SocketOption.hopLimit, dataLen >= 4 {
                    out.hopLimit = UInt8(clamping: buffer.loadUnaligned(fromByteOffset: dataOff, as: Int32.self))
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
    let interfaceIndex: Int?
    let truncated: Bool
    let kernelStamped: Bool
}

/// Counters for capture-meta.json, updated on the listener queue and read after stop().
struct MDNSListenerStats: Equatable {
    var frames = 0
    var ipv4Frames = 0
    var ipv6Frames = 0
    var ownFrames = 0
    var truncatedFrames = 0
    var kernelStamped = 0
    var ttlMissing = 0
}

enum MDNSListenerStatus: Equatable {
    case idle
    case listening(interface: String, index: UInt32)
    case failed(stage: String, errno: Int32)
    case stopped

    var description: String {
        switch self {
        case .idle: return "idle"
        case .listening(let name, let index): return "listening on \(name) (ifindex \(index))"
        case .failed(let stage, let code): return "failed: \(stage) errno \(code) (\(String(cString: strerror(code))))"
        case .stopped: return "stopped"
        }
    }

    var isListening: Bool {
        if case .listening = self { return true }
        return false
    }
}

/// The `mdnsListener` object in capture-meta.json.
enum MDNSListenerMeta {
    static func dictionary(status: MDNSListenerStatus, ipv6Status: MDNSListenerStatus,
                           interfaceName: String, interfaceIndex: UInt32, stats: MDNSListenerStats) -> [String: Any] {
        var addresses: [String] = []
        if status.isListening { addresses.append("224.0.0.251:5353") }
        if ipv6Status.isListening { addresses.append("[ff02::fb]:5353") }
        return [
            "status": status.description,
            "ipv6Status": ipv6Status.description,
            "interfaceName": interfaceName,
            "interfaceIndex": Int(interfaceIndex),
            "listenAddresses": addresses,
            "frames": stats.frames,
            "ipv4Frames": stats.ipv4Frames,
            "ipv6Frames": stats.ipv6Frames,
            "ownFrames": stats.ownFrames,
            "truncatedFrames": stats.truncatedFrames,
            "ttlSource": stats.ttlMissing == 0 ? "received" : "fixed-255 for \(stats.ttlMissing)",
            "timestampSource": stats.kernelStamped == stats.frames ? "kernel" : "wallclock for \(stats.frames - stats.kernelStamped)"
        ]
    }
}

protocol MDNSListener: AnyObject {
    var status: MDNSListenerStatus { get }
    var ipv6Status: MDNSListenerStatus { get }
    var stats: MDNSListenerStats { get }
    var ownAddresses: [[UInt8]] { get }
    func start(onDatagram: @escaping (MDNSDatagram, MDNSReceiveInfo) -> Void)
    func stop()
}

/// Multicast receive sockets for 224.0.0.251:5353 and [ff02::fb]:5353 next to mDNSResponder, per docs/mdns-listener-scope.md section 2.2. IPv6 failure never affects IPv4.
final class BSDMDNSListener: MDNSListener {
    static let group4: [UInt8] = [224, 0, 0, 251]
    static let group6: [UInt8] = [0xff, 0x02] + [UInt8](repeating: 0, count: 13) + [0xfb]
    static let port: UInt16 = 5353

    private let queue = DispatchQueue(label: "com.mDNSShark.mdns-listener")
    private let logger = Logger(subsystem: "com.mDNSShark.PacketTunnel", category: "mDNSListener")
    private var sockets: [(fd: Int32, source: DispatchSourceRead)] = []
    private var buffer = [UInt8](repeating: 0, count: 65535)
    private var control = [UInt8](repeating: 0, count: 512)
    private var name = [UInt8](repeating: 0, count: MemoryLayout<sockaddr_storage>.size)

    private(set) var status: MDNSListenerStatus = .idle
    private(set) var ipv6Status: MDNSListenerStatus = .idle
    private(set) var stats = MDNSListenerStats()
    private(set) var ownAddresses: [[UInt8]] = []
    private(set) var interfaceName = ""
    private(set) var interfaceIndex: UInt32 = 0

    func start(onDatagram: @escaping (MDNSDatagram, MDNSReceiveInfo) -> Void) {
        guard let wifi = Self.wifiInterface() else {
            status = .failed(stage: "interface lookup", errno: ENXIO)
            ipv6Status = status
            return
        }
        interfaceName = wifi.name
        interfaceIndex = wifi.index
        ownAddresses = wifi.addresses

        switch openIPv4(wifi) {
        case .success(let fd): attach(fd, onDatagram); status = .listening(interface: wifi.name, index: wifi.index)
        case .failure(let failed): status = failed.status
        }
        switch openIPv6(wifi) {
        case .success(let fd): attach(fd, onDatagram); ipv6Status = .listening(interface: wifi.name, index: wifi.index)
        case .failure(let failed): ipv6Status = failed.status
        }
        logger.info("mDNS listener v4 \(self.status.description, privacy: .public), v6 \(self.ipv6Status.description, privacy: .public)")
    }

    /// Cancels the read sources and closes the sockets; returns only once no event handler is running.
    func stop() {
        dispatchPrecondition(condition: .notOnQueue(queue))
        queue.sync {
            for s in sockets { s.source.cancel(); close(s.fd) }
            sockets = []
            if status.isListening { status = .stopped }
            if ipv6Status.isListening { ipv6Status = .stopped }
        }
    }

    // MARK: - Socket setup

    private struct Failure: Error { let status: MDNSListenerStatus }

    private func openIPv4(_ wifi: WiFiInterface) -> Result<Int32, Failure> {
        let sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard sock >= 0 else { return .failure(Failure(status: .failed(stage: "socket", errno: errno))) }
        do {
            try setOptions(sock, [("SO_REUSEADDR", SOL_SOCKET, SO_REUSEADDR), ("SO_REUSEPORT", SOL_SOCKET, SO_REUSEPORT),
                                  ("SO_TIMESTAMP", SOL_SOCKET, SO_TIMESTAMP), ("IP_RECVTTL", IPPROTO_IP, IP_RECVTTL),
                                  ("IP_RECVIF", IPPROTO_IP, IP_RECVIF), ("IP_RECVDSTADDR", IPPROTO_IP, IP_RECVDSTADDR)])
            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = Self.port.bigEndian
            addr.sin_addr = in_addr(s_addr: UInt32(Self.group4[0]) | UInt32(Self.group4[1]) << 8 | UInt32(Self.group4[2]) << 16 | UInt32(Self.group4[3]) << 24)
            let rc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
            guard rc == 0 else { throw Failure(status: .failed(stage: "bind", errno: errno)) }
            var idx = Int32(wifi.index)
            guard setsockopt(sock, IPPROTO_IP, IP_BOUND_IF, &idx, 4) == 0 else { throw Failure(status: .failed(stage: "IP_BOUND_IF", errno: errno)) }
            var mreq = ip_mreq()
            mreq.imr_multiaddr = addr.sin_addr
            mreq.imr_interface = wifi.ipv4
            guard setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, socklen_t(MemoryLayout<ip_mreq>.size)) == 0 else {
                throw Failure(status: .failed(stage: "IP_ADD_MEMBERSHIP", errno: errno))
            }
        } catch let f as Failure {
            close(sock); return .failure(f)
        } catch { close(sock); return .failure(Failure(status: .failed(stage: "setup", errno: errno))) }
        return .success(sock)
    }

    private func openIPv6(_ wifi: WiFiInterface) -> Result<Int32, Failure> {
        let sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP)
        guard sock >= 0 else { return .failure(Failure(status: .failed(stage: "socket6", errno: errno))) }
        do {
            try setOptions(sock, [("SO_REUSEADDR", SOL_SOCKET, SO_REUSEADDR), ("SO_REUSEPORT", SOL_SOCKET, SO_REUSEPORT),
                                  ("SO_TIMESTAMP", SOL_SOCKET, SO_TIMESTAMP), ("IPV6_V6ONLY", IPPROTO_IPV6, IPV6_V6ONLY),
                                  ("IPV6_RECVPKTINFO", IPPROTO_IPV6, IPv6SocketOption.recvPacketInfo), ("IPV6_RECVHOPLIMIT", IPPROTO_IPV6, IPv6SocketOption.recvHopLimit)])
            var addr = sockaddr_in6()
            addr.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            addr.sin6_family = sa_family_t(AF_INET6)
            addr.sin6_port = Self.port.bigEndian
            addr.sin6_scope_id = wifi.index
            withUnsafeMutableBytes(of: &addr.sin6_addr) { $0.copyBytes(from: Self.group6) }
            let rc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(sock, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
            }
            guard rc == 0 else { throw Failure(status: .failed(stage: "bind6", errno: errno)) }
            var idx = Int32(wifi.index)
            guard setsockopt(sock, IPPROTO_IPV6, IPV6_BOUND_IF, &idx, 4) == 0 else { throw Failure(status: .failed(stage: "IPV6_BOUND_IF", errno: errno)) }
            var mreq = ipv6_mreq()
            mreq.ipv6mr_multiaddr = addr.sin6_addr
            mreq.ipv6mr_interface = wifi.index
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

    private func attach(_ sock: Int32, _ onDatagram: @escaping (MDNSDatagram, MDNSReceiveInfo) -> Void) {
        _ = fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK)
        let src = DispatchSource.makeReadSource(fileDescriptor: sock, queue: queue)
        src.setEventHandler { [weak self] in self?.drain(sock, onDatagram) }
        src.resume()
        sockets.append((sock, src))
    }

    // MARK: - Receive

    private func drain(_ sock: Int32, _ onDatagram: (MDNSDatagram, MDNSReceiveInfo) -> Void) {
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
            let cmsgs = control.withUnsafeBytes { MDNSControlMessages.parse($0, length: controlLen) }
            guard let datagram = Self.makeDatagram(sourceAddress: name, payload: Data(buffer[0..<Int(n)]), cmsgs: cmsgs, received: received) else { continue }
            let truncated = flags & MSG_TRUNC != 0
            stats.frames += 1
            if datagram.source.count == 4 { stats.ipv4Frames += 1 } else { stats.ipv6Frames += 1 }
            if ownAddresses.contains(datagram.source) { stats.ownFrames += 1 }
            if truncated { stats.truncatedFrames += 1 }
            if cmsgs.kernelTimestamp != nil { stats.kernelStamped += 1 }
            if datagram.ttl == nil { stats.ttlMissing += 1 }
            onDatagram(datagram, MDNSReceiveInfo(interfaceIndex: cmsgs.interfaceIndex, truncated: truncated, kernelStamped: cmsgs.kernelTimestamp != nil))
        }
    }

    /// Builds the datagram from one recvmsg result (sockaddr bytes, payload, control data); nil for a family that is not IPv4 or IPv6.
    static func makeDatagram(sourceAddress: [UInt8], payload: Data, cmsgs: MDNSControlMessages, received: Date) -> MDNSDatagram? {
        guard sourceAddress.count >= 2 else { return nil }
        let family = Int32(sourceAddress[1])
        let port = UInt16(sourceAddress.count >= 4 ? sourceAddress[2] : 0) << 8 | UInt16(sourceAddress.count >= 4 ? sourceAddress[3] : 0)
        if family == AF_INET, sourceAddress.count >= 8 {
            return MDNSDatagram(payload: payload, source: Array(sourceAddress[4..<8]), destination: cmsgs.destination ?? group4,
                                sourcePort: port, destinationPort: Self.port, ttl: cmsgs.ttl,
                                timestamp: cmsgs.kernelTimestamp ?? received)
        }
        if family == AF_INET6, sourceAddress.count >= 24 {
            return MDNSDatagram(payload: payload, source: Array(sourceAddress[8..<24]), destination: cmsgs.destination6 ?? group6,
                                sourcePort: port, destinationPort: Self.port, ttl: cmsgs.hopLimit,
                                timestamp: cmsgs.kernelTimestamp ?? received)
        }
        return nil
    }

    // MARK: - Interface lookup

    struct WiFiInterface {
        let name: String
        let index: UInt32
        let ipv4: in_addr
        /// Every IPv4 and IPv6 address on the interface, for direction matching.
        let addresses: [[UInt8]]
    }

    /// First up, multicast-capable en* interface with an IPv4 address (en0 on iPhone).
    static func wifiInterface() -> WiFiInterface? {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return nil }
        defer { freeifaddrs(head) }
        let all = Array(sequence(first: first, next: { $0.pointee.ifa_next }))
        guard let primary = all.first(where: { p in
            let name = String(cString: p.pointee.ifa_name)
            let flags = Int32(p.pointee.ifa_flags)
            return name.hasPrefix("en") && p.pointee.ifa_addr?.pointee.sa_family == UInt8(AF_INET)
                && flags & IFF_UP != 0 && flags & IFF_MULTICAST != 0
        }) else { return nil }
        let name = String(cString: primary.pointee.ifa_name)
        let ipv4 = primary.pointee.ifa_addr!.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
        var addresses: [[UInt8]] = []
        for p in all where String(cString: p.pointee.ifa_name) == name {
            guard let sa = p.pointee.ifa_addr else { continue }
            if sa.pointee.sa_family == UInt8(AF_INET) {
                let a = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr.s_addr }
                addresses.append([UInt8(a & 0xFF), UInt8(a >> 8 & 0xFF), UInt8(a >> 16 & 0xFF), UInt8(a >> 24 & 0xFF)])
            } else if sa.pointee.sa_family == UInt8(AF_INET6) {
                var a6 = sa.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
                addresses.append(withUnsafeBytes(of: &a6) { Array($0) })
            }
        }
        return WiFiInterface(name: name, index: if_nametoindex(name), ipv4: ipv4, addresses: addresses)
    }
}
