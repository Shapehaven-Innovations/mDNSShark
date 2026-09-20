import Foundation
import DeviceFingerprint
import os

/// Sends an ASUS `infosvr` discovery-protocol (`NET_CMD_ID_GETINFO`) probe
/// to one host, unicast, on UDP port 9999, and waits for a reply. Used by
/// ASUS routers and AiMesh nodes. Uses a raw BSD UDP socket, matching
/// `UbiquitiDiscoveryProbe`'s technique.
///
/// Unlike Ubiquiti's discovery protocol, ASUS's `infosvr` (per its
/// `sendInfo()` in `infosvr.c`) replies to `255.255.255.255` — a broadcast,
/// not a unicast reply to the requester's address — even though the request
/// itself was sent unicast. Modern firmware still targets the requester's
/// source *port*, so the same socket's `recv()` below does pick the reply
/// up, but only because receiving broadcast-destined datagrams on iOS
/// requires the `com.apple.developer.networking.multicast` entitlement
/// (declared in `mDNSShark.entitlements`/`mDNSSharkDebug.entitlements`);
/// without it the OS sandbox drops the incoming datagram before it ever
/// reaches this socket, silently, with no error surfaced here — this method
/// will just always return nil against real ASUS hardware in that case, not
/// merely "not find" the ASUS probe. See the discovery-probe report at
/// `.superpowers/sdd/phase2-protocols/asus-report.md` for the remaining
/// manual Developer Portal step this entitlement still needs before a
/// signed build can actually use it.
final class ASUSDiscoveryProbe: Sendable {
    private let logger = Logger(subsystem: "com.mDNSShark", category: "ASUSDiscoveryProbe")
    private let port: UInt16 = 9999

    func probe(ip: String, pacer: UDPSendPacer, timeout: TimeInterval) async -> ASUSDiscoveryReply? {
        let sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard sock >= 0 else { logger.error("ASUSDiscoveryProbe: socket() failed"); return nil }
        defer { close(sock) }

        var timeoutVal = timeval(tv_sec: Int(timeout), tv_usec: Int32((timeout - Double(Int(timeout))) * 1_000_000))
        guard setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeoutVal, socklen_t(MemoryLayout<timeval>.size)) == 0 else {
            logger.error("ASUSDiscoveryProbe: setsockopt(SO_RCVTIMEO) failed")
            return nil
        }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, ip, &addr.sin_addr) == 1 else { return nil }

        await pacer.waitTurn()
        guard !Task.isCancelled else { return nil }

        let payload = ASUSDiscoveryPacket.probe()
        let sent = payload.withUnsafeBytes { buf -> Int in
            withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    sendto(sock, buf.baseAddress, buf.count, 0, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent > 0 else { return nil }

        var buffer = [UInt8](repeating: 0, count: 2048)
        let received = recv(sock, &buffer, buffer.count, 0)
        guard received > 0 else { return nil }
        return ASUSDiscoveryPacket.decode(Data(buffer[0..<received]))
    }
}
