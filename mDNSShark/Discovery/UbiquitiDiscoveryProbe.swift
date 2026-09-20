import Foundation
import DeviceFingerprint
import os

/// Sends a Ubiquiti discovery-protocol probe to one host and waits for a
/// reply. Tries v1 first, falls back to v2 if v1 times out — matches nmap's
/// `ubiquiti-discovery.nse` behavior. Uses a raw BSD UDP socket, the same
/// technique `NetworkScanner.scanSSDP()` already uses in this codebase.
final class UbiquitiDiscoveryProbe: Sendable {
    private let logger = Logger(subsystem: "com.mDNSShark", category: "UbiquitiDiscoveryProbe")
    private let port: UInt16 = 10001

    func probe(ip: String, pacer: UDPSendPacer, timeout: TimeInterval) async -> UbiquitiDiscoveryReply? {
        if let reply = await send(UbiquitiDiscoveryPacket.probeV1(), to: ip, pacer: pacer, timeout: timeout) {
            return reply
        }
        return await send(UbiquitiDiscoveryPacket.probeV2(), to: ip, pacer: pacer, timeout: timeout)
    }

    private func send(_ payload: Data, to ip: String, pacer: UDPSendPacer, timeout: TimeInterval) async -> UbiquitiDiscoveryReply? {
        let sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard sock >= 0 else { logger.error("UbiquitiDiscoveryProbe: socket() failed"); return nil }
        defer { close(sock) }

        var timeoutVal = timeval(tv_sec: Int(timeout), tv_usec: Int32((timeout - Double(Int(timeout))) * 1_000_000))
        guard setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeoutVal, socklen_t(MemoryLayout<timeval>.size)) == 0 else {
            logger.error("UbiquitiDiscoveryProbe: setsockopt(SO_RCVTIMEO) failed")
            return nil
        }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, ip, &addr.sin_addr) == 1 else { return nil }

        await pacer.waitTurn()
        guard !Task.isCancelled else { return nil }

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
        return UbiquitiDiscoveryPacket.decode(Data(buffer[0..<received]))
    }
}
