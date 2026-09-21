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
        guard sent > 0 else {
            let sendErrno = errno
            logger.debug("UbiquitiDiscoveryProbe: sendto(\(ip, privacy: .public):\(self.port)) failed, result=\(sent), errno=\(sendErrno) (\(String(cString: strerror(sendErrno)), privacy: .public))")
            return nil
        }
        logger.debug("UbiquitiDiscoveryProbe: sendto(\(ip, privacy: .public):\(self.port)) sent \(sent) bytes, waiting for reply")

        var buffer = [UInt8](repeating: 0, count: 2048)
        let received = recv(sock, &buffer, buffer.count, 0)
        guard received > 0 else {
            // `errno` is only meaningful after a -1 return — a 0 return is
            // a legitimate (if unrealistic for this protocol) empty
            // datagram, not an error, and doesn't set errno itself. Logging
            // it unconditionally would report a stale, misleading code.
            if received < 0 {
                let recvErrno = errno
                logger.debug("UbiquitiDiscoveryProbe: recv(\(ip, privacy: .public)) failed, result=\(received), errno=\(recvErrno) (\(String(cString: strerror(recvErrno)), privacy: .public))")
            } else {
                logger.debug("UbiquitiDiscoveryProbe: recv(\(ip, privacy: .public)) got an empty datagram")
            }
            return nil
        }
        let decoded = UbiquitiDiscoveryPacket.decode(Data(buffer[0..<received]))
        logger.debug("UbiquitiDiscoveryProbe: recv(\(ip, privacy: .public)) got \(received) bytes, decode \(decoded == nil ? "FAILED" : "succeeded", privacy: .public)")
        return decoded
    }
}
