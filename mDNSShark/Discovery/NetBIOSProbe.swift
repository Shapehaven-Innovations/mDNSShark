import Foundation
import DeviceFingerprint
import os

/// Sends a NetBIOS NBSTAT query to one host over UDP 137 and decodes the
/// MAC address out of the adapter-status reply, if any. Same raw-socket
/// technique as `UbiquitiDiscoveryProbe`.
final class NetBIOSProbe {
    private let logger = Logger(subsystem: "com.mDNSShark", category: "NetBIOSProbe")
    private let port: UInt16 = 137

    func probe(ip: String, pacer: UDPSendPacer, timeout: TimeInterval) async -> NetBIOSReply? {
        let sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard sock >= 0 else { logger.error("NetBIOSProbe: socket() failed"); return nil }
        defer { close(sock) }

        // NOTE (found in Task 6 review, applies here too): Darwin's sosetopt rejects
        // SO_RCVTIMEO with EDOM when tv_usec >= 1_000_000 - split the interval into
        // whole seconds + remainder microseconds, and check the result. A silently
        // failed setsockopt here means recv() below never times out and blocks forever
        // on every non-replying host - i.e. almost every host in a real scan.
        var timeoutVal = timeval(tv_sec: Int(timeout), tv_usec: Int32((timeout - Double(Int(timeout))) * 1_000_000))
        guard setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeoutVal, socklen_t(MemoryLayout<timeval>.size)) == 0 else {
            logger.error("NetBIOSProbe: setsockopt(SO_RCVTIMEO) failed"); return nil
        }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, ip, &addr.sin_addr) == 1 else { return nil }

        await pacer.waitTurn()
        guard !Task.isCancelled else { return nil }

        let payload = NetBIOSPacket.nbstatQuery()
        let sent = payload.withUnsafeBytes { buf -> Int in
            withUnsafePointer(to: &addr) { ptr in
                ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    sendto(sock, buf.baseAddress, buf.count, 0, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent > 0 else { return nil }

        var buffer = [UInt8](repeating: 0, count: 1024)
        let received = recv(sock, &buffer, buffer.count, 0)
        guard received > 0 else { return nil }
        return NetBIOSPacket.decode(Data(buffer[0..<received]))
    }
}
