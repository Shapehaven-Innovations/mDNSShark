import Foundation
import DeviceFingerprint
import os

/// Sends a NetBIOS NBSTAT query (the same, already-tested query
/// `NetBIOSProbe` uses) to UDP port 137 and reads the TTL off the real reply
/// datagram via IP_RECVTTL.
///
/// Earlier revision note: this probe originally sent a 1-byte datagram to an
/// unlikely-open high port (33434) and tried to read the TTL off the
/// resulting ICMP-port-unreachable error. That does not work on Darwin: for
/// an *unconnected* UDP socket, the kernel's ICMP error handling never
/// notifies the socket at all - no data, no ancillary record, nothing.
/// `IP_RECVTTL` ancillary data only ever attaches to a genuine, successfully
/// received UDP payload datagram, never to an error condition. That version
/// would have returned nil for essentially every host while still burning
/// its full timeout and a `ProbeConcurrencyLimiter` slot each time. Sending
/// a real, already-known-good query (NBSTAT) to a port real devices actually
/// listen on (137) elicits a genuine reply datagram, which does carry TTL
/// ancillary data. Coverage is narrower than "every host" - only
/// NetBIOS-capable hosts (Windows, Samba, many NAS boxes) reply - but that
/// is an honest, disclosed limitation rather than a silently-broken
/// "works for nobody" probe, and this is already documented as the weakest,
/// tiebreaker-only signal in the whole pipeline.
///
/// On Darwin, reading TTL requires ancillary-data (`recvmsg` + `IP_RECVTTL`)
/// rather than a field NWConnection exposes directly.
///
/// This is the WEAKEST signal in the whole enrichment pipeline (see
/// `guessOSFamily`'s doc comment) — it must never crash or hang, but a nil
/// result here is expected and common (most hosts don't run NetBIOS at all).
final class TTLProbe {
    private let logger = Logger(subsystem: "com.mDNSShark", category: "TTLProbe")
    private let port: UInt16 = 137

    func probe(ip: String, pacer: UDPSendPacer, timeout: TimeInterval) async -> String? {
        let sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        guard sock >= 0 else { logger.error("TTLProbe: socket() failed"); return nil }
        defer { close(sock) }

        var on: Int32 = 1
        guard setsockopt(sock, IPPROTO_IP, IP_RECVTTL, &on, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            logger.error("TTLProbe: setsockopt(IP_RECVTTL) failed")
            return nil
        }

        // NOTE (found in Task 6 review, applies here too): Darwin's sosetopt rejects
        // SO_RCVTIMEO with EDOM when tv_usec >= 1_000_000 - split the interval into
        // whole seconds + remainder microseconds, and check the result.
        var timeoutVal = timeval(tv_sec: Int(timeout), tv_usec: Int32((timeout - Double(Int(timeout))) * 1_000_000))
        guard setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeoutVal, socklen_t(MemoryLayout<timeval>.size)) == 0 else {
            logger.error("TTLProbe: setsockopt(SO_RCVTIMEO) failed"); return nil
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

        var msgBuffer = [UInt8](repeating: 0, count: 512)
        var controlBuffer = [UInt8](repeating: 0, count: 64)
        var receivedTTL: UInt8?

        msgBuffer.withUnsafeMutableBytes { msgBuf in
            controlBuffer.withUnsafeMutableBytes { ctlBuf in
                var iov = iovec(iov_base: msgBuf.baseAddress, iov_len: msgBuf.count)
                withUnsafeMutablePointer(to: &iov) { iovPtr in
                    var msgHeader = msghdr()
                    msgHeader.msg_name = nil
                    msgHeader.msg_namelen = 0
                    msgHeader.msg_iov = iovPtr
                    msgHeader.msg_iovlen = 1
                    msgHeader.msg_control = ctlBuf.baseAddress
                    msgHeader.msg_controllen = socklen_t(ctlBuf.count)
                    msgHeader.msg_flags = 0

                    let received = recvmsg(sock, &msgHeader, 0)
                    guard received >= 0 else { return }

                    receivedTTL = Self.extractTTL(from: ctlBuf, controlLen: Int(msgHeader.msg_controllen))
                }
            }
        }

        guard let ttl = receivedTTL else { return nil }
        return guessOSFamily(ttl: ttl)
    }

    /// Walks the `cmsghdr` chain in `control` looking for the IP_RECVTTL
    /// ancillary record and returns the TTL byte inside it.
    ///
    /// Verified empirically against a real Darwin `recvmsg`/`IP_RECVTTL`
    /// round trip (loopback UDP, known outgoing IP_TTL) rather than assumed:
    /// - The record actually delivered by the kernel is tagged
    ///   `cmsg_type == IP_RECVTTL` (24 on Darwin), NOT `IP_TTL` (4). `IP_TTL`
    ///   is only the *setsockopt* option name for setting the outgoing TTL;
    ///   it is not the wire tag Darwin uses for the received ancillary
    ///   record. Comparing against `IP_TTL` here would never match and this
    ///   function would silently always return nil.
    /// - The payload byte does sit immediately after the header with no
    ///   extra padding, i.e. at `offset + MemoryLayout<cmsghdr>.size` (12 on
    ///   64-bit Darwin) — confirmed byte-for-byte against a known TTL value
    ///   placed in the control buffer.
    /// - Successive `cmsghdr` records are NOT laid back-to-back at raw
    ///   `cmsg_len` - the kernel pads each record's length up before the
    ///   next header starts. Advancing by the raw `cmsg_len` (as opposed to
    ///   an aligned length) can walk into that padding and misread it as a
    ///   header. This matters only if more than one ancillary option is ever
    ///   requested on this socket (currently only IP_RECVTTL is), but the
    ///   loop is written defensively in case that changes.
    private static func extractTTL(from control: UnsafeMutableRawBufferPointer, controlLen: Int) -> UInt8? {
        let headerSize = MemoryLayout<cmsghdr>.size
        var offset = 0
        while offset + headerSize <= controlLen {
            let cmsg = control.loadUnaligned(fromByteOffset: offset, as: cmsghdr.self)
            guard cmsg.cmsg_len > 0 else { break }
            // Bounds check: the record must not claim to extend past the end of
            // the control buffer the kernel actually gave us. Unreachable with
            // well-formed kernel output today, but cheap insurance against
            // malformed/truncated control data before we read from inside it.
            guard offset + Int(cmsg.cmsg_len) <= controlLen else { break }
            if cmsg.cmsg_level == IPPROTO_IP, cmsg.cmsg_type == IP_RECVTTL, cmsg.cmsg_len >= socklen_t(headerSize + 1) {
                return control.load(fromByteOffset: offset + headerSize, as: UInt8.self)
            }
            // Round the advance up to a 4-byte boundary, matching Darwin's real
            // cmsg alignment unit (__DARWIN_ALIGN32 - cmsg records are packed on
            // 4-byte boundaries, not 8). Rounding up to the *correct* unit
            // matters: over-rounding (e.g. to 8, as an earlier revision of this
            // function did) risks overshooting into the middle of a following
            // header if more than one ancillary option is ever requested on this
            // socket - it does not just "stop the search slightly sooner". This
            // doesn't change today's behavior (only one ancillary record -
            // IP_RECVTTL - is ever present, so the loop always matches on its
            // first iteration), but the loop is written correctly rather than
            // correctly-by-luck in case that changes.
            let rawAdvance = Int(cmsg.cmsg_len)
            let alignedAdvance = (rawAdvance + 3) & ~3
            offset += alignedAdvance
        }
        return nil
    }
}
