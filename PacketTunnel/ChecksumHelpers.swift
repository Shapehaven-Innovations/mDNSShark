// PacketTunnel/ChecksumHelpers.swift
// Shared by PacketForwarder.swift (plain TCP/UDP relay) and TLSInterceptor.swift
// (TLS-intercepted relay) — both build raw IPv4/TCP/UDP packets by hand and both
// need the same wire-format checksum math. Extracted here instead of duplicated
// after the plain relay was found to have the same zero-checksum defect the
// TLS-intercepted path was fixed for (see todo.md item 1).
enum PacketChecksum {
    static func ipv4Bytes(_ ip: String) -> [UInt8] {
        ip.split(separator: ".").compactMap { UInt8($0) }
    }

    /// Standard Internet checksum (RFC 1071): 16-bit one's-complement sum,
    /// folded and complemented. Used for both the IPv4 header checksum and
    /// the TCP/UDP checksum (over a pseudo-header + segment).
    static func internetChecksum<C: Collection>(_ bytes: C) -> UInt16 where C.Element == UInt8 {
        var sum: UInt32 = 0
        var iter = bytes.makeIterator()
        while let hi = iter.next() {
            let lo = iter.next() ?? 0
            sum += UInt32(hi) << 8 | UInt32(lo)
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16)
        }
        return ~UInt16(sum & 0xFFFF)
    }
}
