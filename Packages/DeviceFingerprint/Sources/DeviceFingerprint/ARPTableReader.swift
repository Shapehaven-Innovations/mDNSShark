import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Reads the kernel's IPv4 ARP table via `sysctl(CTL_NET, PF_ROUTE, 0,
/// AF_INET, NET_RT_FLAGS, RTF_LLINFO)` — the same call `arp -a` and
/// `netstat -rn` use. Real (non-zero) link-layer addresses only come back
/// on iOS 27+ with the undocumented `com.apple.developer.networking.topology-observation`
/// entitlement (see todo.md item 4); on iOS 18-26, or without the
/// entitlement, the kernel still returns an entry per neighbor but the
/// sandbox zeroes the link-layer bytes, which `ARPTableParser` surfaces as
/// a nil `macAddress` — never throws, so callers can treat this exactly
/// like every other DeviceFingerprint probe's "no answer" case.
public enum ARPTableReader {
    public static func readEntries() -> [ARPTableEntry] {
        // RTF_LLINFO isn't visible on the iOS SDK (see ARPTableParser's
        // header comment) — reuse its hand-encoded value instead of the
        // Darwin-imported constant so this compiles for the app target.
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, ARPTableParser.rtfLLINFO]
        var size = 0
        guard sysctl(&mib, u_int(mib.count), nil, &size, nil, 0) == 0, size > 0 else { return [] }

        var buffer = [UInt8](repeating: 0, count: size)
        let result = buffer.withUnsafeMutableBytes { raw -> Int32 in
            sysctl(&mib, u_int(mib.count), raw.baseAddress, &size, nil, 0)
        }
        guard result == 0 else { return [] }

        return ARPTableParser.parse(Data(buffer[0..<size]))
    }

    public static func macAddress(forIP ip: String) -> String? {
        readEntries().first(where: { $0.ipAddress == ip })?.macAddress
    }
}
