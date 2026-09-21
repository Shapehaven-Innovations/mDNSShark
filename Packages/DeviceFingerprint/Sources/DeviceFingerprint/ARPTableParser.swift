import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// One neighbor entry read from the kernel's IPv4 ARP table via the
/// `PF_ROUTE`/`NET_RT_FLAGS` sysctl (the same table `arp -a` and
/// `netstat -rn` walk). Real link-layer addresses are only non-nil on
/// iOS 27+ with the undocumented `com.apple.developer.networking.topology-observation`
/// entitlement — see todo.md item 4. On iOS 18-26, or without the
/// entitlement, the kernel still returns an entry per neighbor but zeroes
/// the link-layer bytes, so `macAddress` comes back nil and callers fall
/// through to the existing NetBIOS/vendor-discovery MAC sources unchanged.
public struct ARPTableEntry: Equatable {
    public let ipAddress: String
    public let macAddress: String?

    public init(ipAddress: String, macAddress: String?) {
        self.ipAddress = ipAddress
        self.macAddress = macAddress
    }
}

/// Decodes the raw buffer a `NET_RT_FLAGS`/`RTF_LLINFO` routing-socket
/// sysctl returns. Pure and synchronous so it can be exercised with
/// synthetic buffers in tests — the actual `sysctl(2)` call lives in
/// `ARPTableReader`.
///
/// Deliberately does NOT reference the real `rt_msghdr`/`sockaddr_inarp`
/// C types or their `RTF_LLINFO`/`RTAX_*`/`RTA_*` constants, even though
/// `<net/route.h>` (and therefore the actual kernel wire format) is
/// identical across every Darwin platform: the iOS SDK's module map hides
/// those declarations from Swift (confirmed by typechecking against
/// `-sdk iphonesimulator` — `rt_msghdr`/`sockaddr_inarp` and the route
/// constants fail to resolve there, while `sockaddr_dl`/`AF_LINK`/
/// `CTL_NET`/`PF_ROUTE`/`NET_RT_FLAGS` do not), so code that imports the
/// real types builds fine on macOS (where this package's tests run) but
/// fails to compile for the iOS app target. The offsets/sizes below were
/// captured with `MemoryLayout<rt_msghdr>.offset(of:)` against the real
/// macOS-SDK struct rather than guessed, then hand-encoded here so the
/// same byte-level logic compiles on both platforms.
public enum ARPTableParser {
    /// `struct rt_msghdr { u_short rtm_msglen; u_char rtm_version; u_char
    /// rtm_type; u_short rtm_index; int rtm_flags; int rtm_addrs; ... }`
    /// — `rtm_flags`/`rtm_addrs` sit at offsets 8/12 (2 bytes of padding
    /// before the first 4-byte-aligned `int` field), and the whole header
    /// (through the trailing `rt_metrics`) is 92 bytes.
    private static let headerSize = 92
    private static let rtmMsglenOffset = 0
    private static let rtmFlagsOffset = 8
    private static let rtmAddrsOffset = 12
    /// `RTF_LLINFO` (0x400) — not `private`: `ARPTableReader` needs the same
    /// value for the sysctl MIB itself, and it's hidden from the iOS SDK
    /// the same way the other route constants above are.
    static let rtfLLINFO: Int32 = 0x400
    private static let rtaxDST = 0
    private static let rtaxGATEWAY = 1
    private static let rtaDST: Int32 = 1 << 0
    private static let rtaGATEWAY: Int32 = 1 << 1

    /// Rounds a `sockaddr`'s `sa_len` up to the routing socket's 4-byte
    /// address alignment (`ROUNDUP` in BSD's route.c / arp.c) — each
    /// address packed after an `rt_msghdr` consumes this many bytes
    /// regardless of its own reported length.
    static func roundedLength(_ len: Int) -> Int {
        len > 0 ? ((len - 1) | (MemoryLayout<UInt32>.size - 1)) + 1 : MemoryLayout<UInt32>.size
    }

    public static func parse(_ data: Data) -> [ARPTableEntry] {
        let bytes = [UInt8](data)
        var entries: [ARPTableEntry] = []
        var offset = 0

        while offset + headerSize <= bytes.count {
            let msgLen = Int(readUInt16(bytes, at: offset + rtmMsglenOffset))
            guard msgLen > 0, offset + msgLen <= bytes.count else { break }
            defer { offset += msgLen }

            let flags = readInt32(bytes, at: offset + rtmFlagsOffset)
            guard flags & rtfLLINFO != 0 else { continue }
            let addrs = readInt32(bytes, at: offset + rtmAddrsOffset)

            var addrOffset = offset + headerSize
            let msgEnd = offset + msgLen
            var ip: String?
            var mac: String?

            for index in 0..<8 where addrOffset < msgEnd {
                let bit: Int32 = 1 << Int32(index)
                guard addrs & bit != 0 else { continue }
                let saLen = Int(bytes[addrOffset])
                let consumed = roundedLength(saLen == 0 ? MemoryLayout<Int>.size : saLen)
                guard addrOffset + consumed <= msgEnd else { break }

                if index == rtaxDST {
                    ip = readIPv4(bytes, at: addrOffset)
                } else if index == rtaxGATEWAY {
                    mac = readLinkLayerMAC(bytes, at: addrOffset, length: saLen)
                }
                addrOffset += consumed
            }

            if let ip {
                entries.append(ARPTableEntry(ipAddress: ip, macAddress: mac))
            }
        }

        return entries
    }

    private static func readUInt16(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
    }

    private static func readInt32(_ bytes: [UInt8], at offset: Int) -> Int32 {
        Int32(bitPattern: UInt32(bytes[offset])
            | (UInt32(bytes[offset + 1]) << 8)
            | (UInt32(bytes[offset + 2]) << 16)
            | (UInt32(bytes[offset + 3]) << 24))
    }

    /// `sockaddr_inarp` shares `sockaddr_in`'s layout for its first fields
    /// (`sin_len`, `sin_family`, `sin_port`, `sin_addr`) — the IPv4 address
    /// is always the 4 bytes starting at offset 4.
    private static func readIPv4(_ bytes: [UInt8], at offset: Int) -> String? {
        guard offset + 8 <= bytes.count else { return nil }
        let o = offset + 4
        return "\(bytes[o]).\(bytes[o + 1]).\(bytes[o + 2]).\(bytes[o + 3])"
    }

    /// `sockaddr_dl`'s fixed header is 8 bytes (`sdl_len`, `sdl_family`,
    /// `sdl_index`, `sdl_type`, `sdl_nlen`, `sdl_alen`, `sdl_slen`),
    /// followed by `sdl_data`: the interface name (`sdl_nlen` bytes) then
    /// the link-layer address (`sdl_alen` bytes). Only 6-byte (Ethernet)
    /// addresses are decoded; an all-zero address (the pre-iOS27 sandboxed
    /// case) is treated as unresolved. Unlike `rt_msghdr`/`sockaddr_inarp`,
    /// `sockaddr_dl` and `AF_LINK` ARE visible on the iOS SDK, but this
    /// still reads raw bytes rather than the mapped struct to stay
    /// consistent with the rest of this parser.
    private static func readLinkLayerMAC(_ bytes: [UInt8], at offset: Int, length: Int) -> String? {
        guard length >= 8, offset + length <= bytes.count else { return nil }
        let family = bytes[offset + 1]
        guard family == UInt8(AF_LINK) else { return nil }
        // sockaddr_dl: sdl_len(0) sdl_family(1) sdl_index(2-3) sdl_type(4)
        // sdl_nlen(5) sdl_alen(6) sdl_slen(7) sdl_data(8...).
        let nlen = Int(bytes[offset + 5])
        let alen = Int(bytes[offset + 6])
        guard alen == 6 else { return nil }
        let macStart = offset + 8 + nlen
        guard macStart + 6 <= bytes.count, macStart + 6 <= offset + length else { return nil }
        let macBytes = bytes[macStart..<macStart + 6]
        guard macBytes.contains(where: { $0 != 0 }) else { return nil }
        return macBytes.map { String(format: "%02x", $0) }.joined(separator: ":")
    }
}
