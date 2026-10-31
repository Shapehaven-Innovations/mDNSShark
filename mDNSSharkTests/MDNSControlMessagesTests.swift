// mDNSSharkTests/MDNSControlMessagesTests.swift
import Testing
import Foundation
@testable import mDNSShark

@Suite("MDNSControlMessages reads TTL, destination, interface and kernel timestamp from recvmsg control data")
struct MDNSControlMessagesTests {

    /// One cmsghdr plus data, padded to the 4-byte alignment the kernel uses.
    private func cmsg(level: Int32, type: Int32, data: [UInt8]) -> [UInt8] {
        var header = cmsghdr(cmsg_len: socklen_t(MemoryLayout<cmsghdr>.size + data.count), cmsg_level: level, cmsg_type: type)
        var bytes = withUnsafeBytes(of: &header) { Array($0) } + data
        while bytes.count % 4 != 0 { bytes.append(0) }
        return bytes
    }

    private func parse(_ bytes: [UInt8]) -> MDNSControlMessages {
        bytes.withUnsafeBytes { MDNSControlMessages.parse($0, length: bytes.count) }
    }

    @Test func emptyBufferYieldsNothing() {
        let parsed = parse([])
        #expect(parsed == MDNSControlMessages())
    }

    @Test func readsTTLDestinationAndInterface() {
        var sdl = sockaddr_dl()
        sdl.sdl_len = UInt8(MemoryLayout<sockaddr_dl>.size)
        sdl.sdl_family = UInt8(AF_LINK)
        sdl.sdl_index = 13
        let sdlBytes = withUnsafeBytes(of: &sdl) { Array($0) }

        let buffer = cmsg(level: IPPROTO_IP, type: IP_RECVTTL, data: [255])
            + cmsg(level: IPPROTO_IP, type: IP_RECVDSTADDR, data: [224, 0, 0, 251])
            + cmsg(level: IPPROTO_IP, type: IP_RECVIF, data: sdlBytes)
        let parsed = parse(buffer)
        #expect(parsed.ttl == 255)
        #expect(parsed.destination == [224, 0, 0, 251])
        #expect(parsed.interfaceIndex == 13)
        #expect(parsed.kernelTimestamp == nil)
    }

    @Test func readsKernelTimestamp() {
        var tv = timeval(tv_sec: 1_700_000_000, tv_usec: 250_000)
        let buffer = cmsg(level: SOL_SOCKET, type: SCM_TIMESTAMP, data: withUnsafeBytes(of: &tv) { Array($0) })
        let parsed = parse(buffer)
        #expect(parsed.kernelTimestamp == Date(timeIntervalSince1970: 1_700_000_000.25))
    }

    @Test func ignoresUnknownAndStopsAtLengthLimit() {
        let unknown = cmsg(level: IPPROTO_IP, type: 999, data: [1, 2, 3])
        let ttl = cmsg(level: IPPROTO_IP, type: IP_RECVTTL, data: [64])
        let buffer = unknown + ttl
        #expect(parse(buffer).ttl == 64)
        // A length that cuts off the second header hides it instead of reading past the limit.
        let truncated = buffer.withUnsafeBytes { MDNSControlMessages.parse($0, length: unknown.count + 4) }
        #expect(truncated.ttl == nil)
    }

    @Test func readsIPv6HopLimitAndPacketInfo() {
        var hop: Int32 = 255
        var info = in6_pktinfo()
        info.ipi6_ifindex = 13
        let group: [UInt8] = [0xff, 0x02] + [UInt8](repeating: 0, count: 13) + [0xfb]
        withUnsafeMutableBytes(of: &info.ipi6_addr) { $0.copyBytes(from: group) }
        let buffer = cmsg(level: IPPROTO_IPV6, type: IPv6SocketOption.hopLimit, data: withUnsafeBytes(of: &hop) { Array($0) })
            + cmsg(level: IPPROTO_IPV6, type: IPv6SocketOption.packetInfo, data: withUnsafeBytes(of: &info) { Array($0) })
        let parsed = parse(buffer)
        #expect(parsed.hopLimit == 255)
        #expect(parsed.destination6 == group)
        #expect(parsed.interfaceIndex == 13)
        #expect(parsed.ttl == nil)
        #expect(parsed.destination == nil)
    }

    @Test func zeroLengthHeaderDoesNotLoopForever() {
        var header = cmsghdr(cmsg_len: 0, cmsg_level: IPPROTO_IP, cmsg_type: IP_RECVTTL)
        let bytes = withUnsafeBytes(of: &header) { Array($0) } + [255, 0, 0, 0]
        #expect(parse(bytes).ttl == nil)
    }
}
