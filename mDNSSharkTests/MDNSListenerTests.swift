// mDNSSharkTests/MDNSListenerTests.swift
import Testing
import Foundation
@testable import mDNSShark

@Suite("BSDMDNSListener turns recvmsg results into datagrams and reports both families in meta")
struct MDNSListenerTests {

    private let group6: [UInt8] = [0xff, 0x02] + [UInt8](repeating: 0, count: 13) + [0xfb]
    private let received = Date(timeIntervalSince1970: 1_700_000_000)

    private func sockaddr4(_ a: [UInt8], port: UInt16) -> [UInt8] {
        var sa = sockaddr_in()
        sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_port = port.bigEndian
        sa.sin_addr = in_addr(s_addr: UInt32(a[0]) | UInt32(a[1]) << 8 | UInt32(a[2]) << 16 | UInt32(a[3]) << 24)
        return withUnsafeBytes(of: &sa) { Array($0) }
    }

    private func sockaddr6(_ a: [UInt8], port: UInt16) -> [UInt8] {
        var sa = sockaddr_in6()
        sa.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
        sa.sin6_family = sa_family_t(AF_INET6)
        sa.sin6_port = port.bigEndian
        withUnsafeMutableBytes(of: &sa.sin6_addr) { $0.copyBytes(from: a) }
        return withUnsafeBytes(of: &sa) { Array($0) }
    }

    @Test func ipv4DatagramUsesSocketMetadata() {
        var cmsgs = MDNSControlMessages()
        cmsgs.ttl = 255
        cmsgs.destination = [224, 0, 0, 251]
        cmsgs.kernelTimestamp = received.addingTimeInterval(-0.05)
        let d = BSDMDNSListener.makeDatagram(sourceAddress: sockaddr4([192, 168, 8, 178], port: 5353),
                                             payload: Data([1, 2, 3]), cmsgs: cmsgs, received: received)
        #expect(d?.source == [192, 168, 8, 178])
        #expect(d?.destination == [224, 0, 0, 251])
        #expect(d?.sourcePort == 5353)
        #expect(d?.destinationPort == 5353)
        #expect(d?.ttl == 255)
        #expect(d?.timestamp == received.addingTimeInterval(-0.05))
        #expect(d?.payload == Data([1, 2, 3]))
    }

    @Test func ipv4DatagramFallsBackToGroupAndWallClock() {
        let d = BSDMDNSListener.makeDatagram(sourceAddress: sockaddr4([10, 0, 0, 9], port: 49152),
                                             payload: Data([0]), cmsgs: MDNSControlMessages(), received: received)
        #expect(d?.destination == [224, 0, 0, 251])
        #expect(d?.sourcePort == 49152)
        #expect(d?.ttl == nil)
        #expect(d?.timestamp == received)
    }

    @Test func ipv6DatagramUsesHopLimitAndPacketInfo() {
        let source: [UInt8] = [0xfe, 0x80] + [UInt8](repeating: 0, count: 6) + [0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d]
        var cmsgs = MDNSControlMessages()
        cmsgs.hopLimit = 255
        cmsgs.destination6 = group6
        let d = BSDMDNSListener.makeDatagram(sourceAddress: sockaddr6(source, port: 5353),
                                             payload: Data([9]), cmsgs: cmsgs, received: received)
        #expect(d?.source == source)
        #expect(d?.destination == group6)
        #expect(d?.ttl == 255)
        #expect(MDNSFrameBuilder.frame(d!)?.first.map { $0 >> 4 } == 6)
    }

    @Test func ipv6DatagramFallsBackToGroup() {
        let d = BSDMDNSListener.makeDatagram(sourceAddress: sockaddr6([UInt8](repeating: 1, count: 16), port: 5353),
                                             payload: Data([9]), cmsgs: MDNSControlMessages(), received: received)
        #expect(d?.destination == group6)
        #expect(d?.ttl == nil)
    }

    @Test func unknownFamilyIsRejected() {
        var bytes = sockaddr4([1, 2, 3, 4], port: 1)
        bytes[1] = UInt8(AF_UNIX)
        #expect(BSDMDNSListener.makeDatagram(sourceAddress: bytes, payload: Data(), cmsgs: MDNSControlMessages(), received: received) == nil)
        #expect(BSDMDNSListener.makeDatagram(sourceAddress: [0, 2], payload: Data(), cmsgs: MDNSControlMessages(), received: received) == nil)
    }

    @Test func metaListsOnlyTheFamiliesThatAreListening() {
        var stats = MDNSListenerStats()
        stats.frames = 20; stats.ipv4Frames = 17; stats.ipv6Frames = 3; stats.ownFrames = 15; stats.kernelStamped = 20
        let both = MDNSListenerMeta.dictionary(status: .listening(interface: "en0", index: 13),
                                               ipv6Status: .listening(interface: "en0", index: 13),
                                               interfaceName: "en0", interfaceIndex: 13, stats: stats)
        #expect(both["listenAddresses"] as? [String] == ["224.0.0.251:5353", "[ff02::fb]:5353"])
        #expect(both["ipv6Status"] as? String == "listening on en0 (ifindex 13)")
        #expect(both["frames"] as? Int == 20)
        #expect(both["ipv6Frames"] as? Int == 3)
        #expect(both["timestampSource"] as? String == "kernel")
        #expect(both["ttlSource"] as? String == "received")

        let v4Only = MDNSListenerMeta.dictionary(status: .listening(interface: "en0", index: 13),
                                                 ipv6Status: .failed(stage: "IPV6_JOIN_GROUP", errno: 49),
                                                 interfaceName: "en0", interfaceIndex: 13, stats: MDNSListenerStats())
        #expect(v4Only["listenAddresses"] as? [String] == ["224.0.0.251:5353"])
        #expect((v4Only["ipv6Status"] as? String)?.hasPrefix("failed: IPV6_JOIN_GROUP errno 49") == true)
        #expect(v4Only["status"] as? String == "listening on en0 (ifindex 13)")
    }

    @Test func metaReportsFallbacksWithCounts() {
        var stats = MDNSListenerStats()
        stats.frames = 10; stats.kernelStamped = 8; stats.ttlMissing = 2
        let meta = MDNSListenerMeta.dictionary(status: .listening(interface: "en0", index: 13), ipv6Status: .idle,
                                               interfaceName: "en0", interfaceIndex: 13, stats: stats)
        #expect(meta["timestampSource"] as? String == "wallclock for 2")
        #expect(meta["ttlSource"] as? String == "fixed-255 for 2")
    }
}
