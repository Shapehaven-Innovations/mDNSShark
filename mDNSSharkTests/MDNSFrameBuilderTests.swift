// mDNSSharkTests/MDNSFrameBuilderTests.swift
import Testing
import Foundation
@testable import mDNSShark

@Suite("MDNSFrameBuilder rebuilds valid IP and UDP headers around an mDNS payload")
struct MDNSFrameBuilderTests {

    private let v4Source: [UInt8] = [192, 168, 8, 178]
    private let v4Group: [UInt8] = [224, 0, 0, 251]
    private let v6Source: [UInt8] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d]
    private let v6Group: [UInt8] = [0xff, 0x02] + [UInt8](repeating: 0, count: 13) + [0xfb]

    private func datagram(payload: [UInt8], source: [UInt8], destination: [UInt8], ttl: UInt8? = 255, trafficClass: UInt8? = nil) -> MDNSDatagram {
        MDNSDatagram(payload: Data(payload), source: source, destination: destination,
                     sourcePort: 5353, destinationPort: 5353, ttl: ttl, trafficClass: trafficClass, timestamp: Date(timeIntervalSince1970: 1_700_000_000))
    }

    private func be16(_ d: Data, _ offset: Int) -> Int { Int(d[offset]) << 8 | Int(d[offset + 1]) }

    private func udpPseudoHeaderV4(_ frame: Data) -> [UInt8] {
        let udpLen = frame.count - 20
        return Array(frame[12..<20]) + [0, 17] + [UInt8(udpLen >> 8), UInt8(udpLen & 0xFF)]
    }

    private func udpPseudoHeaderV6(_ frame: Data) -> [UInt8] {
        let udpLen = UInt32(frame.count - 40)
        return Array(frame[8..<40]) + [UInt8(udpLen >> 24), UInt8(udpLen >> 16 & 0xFF), UInt8(udpLen >> 8 & 0xFF), UInt8(udpLen & 0xFF)] + [0, 0, 0, 17]
    }

    @Test func ipv4FrameHasCorrectLengthsAndFields() throws {
        let payload = [UInt8](repeating: 0xAB, count: 12)
        let frame = try #require(MDNSFrameBuilder.ipv4Frame(datagram(payload: payload, source: v4Source, destination: v4Group, ttl: 17)))
        #expect(frame.count == 20 + 8 + 12)
        #expect(frame[0] == 0x45)
        #expect(be16(frame, 2) == 40)
        #expect(be16(frame, 6) == 0x4000)
        #expect(frame[8] == 17)
        #expect(frame[9] == 17)
        #expect(Array(frame[12..<16]) == v4Source)
        #expect(Array(frame[16..<20]) == v4Group)
        #expect(be16(frame, 20) == 5353)
        #expect(be16(frame, 22) == 5353)
        #expect(be16(frame, 24) == 20)
        #expect(Array(frame[28...]) == payload)
    }

    @Test func ipv4HeaderChecksumValidates() throws {
        let frame = try #require(MDNSFrameBuilder.ipv4Frame(datagram(payload: [1, 2, 3], source: v4Source, destination: v4Group)))
        #expect(be16(frame, 10) != 0)
        #expect(PacketChecksum.internetChecksum(frame[0..<20]) == 0)
    }

    @Test func udpChecksumValidatesOverPseudoHeaderV4() throws {
        let frame = try #require(MDNSFrameBuilder.ipv4Frame(datagram(payload: [UInt8](repeating: 0x5C, count: 13), source: v4Source, destination: v4Group)))
        #expect(be16(frame, 26) != 0)
        #expect(PacketChecksum.internetChecksum(udpPseudoHeaderV4(frame) + Array(frame[20...])) == 0)
    }

    @Test func udpChecksumValidatesOverPseudoHeaderV6() throws {
        let frame = try #require(MDNSFrameBuilder.ipv6Frame(datagram(payload: [UInt8](repeating: 0x5C, count: 13), source: v6Source, destination: v6Group)))
        #expect(be16(frame, 46) != 0)
        #expect(PacketChecksum.internetChecksum(udpPseudoHeaderV6(frame) + Array(frame[40...])) == 0)
    }

    @Test func zeroChecksumBecomesFFFF() throws {
        // With a two-byte payload the checksum of an all-zero payload, used as the payload, drives the computed checksum to 0x0000.
        let probe = try #require(MDNSFrameBuilder.ipv4Frame(datagram(payload: [0, 0], source: v4Source, destination: v4Group)))
        let c = be16(probe, 26)
        let frame = try #require(MDNSFrameBuilder.ipv4Frame(datagram(payload: [UInt8(c >> 8), UInt8(c & 0xFF)], source: v4Source, destination: v4Group)))
        #expect(be16(frame, 26) == 0xFFFF)
        #expect(PacketChecksum.internetChecksum(udpPseudoHeaderV4(frame) + Array(frame[20...])) == 0)
    }

    @Test func ipv6FrameHasCorrectPayloadLengthAndNextHeader() throws {
        let payload = [UInt8](repeating: 0xCD, count: 30)
        let frame = try #require(MDNSFrameBuilder.ipv6Frame(datagram(payload: payload, source: v6Source, destination: v6Group, ttl: 64)))
        #expect(frame.count == 40 + 8 + 30)
        #expect(frame[0] >> 4 == 6)
        #expect(be16(frame, 4) == 38)
        #expect(frame[6] == 17)
        #expect(frame[7] == 64)
        #expect(Array(frame[8..<24]) == v6Source)
        #expect(Array(frame[24..<40]) == v6Group)
        #expect(be16(frame, 40) == 5353)
        #expect(be16(frame, 42) == 5353)
        #expect(be16(frame, 44) == 38)
        #expect(Array(frame[48...]) == payload)
    }

    @Test func fallbackTTLIs255WhenNotReceived() throws {
        let v4 = try #require(MDNSFrameBuilder.ipv4Frame(datagram(payload: [0], source: v4Source, destination: v4Group, ttl: nil)))
        let v6 = try #require(MDNSFrameBuilder.ipv6Frame(datagram(payload: [0], source: v6Source, destination: v6Group, ttl: nil)))
        #expect(v4[8] == 255)
        #expect(v6[7] == 255)
    }

    @Test func frameDispatchesOnAddressLength() {
        let v4 = MDNSFrameBuilder.frame(datagram(payload: [0], source: v4Source, destination: v4Group))
        let v6 = MDNSFrameBuilder.frame(datagram(payload: [0], source: v6Source, destination: v6Group))
        #expect(v4?[0] == 0x45)
        #expect(v6.map { $0[0] >> 4 } == 6)
    }

    @Test func frameRejectsMismatchedAddressLengths() {
        #expect(MDNSFrameBuilder.frame(datagram(payload: [0], source: v4Source, destination: v6Group)) == nil)
        #expect(MDNSFrameBuilder.frame(datagram(payload: [0], source: [1, 2, 3], destination: [1, 2, 3])) == nil)
    }

    @Test func frameReturnsNilForOversizePayload() {
        let v4 = [UInt8](repeating: 0, count: MDNSFrameBuilder.maxIPv4Payload + 1)
        let v6 = [UInt8](repeating: 0, count: MDNSFrameBuilder.maxIPv6Payload + 1)
        #expect(MDNSFrameBuilder.maxIPv4Payload == 65507)
        #expect(MDNSFrameBuilder.maxIPv6Payload == 65527)
        #expect(MDNSFrameBuilder.frame(datagram(payload: v4, source: v4Source, destination: v4Group)) == nil)
        #expect(MDNSFrameBuilder.frame(datagram(payload: v6, source: v6Source, destination: v6Group)) == nil)
    }

    @Test func maxSizeIPv4FrameHasValidLengthsAndChecksums() throws {
        let payload = [UInt8](repeating: 0x7E, count: MDNSFrameBuilder.maxIPv4Payload)
        let frame = try #require(MDNSFrameBuilder.frame(datagram(payload: payload, source: v4Source, destination: v4Group)))
        #expect(frame.count == 65535)
        #expect(be16(frame, 2) == 65535)
        #expect(be16(frame, 24) == 65515)
        #expect(PacketChecksum.internetChecksum(frame[0..<20]) == 0)
        #expect(PacketChecksum.internetChecksum(udpPseudoHeaderV4(frame) + Array(frame[20...])) == 0)
        #expect(Array(frame[28...]) == payload)
    }

    @Test func maxSizeIPv6FrameHasValidLengthsAndChecksum() throws {
        let payload = [UInt8](repeating: 0x7E, count: MDNSFrameBuilder.maxIPv6Payload)
        let frame = try #require(MDNSFrameBuilder.frame(datagram(payload: payload, source: v6Source, destination: v6Group)))
        #expect(frame.count == 40 + 65535)
        #expect(be16(frame, 4) == 65535)
        #expect(be16(frame, 44) == 65535)
        #expect(PacketChecksum.internetChecksum(udpPseudoHeaderV6(frame) + Array(frame[40...])) == 0)
        #expect(Array(frame[48...]) == payload)
    }

    @Test func ipv4TOSByteCarriesTheReceivedValueAndDefaultsToZero() throws {
        let marked = try #require(MDNSFrameBuilder.ipv4Frame(datagram(payload: [1], source: v4Source, destination: v4Group, trafficClass: 0xC0)))
        let plain = try #require(MDNSFrameBuilder.ipv4Frame(datagram(payload: [1], source: v4Source, destination: v4Group)))
        #expect(marked[1] == 0xC0)
        #expect(plain[1] == 0)
        #expect(PacketChecksum.internetChecksum(marked[0..<20]) == 0)
    }

    @Test func ipv6TrafficClassSplitsAcrossFirstTwoBytesWithZeroFlowLabel() throws {
        let frame = try #require(MDNSFrameBuilder.ipv6Frame(datagram(payload: [1], source: v6Source, destination: v6Group, trafficClass: 0xB8)))
        #expect(frame[0] == 0x6B)
        #expect(frame[1] == 0x80)
        #expect(frame[2] == 0 && frame[3] == 0)
        let plain = try #require(MDNSFrameBuilder.ipv6Frame(datagram(payload: [1], source: v6Source, destination: v6Group)))
        #expect(Array(plain[0..<4]) == [0x60, 0, 0, 0])
        #expect(PacketChecksum.internetChecksum(udpPseudoHeaderV6(frame) + Array(frame[40...])) == 0)
    }

    @Test func dispatcherWritesTheTrafficClassWhereAnalyzersReadIt() throws {
        let v4 = try #require(MDNSFrameBuilder.frame(datagram(payload: [1], source: v4Source, destination: v4Group, trafficClass: 0x28)))
        let v6 = try #require(MDNSFrameBuilder.frame(datagram(payload: [1], source: v6Source, destination: v6Group, trafficClass: 0x28)))
        #expect(v4[1] == 0x28)
        #expect(UInt8(v6[0] & 0x0F) << 4 | v6[1] >> 4 == 0x28)
    }

    @Test func familyBuildersRejectTheWrongAddressLengths() {
        #expect(MDNSFrameBuilder.ipv4Frame(datagram(payload: [0], source: v6Source, destination: v6Group)) == nil)
        #expect(MDNSFrameBuilder.ipv4Frame(datagram(payload: [0], source: v4Source, destination: v6Group)) == nil)
        #expect(MDNSFrameBuilder.ipv6Frame(datagram(payload: [0], source: v4Source, destination: v4Group)) == nil)
        #expect(MDNSFrameBuilder.ipv6Frame(datagram(payload: [0], source: v6Source, destination: v4Group)) == nil)
    }

    @Test func familyBuildersNeverClampAnOverflowingLength() {
        let v4 = [UInt8](repeating: 0, count: MDNSFrameBuilder.maxIPv4Payload + 1)
        let v6 = [UInt8](repeating: 0, count: MDNSFrameBuilder.maxIPv6Payload + 1)
        #expect(MDNSFrameBuilder.ipv4Frame(datagram(payload: v4, source: v4Source, destination: v4Group)) == nil)
        #expect(MDNSFrameBuilder.ipv6Frame(datagram(payload: v6, source: v6Source, destination: v6Group)) == nil)
    }
}
