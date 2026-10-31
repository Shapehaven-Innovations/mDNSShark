// mDNSSharkTests/PacketParserTests.swift
import Testing
import Foundation
@testable import mDNSShark

@Suite("PacketParser summarizes raw IPv4 and IPv6 packets, including synthesized mDNS frames")
struct PacketParserTests {

    /// A minimal DNS header: ID 0, QR set, one answer, no question labels.
    private let dnsResponse: [UInt8] = [0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0]

    private func mdnsDatagram(source: [UInt8], destination: [UInt8]) -> MDNSDatagram {
        MDNSDatagram(payload: Data(dnsResponse), source: source, destination: destination,
                     sourcePort: 5353, destinationPort: 5353, ttl: 255, timestamp: Date(timeIntervalSince1970: 1_700_000_000))
    }

    @Test func ipv4FrameFromBuilderParsesAsMDNS() {
        let frame = MDNSFrameBuilder.ipv4Frame(mdnsDatagram(source: [192, 168, 8, 178], destination: [224, 0, 0, 251]))
        let packet = PacketParser.parse(frame, frameNumber: 7, timestamp: Date(timeIntervalSince1970: 1_700_000_000),
                                        direction: .inbound, isReconstructed: true, captureSource: .mdnsListener)
        #expect(packet.protocolName == "mDNS")
        #expect(packet.sourceIP == "192.168.8.178")
        #expect(packet.destinationIP == "224.0.0.251")
        #expect(packet.sourcePort == 5353)
        #expect(packet.destinationPort == 5353)
        #expect(packet.info == "Multicast DNS [reconstructed]")
        #expect(packet.isReconstructed)
        #expect(packet.captureSource == .mdnsListener)
        #expect(packet.frameNumber == 7)
        #expect(packet.length == frame.count)
        #expect(packet.timestamp == Date(timeIntervalSince1970: 1_700_000_000))
        #expect(packet.direction == .inbound)
    }

    @Test func ipv6FrameFromBuilderParsesAsMDNS() {
        let source: [UInt8] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x1c, 0x2d, 0x3e, 0x4f, 0x5a, 0x6b, 0x7c, 0x8d]
        let group: [UInt8] = [0xff, 0x02] + [UInt8](repeating: 0, count: 13) + [0xfb]
        let frame = MDNSFrameBuilder.ipv6Frame(mdnsDatagram(source: source, destination: group))
        let packet = PacketParser.parse(frame, frameNumber: 8, direction: .outbound, isReconstructed: true, captureSource: .mdnsListener)
        #expect(packet.protocolName == "mDNS")
        #expect(packet.sourceIP == "fe80::1c2d:3e4f:5a6b:7c8d")
        #expect(packet.destinationIP == "ff02::fb")
        #expect(packet.sourcePort == 5353)
        #expect(packet.destinationPort == 5353)
        #expect(packet.info == "Multicast DNS [reconstructed]")
    }

    @Test func nonIPBufferIsOther() {
        let packet = PacketParser.parse(Data(repeating: 0x00, count: 20), frameNumber: 1, direction: .outbound, isReconstructed: false)
        #expect(packet.protocolName == "Other")
        #expect(packet.info == "Non-IP")
        #expect(packet.captureSource == .tunnel)
    }

    @Test func tcpSynToPort443IsHTTPS() {
        var bytes: [UInt8] = [0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 2, 93, 184, 216, 34]
        bytes += [0xC0, 0x00, 0x01, 0xBB, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xFF, 0xFF, 0, 0, 0, 0]
        let packet = PacketParser.parse(Data(bytes), frameNumber: 2, direction: .outbound, isReconstructed: false)
        #expect(packet.protocolName == "HTTPS")
        #expect(packet.info == "[SYN]")
        #expect(packet.sourceIP == "10.0.0.2")
        #expect(packet.destinationIP == "93.184.216.34")
        #expect(packet.destinationPort == 443)
    }

    @Test func dnsQueryNameIsExtracted() {
        var bytes: [UInt8] = [0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 0, 0, 2, 8, 8, 8, 8]
        bytes += [0xC3, 0x50, 0, 53, 0, 0, 0, 0]
        bytes += [0, 1, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0]
        bytes += [7] + Array("example".utf8) + [3] + Array("com".utf8) + [0, 0, 1, 0, 1]
        let packet = PacketParser.parse(Data(bytes), frameNumber: 3, direction: .outbound, isReconstructed: false)
        #expect(packet.protocolName == "DNS")
        #expect(packet.info == "Query: example.com")
    }

    @Test func reconstructedSuffixIsNotDoubled() {
        let frame = MDNSFrameBuilder.ipv4Frame(mdnsDatagram(source: [192, 168, 8, 123], destination: [224, 0, 0, 251]))
        let packet = PacketParser.parse(frame, frameNumber: 9, direction: .outbound, isReconstructed: true)
        #expect(packet.info.components(separatedBy: "[reconstructed]").count == 2)
    }
}
