// mDNSSharkTests/PacketCaptureFilterTests.swift
import Testing
import Foundation
@testable import mDNSShark

@Suite("Packet Capture chips filter by protocol and TCP can narrow to decrypted requests")
struct PacketCaptureFilterTests {

    private let tcp = PacketModel(frameNumber: 1, sourceIP: "a", destinationIP: "b", protocolName: "TCP", length: 1, info: "", hexDump: "")
    private let http = PacketModel(frameNumber: 2, sourceIP: "a", destinationIP: "b", protocolName: "HTTP", length: 1, info: "", hexDump: "")
    private let https = PacketModel(frameNumber: 3, sourceIP: "a", destinationIP: "b", protocolName: "HTTPS", length: 1, info: "Client Hello", hexDump: "")
    private let udp = PacketModel(frameNumber: 4, sourceIP: "a", destinationIP: "b", protocolName: "UDP", length: 1, info: "", hexDump: "")
    private let dns = PacketModel(frameNumber: 5, sourceIP: "a", destinationIP: "b", protocolName: "DNS", length: 1, info: "", hexDump: "")
    private let mdns = PacketModel(frameNumber: 6, sourceIP: "a", destinationIP: "b", protocolName: "mDNS", length: 1, info: "", hexDump: "")
    private let icmp = PacketModel(frameNumber: 7, sourceIP: "a", destinationIP: "b", protocolName: "ICMP", length: 1, info: "", hexDump: "")
    private let igmp = PacketModel(frameNumber: 8, sourceIP: "a", destinationIP: "b", protocolName: "IGMP", length: 1, info: "", hexDump: "")
    private let decrypted = PacketModel(frameNumber: 8, sourceIP: "device", destinationIP: "example.com",
                                        destinationPort: 443, protocolName: "HTTPS", length: 120,
                                        info: PacketModel.tlsDecryptedInfo, hexDump: "", payloadText: "GET / HTTP/1.1",
                                        decryptedSequence: 1)
    /// Logged before `decryptedSequence` existed; identified by its info string alone.
    private let legacyDecrypted = PacketModel(frameNumber: 9, sourceIP: "device", destinationIP: "example.org",
                                              destinationPort: 443, protocolName: "HTTPS", length: 80,
                                              info: PacketModel.tlsDecryptedInfo, hexDump: "", payloadText: "GET /x HTTP/1.1")

    private var all: [PacketModel] {
        [tcp, http, https, udp, dns, mdns, icmp, igmp, decrypted, legacyDecrypted]
    }

    private func ids(_ chip: String, decryptedOnly: Bool = false) -> [UUID] {
        all.filtered(byChip: chip, decryptedOnly: decryptedOnly).map(\.id)
    }

    @Test func chipOrderIsUnchanged() {
        #expect(PacketCaptureChip.all == ["All", "TCP", "UDP", "DNS", "mDNS", "Other"])
    }

    @Test func allShowsEverythingIncludingDecrypted() {
        #expect(ids("All") == all.map(\.id))
    }

    @Test func tcpIncludesHTTPAndHTTPSAndDecryptedRequests() {
        #expect(ids("TCP") == [tcp.id, http.id, https.id, decrypted.id, legacyDecrypted.id])
    }

    @Test func tcpDecryptedOnlyReturnsJustDecryptedRequests() {
        #expect(ids("TCP", decryptedOnly: true) == [decrypted.id, legacyDecrypted.id])
    }

    @Test func udpShowsOnlyUDP() {
        #expect(ids("UDP") == [udp.id])
    }

    @Test func dnsShowsOnlyDNS() {
        #expect(ids("DNS") == [dns.id])
    }

    @Test func mdnsShowsOnlyMDNS() {
        #expect(ids("mDNS") == [mdns.id])
    }

    @Test func otherExcludesKnownProtocolsAndDecryptedRequests() {
        #expect(ids("Other") == [igmp.id])
    }

    @Test(arguments: ["UDP", "DNS", "mDNS", "Other"])
    func nonTCPChipsHaveNoDecryptedEntries(chip: String) {
        #expect(ids(chip, decryptedOnly: true).isEmpty)
    }

    @Test func decryptedOnlyIsEmptyWithoutInspection() {
        let wireOnly = [tcp, https, udp, dns]
        #expect(wireOnly.filtered(byChip: "TCP", decryptedOnly: true).isEmpty)
        #expect(wireOnly.filtered(byChip: "TCP").count == 2)
    }
}
