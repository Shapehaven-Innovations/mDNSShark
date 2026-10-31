// mDNSSharkTests/CaptureSequenceTests.swift
import Testing
import Foundation
@testable import mDNSShark

@Suite("Frame numbers match the pcap and decrypted requests are numbered separately")
struct CaptureSequenceTests {

    @Test func framesNumberConsecutivelyFromOne() {
        var seq = CaptureSequence()
        #expect(seq.nextFrameNumber == 1)
        #expect(seq.recordFrame() == 1)
        #expect(seq.recordFrame() == 2)
        #expect(seq.nextFrameNumber == 3)
        #expect(seq.framesWritten == 2)
        #expect(seq.decryptedRequests == 0)
    }

    @Test func decryptedRequestsDoNotConsumeFrameNumbers() {
        var seq = CaptureSequence()
        for _ in 0..<640 { seq.recordFrame() }
        let first = seq.recordDecryptedRequest()
        #expect(first.sequence == 1)
        #expect(first.afterFrame == 640)
        #expect(seq.nextFrameNumber == 641)
        #expect(seq.recordFrame() == 641)
        let second = seq.recordDecryptedRequest()
        #expect(second.sequence == 2)
        #expect(second.afterFrame == 641)
        #expect(seq.framesWritten == 642 - 1)
        #expect(seq.decryptedRequests == 2)
    }

    @Test func decryptedRequestBeforeAnyFrameLinksToZero() {
        var seq = CaptureSequence()
        let entry = seq.recordDecryptedRequest()
        #expect(entry.sequence == 1)
        #expect(entry.afterFrame == 0)
        #expect(seq.nextFrameNumber == 1)
    }

    @Test func frameLabelUsesDecryptedSequence() {
        let frame = PacketModel(frameNumber: 640, sourceIP: "a", destinationIP: "b",
                                protocolName: "HTTPS", length: 74, info: "[SYN]", hexDump: "")
        #expect(frame.frameLabel == "#640")
        #expect(!frame.isDecryptedRequest)

        let decrypted = PacketModel(frameNumber: 640, sourceIP: "device", destinationIP: "example.com",
                                    protocolName: "HTTPS", length: 120, info: PacketModel.tlsDecryptedInfo,
                                    hexDump: "", decryptedSequence: 12)
        #expect(decrypted.frameLabel == "D-12")
        #expect(decrypted.isDecryptedRequest)
    }

    // Logs written by 1.9 mark decrypted requests with info only and isReconstructed true.
    @Test func legacyDecryptedEntryDecodesAsDecryptedRequest() throws {
        let json = """
        {"id":"6C5A2E0B-5E9E-4D5D-9B1E-1F6A4E2B3C4D","frameNumber":592,"timestamp":"2026-10-12T23:03:10Z",
         "sourceIP":"device","destinationIP":"example.com","destinationPort":443,"protocolName":"HTTPS",
         "length":120,"info":"\(PacketModel.tlsDecryptedInfo)","hexDump":"","direction":"outbound","isReconstructed":true}
        """
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        let packet = try dec.decode(PacketModel.self, from: Data(json.utf8))
        #expect(packet.decryptedSequence == nil)
        #expect(packet.isDecryptedRequest)
        #expect(packet.frameLabel == "#592")
    }

    @Test func decryptedSequenceRoundTripsThroughJSON() throws {
        let original = PacketModel(frameNumber: 640, sourceIP: "device", destinationIP: "example.com",
                                   protocolName: "HTTPS", length: 120, info: PacketModel.tlsDecryptedInfo,
                                   hexDump: "", decryptedSequence: 3)
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        let decoded = try dec.decode(PacketModel.self, from: try enc.encode(original))
        #expect(decoded.decryptedSequence == 3)
        #expect(decoded.frameNumber == 640)

        let plain = PacketModel(frameNumber: 1, sourceIP: "a", destinationIP: "b",
                                protocolName: "DNS", length: 60, info: "Query: x", hexDump: "")
        let plainJSON = String(decoding: try enc.encode(plain), as: UTF8.self)
        #expect(!plainJSON.contains("decryptedSequence"))
    }

    // Logs written before captureSource existed are tunnel frames.
    @Test func packetModelDecodesWithoutCaptureSourceAsTunnel() throws {
        let json = """
        {"id":"6C5A2E0B-5E9E-4D5D-9B1E-1F6A4E2B3C4D","frameNumber":12,"timestamp":"2026-10-12T23:03:10Z",
         "sourceIP":"192.168.8.178","destinationIP":"224.0.0.251","protocolName":"mDNS",
         "length":128,"info":"Multicast DNS","hexDump":"","direction":"inbound"}
        """
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        let packet = try dec.decode(PacketModel.self, from: Data(json.utf8))
        #expect(packet.captureSource == .tunnel)
        #expect(PacketModel(frameNumber: 1, sourceIP: "a", destinationIP: "b",
                            protocolName: "DNS", length: 1, info: "", hexDump: "").captureSource == .tunnel)
    }

    @Test func captureSourceRoundTripsThroughJSON() throws {
        let original = PacketModel(frameNumber: 7, sourceIP: "192.168.8.178", destinationIP: "224.0.0.251",
                                   sourcePort: 5353, destinationPort: 5353, protocolName: "mDNS", length: 128,
                                   info: "Multicast DNS [reconstructed]", hexDump: "", direction: .inbound,
                                   isReconstructed: true, captureSource: .mdnsListener)
        let enc = JSONEncoder()
        enc.dateEncodingStrategy = .iso8601
        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        let decoded = try dec.decode(PacketModel.self, from: try enc.encode(original))
        #expect(decoded.captureSource == .mdnsListener)
        #expect(decoded.frameLabel == "#7")
        #expect(decoded.isReconstructed)
    }

    @MainActor
    @Test func analysisTotalExcludesDecryptedRequests() {
        var packets: [PacketModel] = []
        for n in 1...5 {
            packets.append(PacketModel(frameNumber: n, sourceIP: "a", destinationIP: "b",
                                       protocolName: "HTTPS", length: 100, info: "[ACK]", hexDump: "",
                                       direction: n.isMultiple(of: 2) ? .inbound : .outbound))
        }
        packets.append(PacketModel(frameNumber: 5, sourceIP: "device", destinationIP: "example.com",
                                   protocolName: "HTTPS", length: 999, info: PacketModel.tlsDecryptedInfo,
                                   hexDump: "", decryptedSequence: 1))
        let vm = AnalysisViewModel()
        vm.ingest(packets: packets)
        #expect(vm.totalPackets == 5)
        #expect(vm.outboundBytes == 300)
        #expect(vm.inboundBytes == 200)
        #expect(vm.protocolDistribution["HTTPS"] == 100.0)
    }
}
