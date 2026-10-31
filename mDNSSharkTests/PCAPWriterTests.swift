// mDNSSharkTests/PCAPWriterTests.swift
import Testing
import Foundation
@testable import mDNSShark

@Suite("PCAPWriter writes a valid raw-IP pcap and reports its own counts")
struct PCAPWriterTests {

    private func tempURL() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("pcapwriter-\(UUID().uuidString).pcap")
    }

    private func le32(_ d: Data, _ offset: Int) -> UInt32 {
        d.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) }.littleEndian
    }

    @Test func globalHeaderIsLinkTypeRaw101LittleEndian() throws {
        let url = tempURL(); defer { try? FileManager.default.removeItem(at: url) }
        let writer = PCAPWriter(fileURL: url)
        try writer.startCapture()
        _ = writer.finish()
        let data = try Data(contentsOf: url)
        #expect(data.count == 24)
        #expect(le32(data, 0) == 0xa1b2c3d4)
        #expect(le32(data, 20) == 101)
    }

    @Test func recordCountMatchesAppendsAndFinishReturnsCounts() throws {
        let url = tempURL(); defer { try? FileManager.default.removeItem(at: url) }
        let writer = PCAPWriter(fileURL: url)
        try writer.startCapture()
        let packet = Data([0x45, 0, 0, 20] + [UInt8](repeating: 0, count: 16))
        writer.appendPacket(packet, at: Date())
        writer.appendPacket(packet, at: Date(), isReconstructed: true)
        writer.appendPacket(packet, at: Date(), isReconstructed: true)
        let result = writer.finish()
        #expect(result.total == 3)
        #expect(result.reconstructed == 2)
        let data = try Data(contentsOf: url)
        #expect(data.count == 24 + 3 * (16 + packet.count))
    }

    @Test func existingTunnelStopCaptureStillReturnsSameKeys() throws {
        let url = tempURL(); defer { try? FileManager.default.removeItem(at: url) }
        let writer = PCAPWriter(fileURL: url)
        try writer.startCapture()
        writer.appendPacket(Data(repeating: 0x45, count: 20), at: Date())
        let meta = writer.stopCapture(deviceWiFiIP: "10.0.0.2", tunnelIP: "100.64.0.1", decryptedRequests: 4, lanRouteStatus: "n/a")
        #expect(Set(meta.keys) == ["captureStart", "deviceWiFiIP", "tunnelIP", "lanRouteStatus", "totalPackets",
                                   "rawPackets", "reconstructedPackets", "decryptedRequests", "clampedTimestamps", "disclaimer"])
        #expect(meta["totalPackets"] as? Int == 1)
        #expect(meta["rawPackets"] as? Int == 1)
        #expect(meta["decryptedRequests"] as? Int == 4)
        #expect(meta["clampedTimestamps"] as? Int == 0)
    }

    /// Record timestamps as (seconds, microseconds) pairs, in file order.
    private func recordTimestamps(_ data: Data) -> [(UInt32, UInt32)] {
        var out: [(UInt32, UInt32)] = []
        var off = 24
        while off + 16 <= data.count {
            out.append((le32(data, off), le32(data, off + 4)))
            off += 16 + Int(le32(data, off + 8))
        }
        return out
    }

    // Listener frames carry kernel receive times, tunnel frames the handle time, so a record can arrive with an earlier stamp than the one before it.
    @Test func recordTimestampsNeverGoBackwards() throws {
        let url = tempURL(); defer { try? FileManager.default.removeItem(at: url) }
        let writer = PCAPWriter(fileURL: url)
        try writer.startCapture()
        let packet = Data(repeating: 0x45, count: 20)
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        writer.appendPacket(packet, at: base)
        writer.appendPacket(packet, at: base.addingTimeInterval(-0.0007))
        writer.appendPacket(packet, at: base.addingTimeInterval(0.5))
        writer.appendPacket(packet, at: base.addingTimeInterval(0.4999))
        writer.appendPacket(packet, at: base.addingTimeInterval(1))
        let result = writer.finish()
        #expect(result.total == 5)
        #expect(result.clampedTimestamps == 2)
        let stamps = recordTimestamps(try Data(contentsOf: url))
        #expect(stamps.count == 5)
        #expect(stamps[1] == stamps[0])
        #expect(stamps[3] == stamps[2])
        for i in 1..<stamps.count {
            #expect(stamps[i].0 > stamps[i - 1].0 || (stamps[i].0 == stamps[i - 1].0 && stamps[i].1 >= stamps[i - 1].1))
        }
    }

    @Test func clampedCountIsReportedInTunnelMeta() throws {
        let url = tempURL(); defer { try? FileManager.default.removeItem(at: url) }
        let writer = PCAPWriter(fileURL: url)
        try writer.startCapture()
        let packet = Data(repeating: 0x45, count: 20)
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        writer.appendPacket(packet, at: base)
        writer.appendPacket(packet, at: base.addingTimeInterval(-1))
        let meta = writer.stopCapture(deviceWiFiIP: "", tunnelIP: "")
        #expect(meta["clampedTimestamps"] as? Int == 1)
        #expect(meta["totalPackets"] as? Int == 2)
    }
}
