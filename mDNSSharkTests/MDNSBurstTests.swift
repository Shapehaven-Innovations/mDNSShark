// mDNSSharkTests/MDNSBurstTests.swift
import Testing
import Foundation
@testable import mDNSShark

@Suite("A sustained mDNS burst through build, parse and pcap append stays bounded and fully counted")
struct MDNSBurstTests {

    private func residentBytes() -> UInt64 {
        var info = mach_task_basic_info()
        var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(MACH_TASK_BASIC_INFO), $0, &count)
            }
        }
        return kr == KERN_SUCCESS ? info.resident_size : 0
    }

    // 20,000 frames of 900 bytes is well past anything a LAN produces in a minute (arm H saw 18 in 30 s).
    @Test func twentyThousandFramesAreAllWrittenWithBoundedMemory() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("burst-\(UUID().uuidString).pcap")
        defer { try? FileManager.default.removeItem(at: url) }
        let writer = PCAPWriter(fileURL: url)
        try writer.startCapture()

        let payload = Data((0..<900).map { UInt8(truncatingIfNeeded: $0 &* 31) })
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let before = residentBytes()
        var sequence = CaptureSequence()
        var mdnsRows = 0
        var frameBytes = 0
        for i in 0..<20_000 {
            let own = i % 4 == 0
            let d = MDNSDatagram(payload: payload, source: own ? [192, 168, 8, 123] : [192, 168, 8, 178],
                                 destination: [224, 0, 0, 251], sourcePort: 5353, destinationPort: 5353,
                                 ttl: 255, timestamp: start.addingTimeInterval(Double(i) * 0.0005))
            let frame = MDNSFrameBuilder.ipv4Frame(d)
            frameBytes = frame.count
            let packet = PacketParser.parse(frame, frameNumber: sequence.nextFrameNumber, timestamp: d.timestamp,
                                            direction: own ? .outbound : .inbound, isReconstructed: true, captureSource: .mdnsListener)
            if packet.protocolName == "mDNS" { mdnsRows += 1 }
            sequence.recordFrame()
            writer.appendPacket(frame, at: d.timestamp, isReconstructed: true)
        }
        let result = writer.finish()
        let after = residentBytes()

        #expect(result.total == 20_000)
        #expect(result.reconstructed == 20_000)
        #expect(result.clampedTimestamps == 0)
        #expect(mdnsRows == 20_000)
        #expect(sequence.framesWritten == result.total)
        let size = try FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int
        #expect(size == 24 + 20_000 * (16 + frameBytes))
        // Nothing per frame is retained, so growth should be far below the 50 MB extension budget.
        #expect(after < before + 48 * 1024 * 1024)
    }
}
