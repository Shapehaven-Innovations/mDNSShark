// PacketTunnel/PCAPWriter.swift
import Foundation

// Writes a libpcap-compatible .pcap file (LINKTYPE_RAW = 101, raw IPv4).
// Thread-safe append via serial queue. stopCapture must not be called from this class's own queue.
final class PCAPWriter {
    private let fileURL: URL
    private let queue = DispatchQueue(label: "com.mDNSShark.pcapwriter")
    private var fileHandle: FileHandle?
    private var packetCount: Int = 0
    private var reconstructedCount: Int = 0
    private var captureStartTime: Date = Date()

    init(fileURL: URL) {
        self.fileURL = fileURL
    }

    // Call once before appending any packets. Creates the file and writes the global header.
    func startCapture() throws {
        try queue.sync {
            captureStartTime = Date()
            guard FileManager.default.createFile(atPath: fileURL.path, contents: nil) else {
                throw CocoaError(.fileWriteUnknown)
            }
            fileHandle = try FileHandle(forWritingTo: fileURL)
            fileHandle?.write(globalHeader())
            packetCount = 0
            reconstructedCount = 0
        }
    }

    // Append one raw IPv4 packet. Safe to call from any thread.
    func appendPacket(_ rawIP: Data, at timestamp: Date, isReconstructed: Bool = false) {
        queue.async { [weak self] in
            guard let self, let fh = self.fileHandle else { return }
            fh.write(self.packetRecord(rawIP, timestamp: timestamp))
            self.packetCount += 1
            if isReconstructed { self.reconstructedCount += 1 }
        }
    }

    // Flush and close. Returns metadata dict for capture-meta.json.
    func stopCapture(deviceWiFiIP: String, tunnelIP: String, totalPackets: Int) -> [String: Any] {
        dispatchPrecondition(condition: .notOnQueue(queue))
        var startTime = Date()
        var reconCount = 0
        queue.sync {
            fileHandle?.closeFile()
            fileHandle = nil
            startTime = captureStartTime
            reconCount = reconstructedCount
        }
        return [
            "captureStart": ISO8601DateFormatter().string(from: startTime),
            "deviceWiFiIP": deviceWiFiIP,
            "tunnelIP": tunnelIP,
            "totalPackets": totalPackets,
            "rawPackets": totalPackets - reconCount,
            "reconstructedPackets": reconCount,
            "disclaimer": "Inbound TCP packets are stream-proxied. Payload bytes are accurate. TCP sequence numbers and window sizes are approximate."
        ]
    }

    // MARK: - Private

    private func globalHeader() -> Data {
        var d = Data()
        d.appendUInt32LE(0xa1b2c3d4)  // magic — standard pcap, microsecond timestamps
        d.appendUInt16LE(2)            // version major
        d.appendUInt16LE(4)            // version minor
        d.appendInt32LE(0)             // thiszone (UTC)
        d.appendUInt32LE(0)            // sigfigs
        d.appendUInt32LE(65535)        // snaplen
        d.appendUInt32LE(101)          // LINKTYPE_RAW (raw IPv4)
        return d
    }

    private func packetRecord(_ packet: Data, timestamp: Date) -> Data {
        let ts = timestamp.timeIntervalSince1970
        let sec  = UInt32(ts)
        let usec = UInt32((ts - Double(sec)) * 1_000_000)
        let capLen = UInt32(min(packet.count, 65535))
        var d = Data()
        d.appendUInt32LE(sec)
        d.appendUInt32LE(usec)
        d.appendUInt32LE(capLen)
        d.appendUInt32LE(UInt32(packet.count))
        d.append(packet.prefix(Int(capLen)))
        return d
    }
}

// MARK: - Data helpers (little-endian for PCAP headers)
private extension Data {
    mutating func appendUInt32LE(_ v: UInt32) {
        var x = v.littleEndian; append(Data(bytes: &x, count: MemoryLayout<UInt32>.size))
    }
    mutating func appendUInt16LE(_ v: UInt16) {
        var x = v.littleEndian; append(Data(bytes: &x, count: MemoryLayout<UInt16>.size))
    }
    mutating func appendInt32LE(_ v: Int32) {
        var x = v.littleEndian; append(Data(bytes: &x, count: MemoryLayout<Int32>.size))
    }
}
