// PacketTunnel/PCAPWriter.swift
import Foundation

// Writes a libpcap-compatible .pcap file (LINKTYPE_RAW = 101, raw IPv4 or IPv6).
// Thread-safe append via serial queue. stopCapture must not be called from this class's own queue.
final class PCAPWriter {
    private let fileURL: URL
    private let queue = DispatchQueue(label: "com.mDNSShark.pcapwriter")
    private var fileHandle: FileHandle?
    private var packetCount: Int = 0
    private var reconstructedCount: Int = 0
    private var captureStartTime: Date = Date()
    // Listener frames carry kernel receive times and tunnel frames the handle time, so stamps are clamped to never go backwards.
    private var lastTimestamp: Date?
    private var clampedCount: Int = 0

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
            lastTimestamp = nil
            clampedCount = 0
        }
    }

    // Append one raw IP packet (v4 or v6). Safe to call from any thread.
    func appendPacket(_ rawIP: Data, at timestamp: Date, isReconstructed: Bool = false) {
        queue.async { [weak self] in
            guard let self, let fh = self.fileHandle else { return }
            var stamp = timestamp
            if let last = self.lastTimestamp, stamp < last { stamp = last; self.clampedCount += 1 }
            self.lastTimestamp = stamp
            fh.write(self.packetRecord(rawIP, timestamp: stamp))
            self.packetCount += 1
            if isReconstructed { self.reconstructedCount += 1 }
        }
    }

    // Flush and close. Returns what was written, without any tunnel-specific metadata.
    func finish() -> (start: Date, total: Int, reconstructed: Int, clampedTimestamps: Int) {
        dispatchPrecondition(condition: .notOnQueue(queue))
        return queue.sync {
            fileHandle?.closeFile()
            fileHandle = nil
            return (captureStartTime, packetCount, reconstructedCount, clampedCount)
        }
    }

    // Tunnel wrapper over finish(): returns the metadata dict for capture-meta.json.
    // totalPackets is the number of records actually written, so it always equals the pcap's
    // frame count; decrypted HTTPS requests are reported separately because they have no record.
    // `lanRouteStatus` records whether PacketTunnelProvider's LAN-route
    // attempt (todo.md item 1's includeAllNetworksInCapture A/B test) found
    // a Wi-Fi subnet to add and what it added, or why it couldn't, so a pcap
    // showing zero LAN traffic can be told apart from "the route was never added".
    func stopCapture(deviceWiFiIP: String, tunnelIP: String, decryptedRequests: Int = 0,
                      lanRouteStatus: String = "n/a") -> [String: Any] {
        let result = finish()
        return [
            "captureStart": ISO8601DateFormatter().string(from: result.start),
            "deviceWiFiIP": deviceWiFiIP,
            "tunnelIP": tunnelIP,
            "lanRouteStatus": lanRouteStatus,
            "totalPackets": result.total,
            "rawPackets": result.total - result.reconstructed,
            "reconstructedPackets": result.reconstructed,
            "decryptedRequests": decryptedRequests,
            "clampedTimestamps": result.clampedTimestamps,
            "disclaimer": "Inbound TCP packets are stream-proxied. Payload bytes are accurate. TCP sequence numbers and window sizes are approximate."
        ]
    }

    // MARK: - Private

    private func globalHeader() -> Data {
        var d = Data()
        d.appendUInt32LE(0xa1b2c3d4)  // magic - standard pcap, microsecond timestamps
        d.appendUInt16LE(2)            // version major
        d.appendUInt16LE(4)            // version minor
        d.appendInt32LE(0)             // thiszone (UTC)
        d.appendUInt32LE(0)            // sigfigs
        d.appendUInt32LE(65535)        // snaplen
        d.appendUInt32LE(101)          // LINKTYPE_RAW (raw IPv4 or IPv6)
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
