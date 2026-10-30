// mDNSShark/Models/PacketModel.swift
import Foundation

struct PacketModel: Identifiable, Codable {
    /// The `info` value marking an HTTPS packet whose payload was decrypted by TLS inspection.
    static let tlsDecryptedInfo = "TLS-decrypted"

    let id: UUID
    let frameNumber: Int
    let timestamp: Date
    let sourceIP: String
    let destinationIP: String
    let sourcePort: Int?
    let destinationPort: Int?
    let protocolName: String
    let length: Int
    let info: String
    let hexDump: String
    let payloadText: String?
    let direction: PacketDirection
    let isReconstructed: Bool
    /// Set only on decrypted HTTPS requests, which are logged but never written to the pcap; `frameNumber` then holds the last pcap frame written before the request.
    let decryptedSequence: Int?

    init(
        id: UUID = UUID(),
        frameNumber: Int,
        timestamp: Date = Date(),
        sourceIP: String,
        destinationIP: String,
        sourcePort: Int? = nil,
        destinationPort: Int? = nil,
        protocolName: String,
        length: Int,
        info: String,
        hexDump: String,
        payloadText: String? = nil,
        direction: PacketDirection = .outbound,
        isReconstructed: Bool = false,
        decryptedSequence: Int? = nil
    ) {
        self.id = id; self.frameNumber = frameNumber; self.timestamp = timestamp
        self.sourceIP = sourceIP; self.destinationIP = destinationIP
        self.sourcePort = sourcePort; self.destinationPort = destinationPort
        self.protocolName = protocolName; self.length = length
        self.info = info; self.hexDump = hexDump; self.payloadText = payloadText
        self.direction = direction; self.isReconstructed = isReconstructed
        self.decryptedSequence = decryptedSequence
    }

    /// True for decrypted HTTPS requests; the info fallback covers logs written before `decryptedSequence` existed.
    var isDecryptedRequest: Bool { decryptedSequence != nil || info == Self.tlsDecryptedInfo }

    /// "D-12" for a decrypted request, otherwise "#640" matching the pcap frame number.
    var frameLabel: String {
        if let seq = decryptedSequence { return "D-\(seq)" }
        return "#\(frameNumber)"
    }

    // Decode with defaults for new fields so old JSON in packets.log still parses
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id              = try c.decode(UUID.self,   forKey: .id)
        frameNumber     = try c.decode(Int.self,    forKey: .frameNumber)
        timestamp       = try c.decode(Date.self,   forKey: .timestamp)
        sourceIP        = try c.decode(String.self, forKey: .sourceIP)
        destinationIP   = try c.decode(String.self, forKey: .destinationIP)
        sourcePort      = try c.decodeIfPresent(Int.self,    forKey: .sourcePort)
        destinationPort = try c.decodeIfPresent(Int.self,    forKey: .destinationPort)
        protocolName    = try c.decode(String.self, forKey: .protocolName)
        length          = try c.decode(Int.self,    forKey: .length)
        info            = try c.decode(String.self, forKey: .info)
        hexDump         = try c.decode(String.self, forKey: .hexDump)
        payloadText     = try c.decodeIfPresent(String.self, forKey: .payloadText)
        direction       = try c.decodeIfPresent(PacketDirection.self, forKey: .direction) ?? .outbound
        isReconstructed = try c.decodeIfPresent(Bool.self, forKey: .isReconstructed) ?? false
        decryptedSequence = try c.decodeIfPresent(Int.self, forKey: .decryptedSequence)
    }

    var formattedTimestamp: String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f.string(from: timestamp)
    }
}

/// Numbers pcap frames and decrypted requests on separate sequences so app frame N is pcap record N.
struct CaptureSequence {
    private(set) var framesWritten = 0
    private(set) var decryptedRequests = 0

    /// Frame number the next pcap record will get (1-based, as Wireshark shows it).
    var nextFrameNumber: Int { framesWritten + 1 }

    @discardableResult
    mutating func recordFrame() -> Int {
        framesWritten += 1
        return framesWritten
    }

    /// Returns the request's own sequence and the last frame written before it (0 if none yet).
    mutating func recordDecryptedRequest() -> (sequence: Int, afterFrame: Int) {
        decryptedRequests += 1
        return (decryptedRequests, framesWritten)
    }
}
