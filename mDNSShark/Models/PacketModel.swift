// mDNSShark/Models/PacketModel.swift
import Foundation

struct PacketModel: Identifiable, Codable {
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
        isReconstructed: Bool = false
    ) {
        self.id = id; self.frameNumber = frameNumber; self.timestamp = timestamp
        self.sourceIP = sourceIP; self.destinationIP = destinationIP
        self.sourcePort = sourcePort; self.destinationPort = destinationPort
        self.protocolName = protocolName; self.length = length
        self.info = info; self.hexDump = hexDump; self.payloadText = payloadText
        self.direction = direction; self.isReconstructed = isReconstructed
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
    }

    var formattedTimestamp: String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f.string(from: timestamp)
    }
}
