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
        hexDump: String
    ) {
        self.id = id; self.frameNumber = frameNumber; self.timestamp = timestamp
        self.sourceIP = sourceIP; self.destinationIP = destinationIP
        self.sourcePort = sourcePort; self.destinationPort = destinationPort
        self.protocolName = protocolName; self.length = length
        self.info = info; self.hexDump = hexDump
    }

    var formattedTimestamp: String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f.string(from: timestamp)
    }
}
