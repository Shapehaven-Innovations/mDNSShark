import Foundation

public struct CaptureFinding: Codable, Equatable, Sendable {
    public var severity: String
    public var title: String

    public init(severity: String, title: String) {
        self.severity = severity
        self.title = title
    }
}

public struct CaptureSummary: Codable, Equatable, Sendable {
    public static let schemaVersion = 1

    public var version: Int
    public var updatedAt: Date
    public var isCapturing: Bool
    public var totalPackets: Int
    public var inboundBytes: Int64
    public var outboundBytes: Int64
    public var protocolShare: [String: Double]
    public var packetsPerSecond: [Int]
    public var findings: [CaptureFinding]

    public init(version: Int, updatedAt: Date, isCapturing: Bool, totalPackets: Int, inboundBytes: Int64,
                outboundBytes: Int64, protocolShare: [String: Double], packetsPerSecond: [Int],
                findings: [CaptureFinding]) {
        self.version = version
        self.updatedAt = updatedAt
        self.isCapturing = isCapturing
        self.totalPackets = totalPackets
        self.inboundBytes = inboundBytes
        self.outboundBytes = outboundBytes
        self.protocolShare = protocolShare
        self.packetsPerSecond = packetsPerSecond
        self.findings = findings
    }
}
