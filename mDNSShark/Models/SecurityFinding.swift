// mDNSShark/Models/SecurityFinding.swift
import Foundation

enum Severity: Int, Comparable, Codable {
    case informational = 0, warning = 1, critical = 2
    static func < (l: Severity, r: Severity) -> Bool { l.rawValue < r.rawValue }
}

enum FindingSource: String, Codable {
    case portRule = "Port", bonjourRule = "Bonjour", cisaKEV = "CISA", nist = "NIST"
}

struct SecurityFinding: Identifiable, Equatable {
    let id: UUID
    let deviceID: UUID
    let severity: Severity
    let title: String
    let description: String
    let recommendation: String
    let source: FindingSource

    init(id: UUID = UUID(), deviceID: UUID, severity: Severity, title: String,
         description: String, recommendation: String, source: FindingSource) {
        self.id = id; self.deviceID = deviceID; self.severity = severity
        self.title = title; self.description = description
        self.recommendation = recommendation; self.source = source
    }
}
