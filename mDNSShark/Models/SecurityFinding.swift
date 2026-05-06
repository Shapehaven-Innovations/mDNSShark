// mDNSShark/Models/SecurityFinding.swift
import Foundation

enum Severity: Int, Comparable, Codable {
    case informational = 0, warning = 1, critical = 2
    static func < (l: Severity, r: Severity) -> Bool { l.rawValue < r.rawValue }

    var exportLabel: String {
        switch self {
        case .critical:      return "CRITICAL"
        case .warning:       return "WARNING"
        case .informational: return "INFO"
        }
    }
}

enum FindingSource: String, Codable {
    case portRule = "Port", bonjourRule = "Bonjour", cisaKEV = "CISA", nist = "NIST"
}

struct SecurityFinding: Identifiable, Equatable {
    let id: UUID
    let deviceID: UUID
    let deviceName: String
    let deviceIcon: String
    let severity: Severity
    let title: String
    let description: String
    let recommendation: String
    let source: FindingSource
    let cveID: String?
    let referenceURL: URL?

    init(
        id: UUID = UUID(),
        deviceID: UUID,
        deviceName: String,
        deviceIcon: String,
        severity: Severity,
        title: String,
        description: String,
        recommendation: String,
        source: FindingSource,
        cveID: String? = nil,
        referenceURL: URL? = nil
    ) {
        self.id = id
        self.deviceID = deviceID
        self.deviceName = deviceName
        self.deviceIcon = deviceIcon
        self.severity = severity
        self.title = title
        self.description = description
        self.recommendation = recommendation
        self.source = source
        self.cveID = cveID
        self.referenceURL = referenceURL
    }
}
