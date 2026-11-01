// mDNSShark/Analysis/AnalysisViewModel.swift
import Foundation

enum RecommendationAction { case navigateToSecurity, navigateToTopology }

struct SecurityRecommendation: Identifiable {
    let id = UUID()
    let severity: Severity
    let title: String
    let description: String
    let actionTitle: String?
    let action: RecommendationAction?
}

@MainActor
final class AnalysisViewModel: ObservableObject {
    @Published var inboundBytes: Int64 = 0
    @Published var outboundBytes: Int64 = 0
    @Published var totalPackets: Int = 0
    @Published var protocolDistribution: [String: Double] = [:]
    @Published var recommendations: [SecurityRecommendation] = []

    init() {}

    // Running totals, so each publish walks only the appended packets. seenCount and lastID detect a reset or replacement and force a recount.
    private var seenCount = 0
    private var lastID: UUID?
    private var protocolCounts: [String: Int] = [:]

    // Decrypted requests duplicate bytes already counted as encrypted frames and have no pcap record, so only real frames count.
    func ingest(packets: [PacketModel]) {
        let appendOnly = packets.count >= seenCount && (seenCount == 0 || packets[seenCount - 1].id == lastID)
        if !appendOnly {
            seenCount = 0; lastID = nil; protocolCounts = [:]
            totalPackets = 0; inboundBytes = 0; outboundBytes = 0
        }
        var frames = 0
        var inbound: Int64 = 0
        var outbound: Int64 = 0
        for p in packets[seenCount...] where !p.isDecryptedRequest {
            frames += 1
            if p.direction == .inbound { inbound += Int64(p.length) } else if p.direction == .outbound { outbound += Int64(p.length) }
            protocolCounts[p.protocolName, default: 0] += 1
        }
        seenCount = packets.count
        lastID = packets.last?.id
        totalPackets += frames
        inboundBytes += inbound
        outboundBytes += outbound
        let total = Double(totalPackets)
        protocolDistribution = total > 0 ? protocolCounts.mapValues { Double($0) / total * 100.0 } : [:]
    }

    func update(findings: [SecurityFinding]) {
        var recs: [SecurityRecommendation] = []
        // Distinct devices, vendor advisories excluded.
        let critCount = Set(findings.filter { $0.severity == .critical && $0.source != .vendorAdvisory }.map(\.deviceID)).count
        if critCount > 0 {
            recs.append(SecurityRecommendation(
                severity: .critical,
                title: "Critical Issues on \(critCount) \(critCount == 1 ? "Device" : "Devices")",
                description: "\(critCount) \(critCount == 1 ? "device has" : "devices have") an exposed cleartext-login service (Telnet or FTP) that needs attention.",
                actionTitle: "View Issues", action: .navigateToSecurity
            ))
        }
        // Same rule as the header's "vulnerable" count.
        let vulnerableCount = findings.vulnerableDeviceIDs.count
        if vulnerableCount > 0 {
            recs.append(SecurityRecommendation(
                severity: .warning,
                title: "Network Segmentation",
                description: "Consider segmenting your network to isolate \(vulnerableCount) vulnerable \(vulnerableCount == 1 ? "device" : "devices").",
                actionTitle: nil, action: nil
            ))
        }
        recs.append(SecurityRecommendation(
            severity: .informational,
            title: "Network Visualization",
            description: "Use the Topology view to understand device relationships and identify security risks.",
            actionTitle: "View Topology", action: .navigateToTopology
        ))
        recommendations = recs
    }
}
