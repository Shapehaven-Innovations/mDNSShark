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

    func ingest(packets: [PacketModel]) {
        totalPackets = packets.count
        updateTraffic(packets: packets)
        updateDistribution(packets: packets)
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

    private func updateTraffic(packets: [PacketModel]) {
        let inbound  = packets.filter { $0.direction == .inbound  }.reduce(0) { $0 + $1.length }
        let outbound = packets.filter { $0.direction == .outbound }.reduce(0) { $0 + $1.length }
        inboundBytes  = Int64(inbound)
        outboundBytes = Int64(outbound)
    }

    private func updateDistribution(packets: [PacketModel]) {
        guard !packets.isEmpty else { return }
        let total = Double(packets.count)
        var counts: [String: Int] = [:]
        for p in packets { counts[p.protocolName, default: 0] += 1 }
        protocolDistribution = counts.mapValues { Double($0) / total * 100.0 }
    }
}
