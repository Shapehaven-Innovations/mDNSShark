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
    @Published var inboundMBps: Double = 0
    @Published var outboundMBps: Double = 0
    @Published var totalPackets: Int = 0
    @Published var protocolDistribution: [String: Double] = [:]
    @Published var recommendations: [SecurityRecommendation] = []

    private let localIP: String

    init(localIP: String = LocalDeviceScanner().getWiFiAddress() ?? "") {
        self.localIP = localIP
    }

    func ingest(packets: [PacketModel]) {
        totalPackets = packets.count
        updateTraffic(packets: packets)
        updateDistribution(packets: packets)
    }

    func update(findings: [SecurityFinding]) {
        var recs: [SecurityRecommendation] = []
        let critCount = findings.filter { $0.severity == .critical }.count
        if critCount > 0 {
            recs.append(SecurityRecommendation(
                severity: .critical,
                title: "\(critCount) Critical \(critCount == 1 ? "Issue" : "Issues") Found",
                description: "\(critCount) \(critCount == 1 ? "device has" : "devices have") critical vulnerabilities requiring immediate attention.",
                actionTitle: "View Issues", action: .navigateToSecurity
            ))
        }
        let warnCount = findings.filter { $0.severity == .warning }.count
        if warnCount > 0 {
            recs.append(SecurityRecommendation(
                severity: .warning,
                title: "Network Segmentation",
                description: "Consider segmenting your network to isolate \(warnCount) vulnerable \(warnCount == 1 ? "device" : "devices").",
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
        let now = Date()
        let window = packets.filter { now.timeIntervalSince($0.timestamp) <= 1.0 }
        let inbound  = window.filter { $0.destinationIP == localIP }.reduce(0) { $0 + $1.length }
        let outbound = window.filter { $0.sourceIP      == localIP }.reduce(0) { $0 + $1.length }
        inboundMBps  = Double(inbound)  / 1_048_576.0
        outboundMBps = Double(outbound) / 1_048_576.0
    }

    private func updateDistribution(packets: [PacketModel]) {
        guard !packets.isEmpty else { return }
        let total = Double(packets.count)
        var counts: [String: Int] = [:]
        for p in packets { counts[p.protocolName, default: 0] += 1 }
        protocolDistribution = counts.mapValues { Double($0) / total * 100.0 }
    }
}
