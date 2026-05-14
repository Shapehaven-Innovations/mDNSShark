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
    @Published var inboundKB: Double = 0
    @Published var outboundKB: Double = 0
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
        let wifiIP = LocalDeviceScanner().getWiFiAddress() ?? ""
        let inbound  = packets.filter { isLocalIP($0.destinationIP, wifiIP: wifiIP) }.reduce(0) { $0 + $1.length }
        let outbound = packets.filter { isLocalIP($0.sourceIP,      wifiIP: wifiIP) }.reduce(0) { $0 + $1.length }
        inboundKB  = Double(inbound)  / 1024.0
        outboundKB = Double(outbound) / 1024.0
    }

    // Matches the device's WiFi IP and the tunnel interface IP (192.168.100.x assigned in PacketTunnelProvider).
    private func isLocalIP(_ ip: String, wifiIP: String) -> Bool {
        guard !ip.isEmpty else { return false }
        if !wifiIP.isEmpty && ip == wifiIP { return true }
        return ip.hasPrefix("192.168.100.")
    }

    private func updateDistribution(packets: [PacketModel]) {
        guard !packets.isEmpty else { return }
        let total = Double(packets.count)
        var counts: [String: Int] = [:]
        for p in packets { counts[p.protocolName, default: 0] += 1 }
        protocolDistribution = counts.mapValues { Double($0) / total * 100.0 }
    }
}
