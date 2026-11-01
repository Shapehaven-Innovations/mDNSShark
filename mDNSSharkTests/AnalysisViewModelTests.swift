// mDNSSharkTests/AnalysisViewModelTests.swift
import Testing
import Foundation
@testable import mDNSShark

@MainActor
@Suite("Analysis counts match header vulnerable rule")
struct AnalysisViewModelTests {

    private func finding(_ device: UUID, _ severity: Severity, source: FindingSource = .portRule) -> SecurityFinding {
        SecurityFinding(deviceID: device, deviceName: "d", deviceIcon: "x", severity: severity,
                        title: "t", description: "d", recommendation: "r", source: source)
    }

    private func segmentation(_ vm: AnalysisViewModel) -> String? {
        vm.recommendations.first { $0.title == "Network Segmentation" }?.description
    }

    @Test func vendorAdvisoryOnlyCountsZero() {
        let findings = [finding(UUID(), .warning, source: .vendorAdvisory)]
        #expect(findings.vulnerableDeviceIDs.isEmpty)
        let vm = AnalysisViewModel()
        vm.update(findings: findings)
        #expect(segmentation(vm) == nil)
    }

    @Test func multipleFindingsOnOneDeviceCountOnce() {
        let id = UUID()
        let findings = [finding(id, .warning), finding(id, .warning), finding(id, .critical)]
        #expect(findings.vulnerableDeviceIDs.count == 1)
        let vm = AnalysisViewModel()
        vm.update(findings: findings)
        #expect(segmentation(vm)?.contains("isolate 1 vulnerable device.") == true)
    }

    @Test func informationalIsExcluded() {
        let findings = [finding(UUID(), .informational)]
        #expect(findings.vulnerableDeviceIDs.isEmpty)
    }

    private func pkt(_ proto: String, _ length: Int) -> PacketModel {
        PacketModel(frameNumber: 1, sourceIP: "a", destinationIP: "b", protocolName: proto, length: length, info: "", hexDump: "")
    }

    @Test("feeding packets in two steps gives the same totals as feeding them at once")
    func incrementalMatchesOneShot() {
        let all = [pkt("TCP", 10), pkt("TCP", 20), pkt("UDP", 30), pkt("TCP", 40)]
        let step = AnalysisViewModel()
        step.ingest(packets: Array(all[..<2]))
        step.ingest(packets: all)
        let once = AnalysisViewModel()
        once.ingest(packets: all)
        #expect(step.totalPackets == 4 && step.totalPackets == once.totalPackets)
        #expect(step.protocolDistribution == once.protocolDistribution)
        step.ingest(packets: all)
        #expect(step.totalPackets == 4)
    }

    @Test("an emptied capture clears the totals and the protocol percentages")
    func resetClearsDistribution() {
        let vm = AnalysisViewModel()
        vm.ingest(packets: [pkt("TCP", 10)])
        vm.ingest(packets: [])
        #expect(vm.totalPackets == 0 && vm.protocolDistribution.isEmpty)
    }

    @Test("a new capture of the same length is counted afresh, not added to the old one")
    func replacementRecounts() {
        let vm = AnalysisViewModel()
        vm.ingest(packets: [pkt("TCP", 10), pkt("TCP", 10)])
        vm.ingest(packets: [pkt("UDP", 10), pkt("UDP", 10)])
        #expect(vm.totalPackets == 2 && vm.protocolDistribution == ["UDP": 100])
    }
}
