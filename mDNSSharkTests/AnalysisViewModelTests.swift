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
}
