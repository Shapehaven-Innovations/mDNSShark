// mDNSSharkTests/TopologyNodeStatusTests.swift
import Testing
import Foundation
@testable import mDNSShark

@Suite("Topology node colour follows the device's settled state")
struct TopologyNodeStatusTests {

    private func finding(for device: DiscoveredDevice, severity: Severity) -> SecurityFinding {
        SecurityFinding(deviceID: device.id, deviceName: device.hostname, deviceIcon: "questionmark.circle",
                        severity: severity, title: "t", description: "d", recommendation: "r", source: .portRule)
    }

    @Test("a device whose probes have not settled is pending even when findings exist")
    func pendingEvenWithFindings() {
        var device = DiscoveredDevice(hostname: "cam", ipAddress: "192.168.1.20", openPorts: [23])
        device.probesSettled = false
        device.securityFindings = [finding(for: device, severity: .critical)]

        #expect(TopologyNode(device: device).securityStatus == .pending)
        #expect(TopologyNode.status(findings: device.securityFindings, settled: false) == .pending)
    }

    @Test("a settled device with no findings is secure")
    func settledWithNoFindingsIsSecure() {
        var device = DiscoveredDevice(hostname: "mac", ipAddress: "192.168.1.10")
        device.probesSettled = true
        #expect(TopologyNode(device: device).securityStatus == .secure)
    }

    @Test("a settled device takes the colour of its worst finding")
    func settledTakesWorstFinding() {
        var device = DiscoveredDevice(hostname: "cam", ipAddress: "192.168.1.20", openPorts: [23])
        device.probesSettled = true
        device.securityFindings = [finding(for: device, severity: .informational), finding(for: device, severity: .critical)]
        #expect(TopologyNode(device: device).securityStatus == .critical)
    }

    @Test("no active chip shows every status, pending included")
    func noChipShowsEverything() {
        for status in [SecurityStatus.pending, .secure, .informational, .warning, .critical] {
            #expect(TopologyNode.matchesFilters(status, []))
        }
    }

    @Test("the Pending chip is the only chip that shows pending devices")
    func pendingChipShowsPendingOnly() {
        #expect(TopologyNode.matchesFilters(.pending, [.pending]))
        #expect(TopologyNode.matchesFilters(.pending, [.pending, .critical]))
        #expect(!TopologyNode.matchesFilters(.pending, [.secure]))
        #expect(!TopologyNode.matchesFilters(.pending, [.secure, .informational, .warning, .critical]))
        #expect(!TopologyNode.matchesFilters(.secure, [.pending]))
    }

    @Test("Secure also shows informational-only devices, and each other chip shows only its own status")
    func secureCoversInformational() {
        #expect(TopologyNode.matchesFilters(.informational, [.secure]))
        #expect(TopologyNode.matchesFilters(.informational, [.informational]))
        #expect(!TopologyNode.matchesFilters(.secure, [.informational]))
        #expect(TopologyNode.matchesFilters(.warning, [.warning]))
        #expect(!TopologyNode.matchesFilters(.warning, [.critical]))
        #expect(!TopologyNode.matchesFilters(.critical, [.secure, .warning]))
    }

    @Test("the node's VoiceOver label names the host, address and status")
    func accessibilityLabelNamesHostAndStatus() {
        var pending = DiscoveredDevice(hostname: "cam", ipAddress: "192.168.1.20", openPorts: [23])
        pending.probesSettled = false
        #expect(TopologyNode(device: pending).accessibilityLabel == "cam, 192.168.1.20, pending")

        var critical = pending
        critical.probesSettled = true
        critical.securityFindings = [finding(for: critical, severity: .critical)]
        #expect(TopologyNode(device: critical).accessibilityLabel == "cam, 192.168.1.20, critical")

        var secure = DiscoveredDevice(hostname: "mac", ipAddress: "192.168.1.10")
        secure.probesSettled = true
        #expect(TopologyNode(device: secure).accessibilityLabel == "mac, 192.168.1.10, secure")
    }

    @Test("a vendor advisory is spoken because its badge is otherwise only an icon")
    func accessibilityLabelMentionsVendorAdvisory() {
        var device = DiscoveredDevice(hostname: "tv", ipAddress: "192.168.1.30")
        device.probesSettled = true
        device.securityFindings = [SecurityFinding(deviceID: device.id, deviceName: "tv", deviceIcon: "tv", severity: .informational,
                                                   title: "t", description: "d", recommendation: "r", source: .vendorAdvisory)]
        // A vendor advisory flags the manufacturer, not the device, so it never changes the status itself.
        #expect(TopologyNode(device: device).accessibilityLabel == "tv, 192.168.1.30, secure, vendor advisory")
    }

    @Test("the services node label counts services without a device")
    func servicesNodeLabel() {
        #expect(ServicesGroupNodeView.accessibilityLabel(count: 1) == "1 service without a device")
        #expect(ServicesGroupNodeView.accessibilityLabel(count: 3) == "3 services without a device")
    }

    @Test("every status has a spoken name")
    func everyStatusHasASpokenName() {
        #expect(SecurityStatus.pending.accessibilityName == "pending")
        #expect(SecurityStatus.informational.accessibilityName == "informational")
        #expect(SecurityStatus.critical.accessibilityName == "critical")
    }
}
