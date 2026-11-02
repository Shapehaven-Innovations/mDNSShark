import Testing
import Foundation
import WidgetSnapshot
@testable import mDNSShark

@MainActor
@Suite("DeepLinkRouter")
struct DeepLinkRouterTests {
    let tv = DiscoveredDevice(hostname: "Living Room", ipAddress: "192.168.1.34", macAddress: "aa:bb:cc:dd:ee:ff")
    let nas = DiscoveredDevice(hostname: "nas", ipAddress: "192.168.1.40", addresses: ["192.168.1.40", "192.168.1.41"])

    @Test("every tab parses, case-insensitively") func tabs() {
        for tab in AppTab.allCases {
            #expect(DeepLinkRouter.parse(URL(string: "mdnsshark://tab/\(tab.rawValue.lowercased())")!) == .tab(tab))
        }
        #expect(DeepLinkRouter.parse(URL(string: "mdnsshark://tab/Security")!) == .tab(.security))
    }
    @Test("device links carry mac and ip") func deviceParse() {
        #expect(DeepLinkRouter.parse(URL(string: "mdnsshark://device?mac=AA:BB:CC:DD:EE:FF&ip=192.168.1.34")!)
                == .device(DeviceTarget(mac: "AA:BB:CC:DD:EE:FF", ip: "192.168.1.34")))
        #expect(DeepLinkRouter.parse(URL(string: "mdnsshark://device")!) == .tab(.devices))
    }
    @Test("unknown hosts, tabs and schemes are ignored") func unknown() {
        #expect(DeepLinkRouter.parse(URL(string: "mdnsshark://settings/x")!) == nil)
        #expect(DeepLinkRouter.parse(URL(string: "mdnsshark://tab/nope")!) == nil)
        #expect(DeepLinkRouter.parse(URL(string: "https://tab/devices")!) == nil)
    }
    @Test("MAC wins over IP") func macBeforeIP() {
        #expect(DeepLinkRouter.match(DeviceTarget(mac: "AA:BB:CC:DD:EE:FF", ip: "192.168.1.40"), in: [nas, tv])?.id == tv.id)
    }
    @Test("IP matches any listed address") func ipFallback() {
        #expect(DeepLinkRouter.match(DeviceTarget(mac: "00:00:00:00:00:01", ip: "192.168.1.41"), in: [tv, nas])?.id == nas.id)
        #expect(DeepLinkRouter.match(DeviceTarget(mac: nil, ip: "192.168.1.99"), in: [tv, nas]) == nil)
    }
    @Test("open selects the tab and lands on a matched device") func openMatched() {
        let r = DeepLinkRouter()
        #expect(r.open(URL(string: "mdnsshark://device?mac=aa:bb:cc:dd:ee:ff")!, devices: [tv], isScanning: false) == .devices)
        #expect(r.deviceLinkID == tv.id)
        #expect(r.open(URL(string: "mdnsshark://tab/security")!, devices: [], isScanning: false) == .security)
        #expect(r.open(URL(string: "mdnsshark://bogus")!, devices: [], isScanning: false) == nil)
    }
    @Test("a cold-launch link waits for the scan to find the device") func pendingResolvesDuringScan() {
        let r = DeepLinkRouter()
        _ = r.open(URL(string: "mdnsshark://device?mac=aa:bb:cc:dd:ee:ff")!, devices: [], isScanning: false)
        #expect(r.deviceLinkID == nil)
        r.devicesChanged([tv])
        #expect(r.deviceLinkID == tv.id)
        #expect(r.pendingTarget == nil)
    }
    @Test("scan end drops a link that never matched") func pendingDroppedAtScanEnd() {
        let r = DeepLinkRouter()
        _ = r.open(URL(string: "mdnsshark://device?ip=192.168.1.99")!, devices: [], isScanning: true)
        r.scanFinished()
        r.devicesChanged([DiscoveredDevice(hostname: "late", ipAddress: "192.168.1.99")])
        #expect(r.deviceLinkID == nil)
    }
    @Test("an idle miss with rows does not wait") func idleMissDoesNotWait() {
        let r = DeepLinkRouter()
        _ = r.open(URL(string: "mdnsshark://device?ip=192.168.1.99")!, devices: [tv], isScanning: false)
        #expect(r.pendingTarget == nil)
    }
    @Test("the widget link parses to the Devices tab") func widgetLink() {
        #expect(DeepLinkRouter.parse(WidgetLink.devicesTab) == .tab(.devices))
    }
}

@Suite("Widget scan request")
struct WidgetScanRequestTests {
    @Test("the widget flag lives in the SharedSettings suite") func sameSuite() {
        #expect(AppGroup.identifier == SharedSettings.suiteName)
    }

    private func defaults() -> UserDefaults {
        let d = UserDefaults(suiteName: "WidgetScanRequestTests.\(UUID().uuidString)")!
        return d
    }
    @MainActor @Test("an unsettled gate consumes the flag without restarting") func unsettledGate() {
        let d = defaults(); let now = Date()
        ScanRequestFlag.stamp(in: d, at: now)
        var calls = 0
        AppCoordinator.consumeScanRequest(from: d, now: now, gateSettled: false) { calls += 1 }
        #expect(calls == 0)
        #expect(d.object(forKey: ScanRequestFlag.key) == nil)
    }
    @MainActor @Test("a settled gate restarts exactly once") func settledGate() {
        let d = defaults(); let now = Date()
        ScanRequestFlag.stamp(in: d, at: now)
        var calls = 0
        AppCoordinator.consumeScanRequest(from: d, now: now, gateSettled: true) { calls += 1 }
        AppCoordinator.consumeScanRequest(from: d, now: now, gateSettled: true) { calls += 1 }
        #expect(calls == 1)
    }
    @MainActor @Test("a stale flag is ignored even when settled") func staleIgnored() {
        let d = defaults(); let now = Date()
        ScanRequestFlag.stamp(in: d, at: now.addingTimeInterval(-300))
        var calls = 0
        AppCoordinator.consumeScanRequest(from: d, now: now, gateSettled: true) { calls += 1 }
        #expect(calls == 0)
    }
}
