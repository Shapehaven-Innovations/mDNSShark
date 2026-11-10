import Testing
import Foundation
@testable import WidgetSnapshot

@Suite("Snapshot coding")
struct SnapshotCodingTests {
    static let brief = DeviceBrief(key: "aa:bb:cc:dd:ee:ff", name: "Living Room", ip: "192.168.1.34", typeLabel: "TV",
                                   symbol: "tv", status: "not probed", offNetwork: false, isGateway: false,
                                   firstSeen: Date(timeIntervalSince1970: 1_000_000.25))
    static let sample = WidgetSnapshot(version: 1, scannedAt: Date(timeIntervalSince1970: 1_000_500.5), subnet: "192.168.1.0/24",
        counts: StatusCounts(total: 14, secure: 9, warning: 2, critical: 1, notProbed: 2, pending: 0),
        typeCounts: ["TV": 1, "Router": 1], history: [], newDevices: [brief], topology: [brief], topologyOverflow: 0,
        ownDeviceKey: "ip:192.168.1.20")

    @Test("snapshot round trips exactly, fractional dates included")
    func roundTrip() throws {
        let data = try SnapshotCoding.encode(Self.sample)
        #expect(SnapshotCoding.decodeVersioned(WidgetSnapshot.self, from: data, supported: WidgetSnapshot.schemaVersion) == .loaded(Self.sample))
    }

    @Test("unknown keys are ignored")
    func unknownKeys() throws {
        var json = try JSONSerialization.jsonObject(with: SnapshotCoding.encode(Self.sample)) as! [String: Any]
        json["interfaces"] = ["future"]
        let data = try JSONSerialization.data(withJSONObject: json)
        #expect(SnapshotCoding.decodeVersioned(WidgetSnapshot.self, from: data, supported: 1) == .loaded(Self.sample))
    }

    @Test("a higher version is rejected with its number, even if the rest would not decode")
    func higherVersionRejected() {
        let data = Data(#"{"version": 2, "somethingNew": true}"#.utf8)
        #expect(SnapshotCoding.decodeVersioned(WidgetSnapshot.self, from: data, supported: 1) == .newer(version: 2))
    }

    @Test("garbage reads as missing")
    func garbageIsMissing() {
        #expect(SnapshotCoding.decodeVersioned(WidgetSnapshot.self, from: Data("nope".utf8), supported: 1) == .missing)
    }

    @Test("capture summary round trips")
    func captureRoundTrip() throws {
        let c = CaptureSummary(version: 1, updatedAt: Date(timeIntervalSince1970: 5.5), isCapturing: true, totalPackets: 1200,
                               inboundBytes: 2_100_000, outboundBytes: 640_000, protocolShare: ["HTTPS": 62.5, "DNS": 37.5],
                               packetsPerSecond: [1, 2, 3], findings: [CaptureFinding(severity: "warning", title: "Cleartext HTTP")])
        #expect(SnapshotCoding.decodeVersioned(CaptureSummary.self, from: try SnapshotCoding.encode(c), supported: 1) == .loaded(c))
    }

    @Test("device key is the lowercased MAC, else ip: plus the literal address")
    func deviceKey() {
        #expect(DeviceBrief.key(mac: "AA:BB:CC:DD:EE:FF", ip: "192.168.1.34") == "aa:bb:cc:dd:ee:ff")
        #expect(DeviceBrief.key(mac: nil, ip: "192.168.1.34") == "ip:192.168.1.34")
        #expect(DeviceBrief.key(mac: "", ip: "fe80::1%en0") == "ip:fe80::1%en0")
    }

    @Test("scan kinds are every kind but capture")
    func kinds() {
        #expect(WidgetKind.scanKinds == ["devices", "security", "newdevices", "scan", "mix", "topology"])
    }

    @Test("a snapshot with a Bluetooth summary round trips")
    func roundTripWithBluetooth() throws {
        var s = Self.sample
        s.bluetooth = BluetoothSummary(scannedAt: Date(timeIntervalSince1970: 1_000_400), nearby: 7)
        let data = try SnapshotCoding.encode(s)
        #expect(SnapshotCoding.decodeVersioned(WidgetSnapshot.self, from: data, supported: WidgetSnapshot.schemaVersion) == .loaded(s))
    }

    @Test("an old snapshot without the bluetooth key decodes with nil")
    func oldSnapshotWithoutBluetoothKeyDecodesNil() throws {
        let data = try SnapshotCoding.encode(Self.sample)
        let json = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        #expect(json["bluetooth"] == nil)
        guard case .loaded(let decoded) = SnapshotCoding.decodeVersioned(WidgetSnapshot.self, from: data, supported: 1) else {
            Issue.record("did not load")
            return
        }
        #expect(decoded.bluetooth == nil)
    }

    @Test("the schema version stays 1")
    func versionStaysOne() {
        #expect(WidgetSnapshot.schemaVersion == 1)
    }
}
