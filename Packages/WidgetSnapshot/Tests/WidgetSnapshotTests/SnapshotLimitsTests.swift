import Testing
import Foundation
@testable import WidgetSnapshot

@Suite("Snapshot limits")
struct SnapshotLimitsTests {
    @Test("ring keeps the newest 12, newest last")
    func ringKeeps12() {
        var h: [ScanSample] = []
        for i in 0..<15 { h = WidgetSnapshot.appending(ScanSample(at: Date(timeIntervalSince1970: Double(i)), counts: .zero), to: h) }
        #expect(h.count == 12)
        #expect(h.first?.at == Date(timeIntervalSince1970: 3))
        #expect(h.last?.at == Date(timeIntervalSince1970: 14))
    }

    @Test("seen map keeps the first sighting and stamps new keys with now")
    func seenKeepsFirst() {
        let old = Date(timeIntervalSince1970: 10), now = Date(timeIntervalSince1970: 99)
        let out = SeenMap.updated(["a": old], present: ["a", "b"], now: now)
        #expect(out == ["a": old, "b": now])
    }

    @Test("seen map evicts at 512, oldest first")
    func evictsAt512() {
        var seen: [String: Date] = [:]
        for i in 0..<512 { seen["k\(i)"] = Date(timeIntervalSince1970: Double(i)) }
        let out = SeenMap.updated(seen, present: ["new"], now: Date(timeIntervalSince1970: 10_000))
        #expect(out.count == 512)
        #expect(out["k0"] == nil)
        #expect(out["new"] != nil)
    }

    @Test("absent keys are evicted before present ones, so the router never comes back as new")
    func evictsAbsentKeysFirst() {
        var seen: [String: Date] = ["router": Date(timeIntervalSince1970: 0)]
        for i in 1..<512 { seen["k\(i)"] = Date(timeIntervalSince1970: Double(i)) }
        let out = SeenMap.updated(seen, present: ["router", "new"], now: Date(timeIntervalSince1970: 10_000))
        #expect(out["router"] == Date(timeIntervalSince1970: 0))
        #expect(out["k1"] == nil)
        #expect(out.count == 512)
    }

    static func big() -> WidgetSnapshot {
        let long = String(repeating: "h", count: 2000)
        let briefs = (0..<12).map { i in
            DeviceBrief(key: "k\(i)", name: long, ip: "192.168.1.\(i)", typeLabel: "TV", symbol: "tv", status: "not probed",
                        offNetwork: false, isGateway: false, firstSeen: Date(timeIntervalSince1970: Double(i)))
        }
        let history = (0..<12).map { ScanSample(at: Date(timeIntervalSince1970: Double($0)), counts: .zero) }
        return WidgetSnapshot(version: 1, scannedAt: Date(timeIntervalSince1970: 100), subnet: nil, counts: .zero,
                              typeCounts: [:], history: history, newDevices: Array(briefs.prefix(6)), topology: briefs,
                              topologyOverflow: 0, ownDeviceKey: nil)
    }

    static func size(_ s: WidgetSnapshot) -> Int { (try? SnapshotCoding.encode(s).count) ?? 0 }

    @Test("trimmedToFit drops topology, then new devices, then the oldest history")
    func trimOrder() {
        let s = Self.big()

        var a = s
        a.topology = Array(s.topology.prefix(8))
        a.topologyOverflow = 4
        let outA = s.trimmedToFit(maxBytes: Self.size(a))
        #expect(outA.newDevices.count == 6)
        #expect(outA.history.count == 12)
        #expect(outA.topology.count < 12)
        #expect(outA.topologyOverflow == 12 - outA.topology.count)

        var b = s
        b.topology = []
        b.topologyOverflow = 12
        b.newDevices = Array(s.newDevices.prefix(3))
        let outB = s.trimmedToFit(maxBytes: Self.size(b))
        #expect(outB.topology.isEmpty)
        #expect(outB.newDevices.count < 6)
        #expect(outB.history.count == 12)

        var c = s
        c.topology = []
        c.topologyOverflow = 12
        c.newDevices = []
        c.history = Array(s.history.suffix(7))
        let outC = s.trimmedToFit(maxBytes: Self.size(c))
        #expect(outC.topology.isEmpty)
        #expect(outC.newDevices.isEmpty)
        #expect(outC.history.count < 12)
        #expect(outC.history.last == s.history.last)

        let small = SnapshotCodingTests.sample
        #expect(small.trimmedToFit() == small)
    }

    @Test("trimmedToFit never drops the Bluetooth summary")
    func trimmedToFitKeepsBluetooth() {
        var s = Self.big()
        let summary = BluetoothSummary(scannedAt: Date(timeIntervalSince1970: 90), nearby: 4, suggested: 1)
        s.bluetooth = summary
        let out = s.trimmedToFit(maxBytes: 200)
        #expect(out.bluetooth == summary)
        #expect(out.topology.isEmpty)
        #expect(out.newDevices.isEmpty)
        #expect(out.history.isEmpty)
    }
}
