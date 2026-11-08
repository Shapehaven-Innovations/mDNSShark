import Testing
import Foundation
import DeviceFingerprint
@testable import mDNSShark

@MainActor @Suite("BLEDeviceStore") struct BLEDeviceStoreTests {
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    func tempURL() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("ble-\(UUID().uuidString)/saved.json")
    }

    func tempStore() -> BLEDeviceStore { BLEDeviceStore(fileURL: tempURL()) }

    func peripheral(name: String? = "Lamp", services: [String] = ["180F"]) -> BLEPeripheral {
        var parsed = BLEAdvertisementParser(companies: BLECompanyTable(text: "76\tApple, Inc."), services: BLEServiceNameTable(text: ""))
            .parse(BLEAdvertisementFields(localName: name, manufacturerData: Data([0x4C, 0x00, 0x01])))
        parsed.serviceUUIDs = services
        parsed.kind = .smartHome
        return BLEPeripheral(id: UUID(), identifiers: [UUID()], parsed: parsed,
                             fields: BLEAdvertisementFields(localName: name, manufacturerData: Data([0x4C, 0x00, 0x01])),
                             rssi: -55, rssiHistory: RSSIRingBuffer(), firstSeen: t0, lastSeen: t0,
                             markedStale: false, savedID: nil, deviceInfo: nil, readState: .idle)
    }

    @Test func addPersistsAndReloads() async throws {
        let url = tempURL()
        let store = BLEDeviceStore(fileURL: url)
        let saved = BLESavedDevice(peripheral: peripheral(), now: t0)
        try store.add(saved)
        let reloaded = BLEDeviceStore(fileURL: url)
        reloaded.load()
        #expect(reloaded.devices == [saved])
    }

    @Test func encodingHoldsNoIdentifierOrRawPayload() throws {
        let saved = BLESavedDevice(peripheral: peripheral(), now: t0)
        let json = String(data: try BLEDeviceStore.encode([saved]), encoding: .utf8)!
        #expect(!json.contains("identifier"))
        #expect(!json.contains("manufacturerData"))
        #expect(!json.contains("rssi"))
        #expect(!json.contains("serviceData"))
    }

    @Test func savedDeviceFromPeripheralCopiesStableFieldsOnly() {
        let p = peripheral()
        let saved = BLESavedDevice(peripheral: p, now: t0)
        #expect(saved.name == "Lamp")
        #expect(saved.companyID == 0x004C)
        #expect(saved.serviceUUIDs == ["180F"])
        #expect(saved.matterVendorID == nil)
        #expect(saved.matterProductID == nil)
        #expect(saved.matterDiscriminator == nil)
        #expect(saved.fastPairModelID == nil)
        #expect(saved.kind == .smartHome)
        #expect(saved.addedAt == t0)
        #expect(saved.lastSeenAt == t0)
        #expect(saved.notes == "")
    }

    @Test func mergeKeepsTargetIDAndUnionsServices() throws {
        let store = tempStore()
        var a = BLESavedDevice(peripheral: peripheral(services: ["180F"]), now: t0)
        var b = BLESavedDevice(peripheral: peripheral(services: ["1812"]), now: t0 + 10)
        a.notes = "first"
        b.notes = "second"
        try store.add(a)
        try store.add(b)
        try store.merge(a.id, into: b.id)
        #expect(store.devices.count == 1)
        let merged = store.devices[0]
        #expect(merged.id == b.id)
        #expect(merged.serviceUUIDs == ["180F", "1812"])
        #expect(merged.addedAt == t0)
        #expect(merged.lastSeenAt == t0 + 10)
        #expect(merged.notes == "second\nfirst")
    }

    @Test func removeUnknownIDIsNoOp() throws {
        let store = tempStore()
        try store.add(BLESavedDevice(peripheral: peripheral(), now: t0))
        try store.remove(id: UUID())
        #expect(store.devices.count == 1)
    }

    @Test func corruptFileLoadsEmpty() throws {
        let url = tempURL()
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("nope".utf8).write(to: url)
        let store = BLEDeviceStore(fileURL: url)
        store.load()
        #expect(store.devices.isEmpty)
    }

    func corruptCopies(beside url: URL) throws -> [URL] {
        try FileManager.default.contentsOfDirectory(at: url.deletingLastPathComponent(), includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasPrefix("saved.corrupt-") && $0.pathExtension == "json" }
    }

    @Test func unreadableFileIsMovedAsideBeforeAnyWrite() throws {
        let url = tempURL()
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("nope".utf8).write(to: url)
        let store = BLEDeviceStore(fileURL: url)
        store.load()
        #expect(!FileManager.default.fileExists(atPath: url.path))
        let copies = try corruptCopies(beside: url)
        try #require(copies.count == 1)
        #expect(try Data(contentsOf: copies[0]) == Data("nope".utf8))
        try store.add(BLESavedDevice(peripheral: peripheral(), now: t0))
        #expect(try Data(contentsOf: copies[0]) == Data("nope".utf8))
        #expect(store.devices.count == 1)
    }

    @Test func badElementIsSkippedAndOriginalKeptBeforeFirstWrite() throws {
        let url = tempURL()
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let good = BLESavedDevice(peripheral: peripheral(), now: t0)
        let goodJSON = String(data: try BLEDeviceStore.encode([good]), encoding: .utf8)!
        let text = goodJSON.replacingOccurrences(of: "\n]", with: ",\n  { \"id\": \"not-a-uuid\" }\n]")
        let original = Data(text.utf8)
        try original.write(to: url)
        let store = BLEDeviceStore(fileURL: url)
        store.load()
        #expect(store.devices == [good])
        #expect(try corruptCopies(beside: url).isEmpty)
        try store.add(BLESavedDevice(peripheral: peripheral(name: "Desk"), now: t0))
        let copies = try corruptCopies(beside: url)
        try #require(copies.count == 1)
        #expect(try Data(contentsOf: copies[0]) == original)
        #expect(store.devices.count == 2)
    }

    @Test func entryWithoutMatterDiscriminatorDecodes() throws {
        let json = """
        [{"addedAt":"2027-01-15T08:00:00Z","id":"\(UUID().uuidString)","kind":"smartHome","lastSeenAt":"2027-01-15T08:00:00Z",
          "matterProductID":2,"matterVendorID":1,"name":"Plug","notes":"","serviceUUIDs":[]}]
        """
        let devices = try BLEDeviceStore.decode(Data(json.utf8))
        #expect(devices.count == 1)
        #expect(devices[0].matterDiscriminator == nil)
        #expect(devices[0].fingerprint == BLEFingerprint(key: .name("Plug", companyID: nil)))
    }

    @Test func savedMatterFingerprintCarriesDiscriminator() {
        var p = peripheral()
        p.parsed.matter = MatterBLEAdvertisement(discriminator: 0x0ABC, vendorID: 1, productID: 2)
        let saved = BLESavedDevice(peripheral: p, now: t0)
        #expect(saved.matterDiscriminator == 0x0ABC)
        #expect(saved.fingerprint == p.fingerprint)
        #expect(saved.fingerprint == BLEFingerprint(key: .matter(vendorID: 1, productID: 2, discriminator: 0x0ABC)))
    }

    @Test func mergeTakesMatterIDsFromOneEntry() throws {
        let store = tempStore()
        var target = BLESavedDevice(peripheral: peripheral(), now: t0)
        var source = BLESavedDevice(peripheral: peripheral(name: "Other"), now: t0)
        target.matterVendorID = 1
        source.matterVendorID = 7
        source.matterProductID = 8
        source.matterDiscriminator = 9
        try store.add(target)
        try store.add(source)
        try store.merge(source.id, into: target.id)
        let merged = try #require(store.devices.first)
        #expect(merged.matterVendorID == 7 && merged.matterProductID == 8 && merged.matterDiscriminator == 9)

        var full = BLESavedDevice(peripheral: peripheral(), now: t0)
        full.matterVendorID = 1
        full.matterProductID = 2
        full.matterDiscriminator = 3
        var other = BLESavedDevice(peripheral: peripheral(name: "Other"), now: t0)
        other.matterVendorID = 4
        other.matterProductID = 5
        other.matterDiscriminator = 6
        try store.add(full)
        try store.add(other)
        try store.merge(other.id, into: full.id)
        let kept = try #require(store.devices.first { $0.id == full.id })
        #expect(kept.matterVendorID == 1 && kept.matterProductID == 2 && kept.matterDiscriminator == 3)
    }
}
