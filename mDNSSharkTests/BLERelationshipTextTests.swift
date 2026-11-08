import Testing
import Foundation
import DeviceFingerprint
@testable import mDNSShark

@Suite("Bluetooth relationship wording") struct BLERelationshipTextTests {
    let p = UUID(), d1 = UUID(), d2 = UUID()

    func table(_ s: [BLESuggestion] = [], _ t: [BLETie] = []) -> BLEMatchTable { BLEMatchTable(suggestions: s, ties: t) }

    @Test func noScanOmitsCard() {
        #expect(BLERelationshipText.forLANDevice(deviceID: d1, table: .empty, peripheralName: { _ in "" }, deviceName: { _ in "" }, scanRanThisSession: false) == nil)
    }

    @Test func noSuggestionAfterScan() {
        let lines = BLERelationshipText.forLANDevice(deviceID: d1, table: .empty, peripheralName: { _ in "" }, deviceName: { _ in "" }, scanRanThisSession: true)
        #expect(lines?.map(\.title) == ["No Bluetooth device suggested"])
    }

    @Test func strongAndPossibleWording() throws {
        let strong = BLESuggestion(peripheralID: p, deviceID: d1, tier: .strong, caption: "Inferred, not confirmed: Matter vendor and product IDs match.")
        let lines = try #require(BLERelationshipText.forLANDevice(deviceID: d1, table: table([strong]), peripheralName: { _ in "Nanoleaf A19" }, deviceName: { _ in "" }, scanRanThisSession: true))
        #expect(lines[0].title == "Suggested device: Nanoleaf A19" && lines[0].caption == "Inferred, not confirmed: Matter vendor and product IDs match.")
        #expect(lines[0].tier == .strong && lines[0].peripheralID == p && lines[0].deviceID == d1)

        let possible = BLESuggestion(peripheralID: p, deviceID: d1, tier: .possible, caption: "Inferred: similar name, same vendor.")
        let more = try #require(BLERelationshipText.forLANDevice(deviceID: d1, table: table([possible]), peripheralName: { _ in "Sonos Roam" }, deviceName: { _ in "" }, scanRanThisSession: true))
        #expect(more == [.init(title: "Possibly Sonos Roam?", caption: "Inferred: similar name, same vendor.", tier: .possible, peripheralID: p, deviceID: d1)])
    }

    @Test func tieWordingBothSides() throws {
        let t = table([], [.init(peripheralID: p, deviceIDs: [d1, d2].sorted { $0.uuidString < $1.uuidString }, tier: .possible)])
        let lan = try #require(BLERelationshipText.forLANDevice(deviceID: d1, table: t, peripheralName: { _ in "Roam" }, deviceName: { $0 == d2 ? "Sonos Roam (2)" : "Sonos Roam" }, scanRanThisSession: true))
        #expect(lan == [.init(title: "Could be Roam", caption: "Also fits Sonos Roam (2).", tier: .possible, peripheralID: p, deviceID: d1)])
        let ble = BLERelationshipText.forPeripheral(peripheralID: p, table: t, isSaved: false, deviceName: { _ in "Sonos Roam" }, deviceIP: { _ in nil })
        #expect(ble.title == "Could be Sonos Roam, also fits 1 other device")

        let d3 = UUID()
        let wide = table([], [.init(peripheralID: p, deviceIDs: [d1, d2, d3].sorted { $0.uuidString < $1.uuidString }, tier: .possible)])
        let lanWide = try #require(BLERelationshipText.forLANDevice(deviceID: d1, table: wide, peripheralName: { _ in "Roam" }, deviceName: { _ in "X" }, scanRanThisSession: true))
        #expect(lanWide.map(\.caption) == ["Also fits 2 other devices."])
        #expect(BLERelationshipText.forPeripheral(peripheralID: p, table: wide, isSaved: false, deviceName: { _ in "Sonos Roam" }, deviceIP: { _ in nil }).title
                == "Could be Sonos Roam, also fits 2 other devices")
    }

    @Test func peripheralSidePossibleWithIP() {
        let s = BLESuggestion(peripheralID: p, deviceID: d1, tier: .possible, caption: "Inferred: similar name, same vendor.")
        let line = BLERelationshipText.forPeripheral(peripheralID: p, table: table([s]), isSaved: false, deviceName: { _ in "Sonos Living Room" }, deviceIP: { _ in "192.168.1.42" })
        #expect(line == .init(title: "Possibly Sonos Living Room (192.168.1.42)?", caption: "Inferred: similar name, same vendor.", tier: .possible, peripheralID: p, deviceID: d1))
        let noIP = BLERelationshipText.forPeripheral(peripheralID: p, table: table([s]), isSaved: true, deviceName: { _ in "Sonos Living Room" }, deviceIP: { _ in nil })
        #expect(noIP.title == "Possibly Sonos Living Room?")
    }

    @Test func peripheralSideUnmatchedAndSaved() {
        let none = BLERelationshipText.forPeripheral(peripheralID: p, table: .empty, isSaved: false, deviceName: { _ in "" }, deviceIP: { _ in nil })
        #expect(none.title == "Not on network" && none.deviceID == nil)
        let saved = BLERelationshipText.forPeripheral(peripheralID: p, table: .empty, isSaved: true, deviceName: { _ in "" }, deviceIP: { _ in nil })
        #expect(saved.title == "Saved, Bluetooth only")
    }

    @Test func badgesAndForbiddenWords() throws {
        #expect(BLERelationshipText.badge(.strong) == "Strong, inferred" && BLERelationshipText.badge(.possible) == "Possible, inferred")
        let s = BLESuggestion(peripheralID: p, deviceID: d1, tier: .strong, caption: "Inferred, not confirmed: Matter vendor and product IDs match.")
        let tie = BLETie(peripheralID: UUID(), deviceIDs: [d1, d2].sorted { $0.uuidString < $1.uuidString }, tier: .possible)
        let lan = try #require(BLERelationshipText.forLANDevice(deviceID: d1, table: table([s], [tie]), peripheralName: { _ in "Lamp" }, deviceName: { _ in "Lamp 2" }, scanRanThisSession: true))
        let ble = [
            BLERelationshipText.forPeripheral(peripheralID: p, table: table([s]), isSaved: false, deviceName: { _ in "Lamp" }, deviceIP: { _ in "10.0.0.2" }),
            BLERelationshipText.forPeripheral(peripheralID: tie.peripheralID, table: table([], [tie]), isSaved: false, deviceName: { _ in "Lamp" }, deviceIP: { _ in nil }),
            BLERelationshipText.forPeripheral(peripheralID: UUID(), table: .empty, isSaved: false, deviceName: { _ in "" }, deviceIP: { _ in nil }),
            BLERelationshipText.forPeripheral(peripheralID: UUID(), table: .empty, isSaved: true, deviceName: { _ in "" }, deviceIP: { _ in nil }),
        ]
        let lines = lan + ble
        // "Inferred, not confirmed" is the app's guess label, so it is removed before the check.
        let captions = lines.compactMap(\.caption).map { $0.replacingOccurrences(of: "Inferred, not confirmed", with: "") }
        let fixed = [BLERelationshipText.heading, BLERelationshipText.noSuggestion, BLERelationshipText.notOnNetwork,
                     BLERelationshipText.savedBluetoothOnly, BLERelationshipText.savedNotSeen,
                     BLERelationshipText.badge(.strong), BLERelationshipText.badge(.possible)]
        let all = (lines.map(\.title) + captions + fixed).joined(separator: " ").lowercased()
        for w in ["matched", "linked", "confirmed", "paired", "mac address"] { #expect(!all.contains(w), "found \(w)") }
        #expect(lan.count == 2 && lan[1].title == "Could be Lamp")
    }

    @MainActor @Test func readConfirmationNamesTheDeviceAndTheTimeout() {
        let text = BLEPeripheralDetailView.readConfirmation(name: "Tile")
        #expect(text.contains("Tile") && text.contains("5 seconds"))
        #expect(text == "mDNSShark will connect to Tile once, read its Device Information and Battery services, and disconnect within 5 seconds. Nothing is written to the device.")
    }
}
