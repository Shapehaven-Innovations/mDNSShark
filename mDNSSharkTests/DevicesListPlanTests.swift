import Testing
import Foundation
import DeviceFingerprint
@testable import mDNSShark

@Suite("Devices list plan") struct DevicesListPlanTests {
    let now = Date(timeIntervalSince1970: 1_800_000_000)

    func lan(_ name: String) -> DiscoveredDevice { DiscoveredDevice(hostname: name, ipAddress: "192.168.1.\(Int.random(in: 2...250))") }

    func peripheral(_ name: String, savedID: UUID? = nil, lastSeen: Date? = nil) -> BLEPeripheral {
        let fields = BLEAdvertisementFields(localName: name, manufacturerData: Data([0x4C, 0x00, 0x01]))
        let parsed = BLEAdvertisementParser(companies: BLECompanyTable(text: "76\tApple, Inc."), services: BLEServiceNameTable(text: ""))
            .parse(fields)
        let seen = lastSeen ?? now
        return BLEPeripheral(id: UUID(), identifiers: [UUID()], parsed: parsed, fields: fields, rssi: -55,
                             rssiHistory: RSSIRingBuffer(), firstSeen: seen, lastSeen: seen,
                             markedStale: false, savedID: savedID, deviceInfo: nil, readState: .idle)
    }

    func saved(_ name: String) -> BLESavedDevice { BLESavedDevice(peripheral: peripheral(name), now: now) }

    /// d1, d2 on the LAN; p1 suggested for d1; p2 unmatched; p3 a tie between d1 and d2; s1 saved with no live row.
    struct Fixture {
        var d1: DiscoveredDevice, d2: DiscoveredDevice
        var p1: BLEPeripheral, p2: BLEPeripheral, p3: BLEPeripheral
        var s1: BLESavedDevice
        var table: BLEMatchTable
    }

    func fixture() -> Fixture {
        let d1 = lan("tv"), d2 = lan("speaker")
        let p1 = peripheral("TV"), p2 = peripheral("Watch"), p3 = peripheral("Roam")
        let table = BLEMatchTable(
            suggestions: [BLESuggestion(peripheralID: p1.id, deviceID: d1.id, tier: .strong, caption: "Inferred, not confirmed: same name, same vendor.")],
            ties: [BLETie(peripheralID: p3.id, deviceIDs: [d1.id, d2.id], tier: .possible)])
        return Fixture(d1: d1, d2: d2, p1: p1, p2: p2, p3: p3, s1: saved("Old lamp"), table: table)
    }

    func plan(_ filter: DevicesFilter, _ f: Fixture, peripherals: [BLEPeripheral]? = nil, saved: [BLESavedDevice]? = nil,
              table: BLEMatchTable? = nil) -> DevicesListPlan {
        DevicesListPlan.make(filter: filter, devices: [f.d1, f.d2], peripherals: peripherals ?? [f.p1, f.p2, f.p3],
                             saved: saved ?? [f.s1], matches: table ?? f.table, now: now)
    }

    @Test func allAttachesSuggestedAndListsTheRest() {
        let f = fixture()
        let p = plan(.all, f)
        #expect(p.sections.count == 1 && p.sections[0].title == "")
        #expect(p.sections.flatMap(\.rows) == [.lan(f.d1, bluetoothSuggested: true), .lan(f.d2, bluetoothSuggested: false),
                                               .peripheral(f.p2), .peripheral(f.p3), .saved(f.s1)])
        #expect(!p.sections.flatMap(\.rows).contains(.peripheral(f.p1)))
        #expect(!p.isEmpty)
    }

    @Test func lanFilterKeepsFlagOnly() {
        let f = fixture()
        #expect(plan(.lan, f).sections.flatMap(\.rows) == [.lan(f.d1, bluetoothSuggested: true), .lan(f.d2, bluetoothSuggested: false)])
    }

    @Test func bluetoothSectionsAndTitles() {
        let f = fixture()
        var s4 = saved("Desk lamp")
        s4.id = UUID()
        let p4 = peripheral("Desk lamp", savedID: s4.id)
        let p = plan(.bluetooth, f, peripherals: [f.p1, f.p2, f.p3, p4], saved: [f.s1, s4])
        #expect(p.sections.map(\.title) == ["Suggested on your network", "Not on network", "Saved"])
        #expect(p.sections[0].rows == [.peripheral(f.p1)])
        #expect(p.sections[1].rows == [.peripheral(f.p2), .peripheral(f.p3)])
        #expect(p.sections[2].rows == [.peripheral(p4), .saved(f.s1)])
    }

    @Test func emptySuggestedSectionIsOmitted() {
        let f = fixture()
        #expect(plan(.bluetooth, f, table: .empty).sections.map(\.title) == ["Not on network", "Saved"])
    }

    @Test func expiredPeripheralsAreHidden() {
        let f = fixture()
        let old = peripheral("Gone", lastSeen: now.addingTimeInterval(-121))
        for filter in DevicesFilter.allCases {
            let rows = plan(filter, f, peripherals: [f.p1, f.p2, f.p3, old]).sections.flatMap(\.rows)
            #expect(!rows.contains(.peripheral(old)), "\(filter)")
        }
    }

    @Test func savedLiveRowIsNotDuplicated() {
        let f = fixture()
        let p4 = peripheral("Old lamp", savedID: f.s1.id)
        let rows = plan(.all, f, peripherals: [f.p1, f.p2, f.p3, p4]).sections.flatMap(\.rows)
        #expect(rows.filter { $0 == .peripheral(p4) }.count == 1)
        #expect(!rows.contains(.saved(f.s1)))
    }

    /// Every kind of row at once: suggested, suggested and saved, tied, unsuggested, saved and live, saved only,
    /// and a saved row that has expired.
    @Test func noDuplicatesForEveryFilter() {
        let f = fixture()
        var s4 = saved("Desk lamp"); s4.id = UUID()
        var s5 = saved("Garage"); s5.id = UUID()
        var s6 = saved("Speaker"); s6.id = UUID()
        let p4 = peripheral("Desk lamp", savedID: s4.id)
        let p5 = peripheral("Garage", savedID: s5.id, lastSeen: now.addingTimeInterval(-400))
        let p6 = peripheral("Speaker", savedID: s6.id)
        let table = BLEMatchTable(
            suggestions: f.table.suggestions + [BLESuggestion(peripheralID: p6.id, deviceID: f.d2.id, tier: .possible, caption: "Inferred: similar name, same vendor.")],
            ties: f.table.ties)
        let peripherals = [f.p1, f.p2, f.p3, p4, p5, p6]
        let savedEntries = [f.s1, s4, s5, s6]
        let nearby = BluetoothViewModel.nearbyCount(peripherals: peripherals, now: now)
        #expect(nearby == 5)

        for filter in DevicesFilter.allCases {
            let rows = plan(filter, f, peripherals: peripherals, saved: savedEntries, table: table).sections.flatMap(\.rows)
            // (a) Row ids are unique.
            #expect(Set(rows.map(\.id)).count == rows.count, "\(filter)")
            // (b) A saved entry is never drawn beside its live row.
            for case .saved(let entry) in rows {
                #expect(!rows.contains { if case .peripheral(let p) = $0 { return p.savedID == entry.id } else { return false } }, "\(filter)")
            }
            // (d) The tied peripheral appears at most once, and exactly once wherever peripherals are listed.
            let tied = rows.filter { $0 == .peripheral(f.p3) }.count
            #expect(tied == (filter == .lan ? 0 : 1), "\(filter)")
            let peripheralRows = rows.filter { if case .peripheral = $0 { return true } else { return false } }
            switch filter {
            case .all:
                // (c) A suggested peripheral is a line on its LAN row, never an extra row.
                #expect(!peripheralRows.contains { if case .peripheral(let p) = $0 { return table.suggestedPeripheralIDs.contains(p.id) } else { return false } })
                #expect(rows.filter { if case .lan = $0 { return true } else { return false } }.count == 2)
            case .bluetooth:
                // (e) Every non-expired peripheral is listed exactly once, matching the header count.
                #expect(peripheralRows.count == nearby)
                #expect(Set(peripheralRows.map(\.id)).count == nearby)
            case .lan:
                #expect(peripheralRows.isEmpty)
            }
        }
    }

    @Test func expiredSavedRowShowsOnceAsSaved() {
        let f = fixture()
        var s5 = saved("Garage"); s5.id = UUID()
        let p5 = peripheral("Garage", savedID: s5.id, lastSeen: now.addingTimeInterval(-400))
        for filter in [DevicesFilter.all, .bluetooth] {
            let rows = plan(filter, f, peripherals: [f.p1, p5], saved: [s5]).sections.flatMap(\.rows)
            #expect(rows.filter { $0 == .saved(s5) }.count == 1, "\(filter)")
            #expect(!rows.contains(.peripheral(p5)), "\(filter)")
        }
    }

    @Test func accessStateTable() {
        #expect(BluetoothAccessState.from(authorization: .denied, power: .poweredOn) == .denied)
        #expect(BluetoothAccessState.from(authorization: .allowed, power: .unsupported) == .unsupported)
        #expect(BluetoothAccessState.from(authorization: .allowed, power: .poweredOff) == .poweredOff)
        #expect(BluetoothAccessState.from(authorization: .undetermined, power: .unknown) == .undetermined)
        #expect(BluetoothAccessState.from(authorization: .allowed, power: .poweredOn) == .ready)
        #expect(BluetoothAccessState.from(authorization: .restricted, power: .unknown) == .restricted)
    }
}

@Suite("Bluetooth access view") struct BluetoothAccessViewTests {
    @Test func wordingAndSettingsButton() {
        #expect(BluetoothAccessView.undeterminedTitle == "Nearby Bluetooth is not set up")
        #expect(BluetoothAccessView.poweredOffText == "Turn on Bluetooth in Control Center.")
        #expect(BluetoothAccessView.undeterminedNote == "Nothing connects to your devices. Your phone only listens.")
        #expect(BluetoothAccessView.showsOpenSettings(.denied))
        for state in [BluetoothAccessState.poweredOff, .restricted, .unsupported, .undetermined, .ready] {
            #expect(!BluetoothAccessView.showsOpenSettings(state), "\(state)")
        }
    }

    @Test func detailAddOnlyWhenNotOnNetwork() {
        #expect(BLEPeripheralDetailView.showsAdd(isLive: true, savedID: nil, relationshipTitle: BLERelationshipText.notOnNetwork))
        #expect(!BLEPeripheralDetailView.showsAdd(isLive: true, savedID: nil, relationshipTitle: "Could be TV, also fits 1 other device"))
        #expect(!BLEPeripheralDetailView.showsAdd(isLive: true, savedID: nil, relationshipTitle: "Possibly TV?"))
        #expect(!BLEPeripheralDetailView.showsAdd(isLive: false, savedID: nil, relationshipTitle: BLERelationshipText.notOnNetwork))
        #expect(!BLEPeripheralDetailView.showsAdd(isLive: true, savedID: UUID(), relationshipTitle: BLERelationshipText.notOnNetwork))
    }
}
