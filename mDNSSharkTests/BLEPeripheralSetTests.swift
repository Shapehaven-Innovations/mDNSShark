import Testing
import Foundation
import DeviceFingerprint
@testable import mDNSShark

@Suite("BLEPeripheralSet coalescing and lifecycle")
struct BLEPeripheralSetTests {
    let parser = BLEAdvertisementParser(companies: BLECompanyTable(text: "76\tApple, Inc."), services: BLEServiceNameTable(text: ""))
    let t0 = Date(timeIntervalSince1970: 1_800_000_000)

    func fields(name: String? = nil, company: UInt16? = 0x004C, serviceData: [String: Data] = [:]) -> BLEAdvertisementFields {
        let mfg = company.map { Data([UInt8($0 & 0xFF), UInt8($0 >> 8), 0x01]) }
        return BLEAdvertisementFields(localName: name, manufacturerData: mfg, serviceData: serviceData)
    }

    func sighting(_ id: UUID, name: String? = nil, company: UInt16? = 0x004C, rssi: Int = -60, at: Date? = nil, serviceData: [String: Data] = [:]) -> BLESighting {
        BLESighting(identifier: id, fields: fields(name: name, company: company, serviceData: serviceData), rssi: rssi, at: at ?? t0)
    }

    @discardableResult
    func ingest(_ set: inout BLEPeripheralSet, _ s: BLESighting) -> UUID {
        set.ingest(s, parsed: parser.parse(s.fields)).rowID
    }

    @Test func twoUnnamedSameVendorStaySeparate() {
        var set = BLEPeripheralSet()
        ingest(&set, sighting(UUID()))
        ingest(&set, sighting(UUID()))
        #expect(set.peripherals.count == 2)
    }

    @Test func fingerprintIsNilWithoutNameOrStableID() {
        #expect(BLEFingerprint(parsed: parser.parse(BLEAdvertisementFields(manufacturerData: Data([0x4C, 0x00, 0x01])))) == nil)
    }

    @Test func sameIdentifierUpdatesRow() {
        var set = BLEPeripheralSet()
        let id = UUID()
        ingest(&set, sighting(id, rssi: -60))
        ingest(&set, sighting(id, rssi: -70, at: t0 + 5))
        #expect(set.peripherals.count == 1)
        #expect(set.peripherals[0].rssi == -70)
        #expect(set.peripherals[0].rssiHistory.samples == [-60, -70])
        #expect(set.peripherals[0].identifiers.count == 1)
    }

    @Test func rotatedIdentifierWithUniqueNameCoalesces() {
        var set = BLEPeripheralSet()
        ingest(&set, sighting(UUID(), name: "Sonos Roam"))
        ingest(&set, sighting(UUID(), name: "Sonos Roam", at: t0 + 30))
        #expect(set.peripherals.count == 1)
        #expect(set.peripherals[0].identifiers.count == 2)
        #expect(set.peripherals[0].firstSeen == t0)
        #expect(set.peripherals[0].lastSeen == t0 + 30)
    }

    @Test func ambiguousNameDoesNotCoalesce() {
        var set = BLEPeripheralSet()
        let a = UUID(), b = UUID()
        ingest(&set, sighting(a, name: "Foo"))
        ingest(&set, sighting(b, name: "Bar"))
        ingest(&set, sighting(b, name: "Foo"))
        #expect(set.peripherals.count == 2)
        ingest(&set, sighting(UUID(), name: "Unnamed Speaker"))
        ingest(&set, sighting(UUID(), name: "Foo"))
        #expect(set.peripherals.count == 4)
    }

    @Test func matterIDCoalescesEvenWithoutName() {
        var set = BLEPeripheralSet()
        let matter = ["FFF6": Data([0x00, 0x01, 0x00, 0x34, 0x12, 0x78, 0x56, 0x00])]
        ingest(&set, sighting(UUID(), company: nil, serviceData: matter))
        ingest(&set, sighting(UUID(), company: nil, serviceData: matter))
        #expect(set.peripherals.count == 1)
        #expect(set.peripherals[0].identifiers.count == 2)
    }

    // MARK: No duplicates: rotation coalesces, simultaneous advertisers split

    func matterData(discriminator: UInt8) -> [String: Data] {
        ["FFF6": Data([0x00, discriminator, 0x00, 0x34, 0x12, 0x78, 0x56, 0x00])]
    }

    @Test func rotationAtSameInstantIsOneRow() {
        var set = BLEPeripheralSet()
        let a = UUID(), b = UUID()
        ingest(&set, sighting(a, name: "Roam", at: t0))
        ingest(&set, sighting(b, name: "Roam", at: t0))
        for i in 1...10 { ingest(&set, sighting(b, name: "Roam", at: t0 + Double(i))) }
        #expect(set.peripherals.count == 1)
        #expect(set.peripherals[0].identifiers == [a, b])
        #expect(set.peripherals[0].firstSeen == t0)
    }

    @Test func interleavedSameNameDevicesStayTwoRows() {
        var set = BLEPeripheralSet()
        let a = UUID(), b = UUID()
        ingest(&set, sighting(a, name: "Roam", at: t0))
        ingest(&set, sighting(b, name: "Roam", at: t0))
        let split = set.ingest(sighting(a, name: "Roam", at: t0 + 3), parsed: parser.parse(fields(name: "Roam")))
        #expect(split.splitOff?.identifier == b)
        ingest(&set, sighting(b, name: "Roam", at: t0 + 3.5))
        #expect(set.peripherals.count == 2)
        for i in 0..<20 {
            ingest(&set, sighting(i.isMultiple(of: 2) ? a : b, name: "Roam", at: t0 + 4 + Double(i) * 0.5))
            #expect(set.peripherals.count == 2)
        }
        #expect(Set(set.peripherals.map(\.identifiers)) == [[a], [b]])
        #expect(set.reconcileQuietRows(now: t0 + 20).isEmpty)
        #expect(set.peripherals.count == 2)
    }

    @Test func stragglerWithinGraceStaysOneRow() {
        var set = BLEPeripheralSet()
        let a = UUID(), b = UUID()
        ingest(&set, sighting(a, name: "Roam", at: t0))
        ingest(&set, sighting(b, name: "Roam", at: t0 + 30))
        ingest(&set, sighting(a, name: "Roam", at: t0 + 31))
        ingest(&set, sighting(b, name: "Roam", at: t0 + 35))
        #expect(set.peripherals.count == 1)
        #expect(set.peripherals[0].identifiers == [a, b])
    }

    @Test func namelessFirstReportThenNamedIsAbsorbed() {
        var set = BLEPeripheralSet()
        let a = UUID(), b = UUID()
        let original = ingest(&set, sighting(a, name: "Lamp", at: t0))
        ingest(&set, sighting(b, at: t0 + 30))
        #expect(set.peripherals.count == 2)
        let result = set.ingest(sighting(b, name: "Lamp", at: t0 + 30.5), parsed: parser.parse(fields(name: "Lamp")))
        #expect(result.rowID == original)
        #expect(result.absorbed != nil && result.absorbed != original)
        #expect(set.peripherals.count == 1)
        #expect(set.peripherals[0].id == original)
        #expect(set.peripherals[0].firstSeen == t0)
        #expect(set.peripherals[0].identifiers == [a, b])
        #expect(set.peripherals[0].lastSeen == t0 + 30.5)
    }

    @Test func absorbKeepsADonorReadRunning() {
        var set = BLEPeripheralSet()
        let b = UUID()
        let original = ingest(&set, sighting(UUID(), name: "Lamp", at: t0))
        let donor = ingest(&set, sighting(b, at: t0 + 30))
        set.update(donor) { $0.readState = .reading }
        ingest(&set, sighting(b, name: "Lamp", at: t0 + 30.5))
        #expect(set.peripherals.count == 1)
        #expect(set.peripherals.first { $0.id == original }?.readState == .reading)
    }

    @Test func rotateWhileSavedKeepsSavedIDOnOneRow() {
        for nameless in [false, true] {
            var set = BLEPeripheralSet()
            let savedID = UUID()
            let row = ingest(&set, sighting(UUID(), name: "Lamp", at: t0))
            set.setSavedID(savedID, for: row)
            let b = UUID()
            if nameless { ingest(&set, sighting(b, at: t0 + 40)) }
            ingest(&set, sighting(b, name: "Lamp", at: t0 + 41))
            ingest(&set, sighting(b, name: "Lamp", at: t0 + 45))
            #expect(set.peripherals.count == 1, "nameless \(nameless)")
            #expect(set.peripherals.filter { $0.savedID == savedID }.count == 1, "nameless \(nameless)")
            #expect(set.peripherals[0].id == row)
        }
    }

    @Test func quietRowAbsorbsSuccessorBornAfterIt() {
        var set = BLEPeripheralSet()
        let a = UUID(), b = UUID(), c = UUID(), savedID = UUID()
        let rowA = ingest(&set, sighting(a, name: "Roam", at: t0))
        ingest(&set, sighting(b, name: "Roam", at: t0))
        ingest(&set, sighting(a, name: "Roam", at: t0 + 3))
        set.setSavedID(savedID, for: rowA)
        #expect(set.peripherals.count == 2)
        // A rotates to C while B keeps advertising: two rows share the name, so C cannot be placed yet.
        let rowC = ingest(&set, sighting(c, name: "Roam", at: t0 + 3.2))
        #expect(set.peripherals.count == 3)
        for i in 0...12 {
            ingest(&set, sighting(b, name: "Roam", at: t0 + 4 + Double(i)))
            ingest(&set, sighting(c, name: "Roam", at: t0 + 4.5 + Double(i)))
        }
        #expect(set.reconcileQuietRows(now: t0 + 12).isEmpty)
        #expect(set.peripherals.count == 3)
        let folded = set.reconcileQuietRows(now: t0 + 16.6)
        #expect(folded == [rowC: rowA])
        #expect(set.peripherals.count == 2)
        let survivor = set.peripherals.first { $0.id == rowA }
        #expect(survivor?.savedID == savedID)
        #expect(survivor?.identifiers == [a, c])
        #expect(survivor?.firstSeen == t0)
        #expect(survivor?.lastSeen == t0 + 16.5)
    }

    @Test func quietRowNeverFoldsARowBornBeforeItWentSilent() {
        var set = BLEPeripheralSet()
        let a = UUID(), b = UUID()
        ingest(&set, sighting(a, name: "Roam", at: t0))
        ingest(&set, sighting(b, name: "Roam", at: t0))
        ingest(&set, sighting(a, name: "Roam", at: t0 + 3))
        for i in 0...20 { ingest(&set, sighting(b, name: "Roam", at: t0 + 4 + Double(i))) }
        #expect(set.reconcileQuietRows(now: t0 + 25).isEmpty)
        #expect(set.peripherals.count == 2)
    }

    @Test func nameIsKeptWhenALaterSightingHasNone() {
        var set = BLEPeripheralSet()
        let a = UUID()
        ingest(&set, sighting(a, name: "Lamp", at: t0))
        ingest(&set, sighting(a, at: t0 + 1))
        #expect(set.peripherals.count == 1)
        #expect(set.peripherals[0].displayName == "Lamp")
        #expect(set.peripherals[0].fields.localName == "Lamp")
        #expect(set.peripherals[0].fingerprint == BLEFingerprint(key: .name("Lamp", companyID: 0x004C)))
    }

    @Test func matterSameIDsDifferentDiscriminatorStayTwoRows() {
        var set = BLEPeripheralSet()
        ingest(&set, sighting(UUID(), company: nil, serviceData: matterData(discriminator: 0x01)))
        ingest(&set, sighting(UUID(), company: nil, serviceData: matterData(discriminator: 0x02)))
        #expect(set.peripherals.count == 2)
    }

    // MARK: Sticky fingerprint

    let fastPairModel = ["FE2C": Data([0x2A, 0x41, 0x0B])]
    /// An account-key frame: not 3 bytes, so it carries no model ID.
    let fastPairAccountKey = ["FE2C": Data([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])]

    @Test func accountKeyFrameDoesNotMoveARowsFingerprint() {
        var set = BLEPeripheralSet()
        let a = UUID(), b = UUID(), savedID = UUID()
        let rowA = ingest(&set, sighting(a, company: nil, at: t0, serviceData: fastPairModel))
        ingest(&set, sighting(b, company: nil, at: t0, serviceData: fastPairModel))
        ingest(&set, sighting(a, company: nil, at: t0 + 3, serviceData: fastPairModel))
        set.setSavedID(savedID, for: rowA)
        #expect(set.peripherals.count == 2)
        let fingerprint = set.peripherals.first { $0.id == rowA }?.fingerprint
        ingest(&set, sighting(a, company: nil, at: t0 + 4, serviceData: fastPairAccountKey))
        #expect(set.peripherals.first { $0.id == rowA }?.fingerprint == fingerprint)
        ingest(&set, sighting(b, company: nil, at: t0 + 4.5, serviceData: fastPairModel))
        ingest(&set, sighting(a, company: nil, at: t0 + 5, serviceData: fastPairModel))
        #expect(set.peripherals.count == 2)
        #expect(set.peripherals.first { $0.id == rowA }?.savedID == savedID)
        #expect(set.peripherals.filter { $0.savedID == savedID }.count == 1)
    }

    @Test func rotationCoalescesWhenOnlyTheEarlierFramesCarriedTheModel() {
        var set = BLEPeripheralSet()
        let a = UUID(), b = UUID()
        ingest(&set, sighting(a, company: nil, at: t0, serviceData: fastPairModel))
        ingest(&set, sighting(a, company: nil, at: t0 + 1, serviceData: fastPairAccountKey))
        ingest(&set, sighting(b, company: nil, at: t0 + 30, serviceData: fastPairModel))
        #expect(set.peripherals.count == 1)
        #expect(set.peripherals[0].identifiers == [a, b])
    }

    @Test func manufacturerDataInSomeFramesKeepsOneFingerprint() {
        var set = BLEPeripheralSet()
        let a = UUID()
        ingest(&set, sighting(a, name: "Lamp", at: t0))
        let fingerprint = set.peripherals[0].fingerprint
        ingest(&set, sighting(a, name: "Lamp", company: nil, at: t0 + 1))
        #expect(set.peripherals[0].fingerprint == fingerprint)
        #expect(set.peripherals[0].parsed.companyName == "Apple, Inc.")
        ingest(&set, sighting(UUID(), name: "Lamp", at: t0 + 30))
        #expect(set.peripherals.count == 1)
    }

    /// A small seeded generator so the property tests are repeatable.
    struct LCG {
        var state: UInt64
        mutating func next(_ range: ClosedRange<Double>) -> Double {
            state = state &* 6364136223846793005 &+ 1442695040888963407
            let unit = Double(state >> 11) / Double(1 << 53)
            return range.lowerBound + unit * (range.upperBound - range.lowerBound)
        }
    }

    @Test func propertySimultaneousSameNameAdvertisersAreTwoRows() {
        for seed in UInt64(1)...40 {
            var rng = LCG(state: seed)
            var set = BLEPeripheralSet()
            let a = UUID(), b = UUID()
            var nextA = t0 + rng.next(0...1), nextB = t0 + rng.next(0...1)
            let end = t0 + 40
            while min(nextA, nextB) < end {
                if nextA <= nextB {
                    ingest(&set, sighting(a, name: "Roam", at: nextA))
                    nextA += rng.next(0.1...1.5)
                } else {
                    ingest(&set, sighting(b, name: "Roam", at: nextB))
                    nextB += rng.next(0.1...1.5)
                }
                _ = set.reconcileQuietRows(now: min(nextA, nextB))
            }
            #expect(set.peripherals.count == 2, "seed \(seed)")
            #expect(Set(set.peripherals.map(\.identifiers)) == [[a], [b]], "seed \(seed)")
        }
    }

    @Test func propertyRotationIsOneRow() {
        for seed in UInt64(1)...40 {
            var rng = LCG(state: seed)
            var set = BLEPeripheralSet()
            let savedID = UUID()
            var identifier = UUID()
            var at = t0
            var rotateAt = t0 + rng.next(5...60)
            var all: Set<UUID> = [identifier]
            let first = ingest(&set, sighting(identifier, name: "Roam", at: at))
            set.setSavedID(savedID, for: first)
            var lastNamed = true
            while at < t0 + 300 {
                at += rng.next(0.1...1.5)
                if at >= rotateAt {
                    identifier = UUID()
                    all.insert(identifier)
                    // Some rotations leave a short silence; some switch at once.
                    at += rng.next(0...1) < 0.5 ? 0 : rng.next(0...20)
                    rotateAt = at + rng.next(5...60)
                }
                // An advertisement without its scan response has no name; the next one carries it.
                let named = !lastNamed || rng.next(0...1) >= 0.2
                lastNamed = named
                ingest(&set, sighting(identifier, name: named ? "Roam" : nil, at: at))
                _ = set.reconcileQuietRows(now: at)
                if named { #expect(set.peripherals.count == 1, "seed \(seed)") }
            }
            // The loop can end on a nameless first report; the named one that follows completes the row.
            ingest(&set, sighting(identifier, name: "Roam", at: at + 0.5))
            #expect(set.peripherals.count == 1, "seed \(seed)")
            #expect(set.peripherals.first?.identifiers == all, "seed \(seed)")
            #expect(set.peripherals.first?.savedID == savedID, "seed \(seed)")
        }
    }

    @Test func lifecycleThresholds() {
        #expect(BLELifecycle.of(lastSeen: t0, now: t0 + 59, markedStale: false) == .live)
        #expect(BLELifecycle.of(lastSeen: t0, now: t0 + 60, markedStale: false) == .dim)
        #expect(BLELifecycle.of(lastSeen: t0, now: t0 + 119, markedStale: false) == .dim)
        #expect(BLELifecycle.of(lastSeen: t0, now: t0 + 120, markedStale: false) == .expired)
        #expect(BLELifecycle.of(lastSeen: t0, now: t0, markedStale: true) == .dim)
    }

    @Test func pruneKeepsSavedRows() {
        var set = BLEPeripheralSet()
        let keep = ingest(&set, sighting(UUID()))
        let drop = ingest(&set, sighting(UUID()))
        set.setSavedID(UUID(), for: keep)
        let removed = set.pruneExpired(now: t0 + 400)
        #expect(removed == [drop])
        #expect(set.peripherals.count == 1)
        #expect(set.peripherals[0].id == keep)
    }

    @Test func shiftAgingPausesAgingAndKeepsLastSeen() {
        var set = BLEPeripheralSet()
        ingest(&set, sighting(UUID()))
        set.shiftAging(by: 100)
        #expect(set.peripherals[0].lifecycle(now: t0 + 150) == .live)
        #expect(set.peripherals[0].lastSeen == t0)
    }

    @Test func ringBufferCapsAt32() {
        var ring = RSSIRingBuffer()
        for i in 0..<40 { ring.append(i) }
        #expect(ring.samples.count == 32)
        #expect(ring.samples.first == 8)
    }

    @Test func distanceBuckets() {
        #expect(BLEDistance.from(rssi: -60) == .near)
        #expect(BLEDistance.from(rssi: -61) == .mid)
        #expect(BLEDistance.from(rssi: -80) == .mid)
        #expect(BLEDistance.from(rssi: -81) == .far)
    }

    @Test func kindMapsOntoDeviceTypeOrFallsBack() {
        #expect(BLEKind.earbuds.deviceType == .audio)
        #expect(BLEKind.tracker.deviceType == nil)
        #expect(DeviceType.printer.symbol == "printer")
        #expect(DeviceType.unknown.symbol == "questionmark.circle")
    }
}
