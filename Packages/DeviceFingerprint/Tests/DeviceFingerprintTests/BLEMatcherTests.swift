import XCTest
@testable import DeviceFingerprint

final class BLEMatcherTests: XCTestCase {
    private func cand(_ name: String, _ maker: String?, vid: UInt16? = nil, pid: UInt16? = nil,
                      airPlay: Bool = false, homeKit: Bool = false, id: UUID = UUID()) -> BLEMatchCandidate {
        BLEMatchCandidate(id: id, name: name, manufacturer: maker, matterVendorID: vid, matterProductID: pid,
                          hasAirPlay: airPlay, hasHomeKit: homeKit)
    }

    private func subj(_ name: String?, _ company: String?, vid: UInt16? = nil, pid: UInt16? = nil,
                      continuity: Set<AppleContinuityType> = [], category: Int? = nil,
                      id: UUID = UUID()) -> BLEMatchSubject {
        BLEMatchSubject(id: id, name: name, companyName: company, matterVendorID: vid, matterProductID: pid,
                        continuity: continuity, homeKitCategory: category)
    }

    func test_matterIDsAreStrong() {
        let r = BLEMatcher.score(subj(nil, nil, vid: 0xFFF1, pid: 0x8001), cand("Lamp", nil, vid: 0xFFF1, pid: 0x8001))
        XCTAssertEqual(r.tier, .strong)
        XCTAssertEqual(r.caption, "Inferred, not confirmed: Matter vendor and product IDs match.")
    }

    func test_exactNameAndVendorIsStrong() {
        let r = BLEMatcher.score(subj("Sonos Roam", "Sonos, Inc."), cand("Sonos Roam.local", "Sonos Inc"))
        XCTAssertEqual(r.tier, .strong)
        XCTAssertEqual(r.caption, "Inferred, not confirmed: same name, same vendor.")
    }

    func test_similarNameAndVendorIsPossible() {
        let r = BLEMatcher.score(subj("Roam", "Sonos, Inc."), cand("Sonos Roam (2)", "Sonos Inc"))
        XCTAssertEqual(r.tier, .possible)
        XCTAssertEqual(r.caption, "Inferred: similar name, same vendor.")
    }

    func test_similarNameWithoutVendorIsNone() {
        let r = BLEMatcher.score(subj("Sonos Roam", "Sonos, Inc."), cand("Sonos Roam", nil))
        XCTAssertEqual(r.tier, .none)
        XCTAssertEqual(r.caption, "")
    }

    func test_continuityFitsAirPlayHost() {
        let r = BLEMatcher.score(subj(nil, "Apple, Inc.", continuity: [.airPlayTarget]),
                                 cand("Living Room", "Apple", airPlay: true))
        XCTAssertEqual(r.tier, .possible)
        XCTAssertEqual(r.caption, "Inferred: same vendor, Apple Continuity fits this host.")
        let h = BLEMatcher.score(subj(nil, "Apple, Inc.", category: 5), cand("Hub", "Apple", homeKit: true))
        XCTAssertEqual(h.caption, "Inferred: same vendor, HomeKit accessory fits this host.")
    }

    func test_onlyAirPlayTargetFitsAnAirPlayHost() {
        let mac = cand("Studio Mac", "Apple", airPlay: true)
        for continuity: Set<AppleContinuityType> in [[.handoff, .nearbyInfo], [.airPlaySource], [.nearbyInfo]] {
            XCTAssertEqual(BLEMatcher.score(subj(nil, "Apple, Inc.", continuity: continuity), mac).tier, .none, "\(continuity)")
        }
        XCTAssertEqual(BLEMatcher.score(subj(nil, "Apple, Inc.", continuity: [.airPlayTarget]), mac).tier, .possible)
        let table = BLEMatcher.match(subjects: [subj(nil, "Apple, Inc.", continuity: [.handoff, .nearbyInfo])], candidates: [mac])
        XCTAssertEqual(table, .empty)
    }

    func test_vendorsAgreeSkipsPlaceAndFillerWords() {
        XCTAssertFalse(BLEMatcher.vendorsAgree("Shenzhen Foo Tech", "Shenzhen Bar Ltd"))
        XCTAssertTrue(BLEMatcher.vendorsAgree("Shenzhen Xiaomi Communications", "Xiaomi"))
        XCTAssertTrue(BLEMatcher.vendorsAgree("The Sonos Company", "Sonos, Inc."))
        XCTAssertFalse(BLEMatcher.vendorsAgree("Beijing Alpha", "Hangzhou Beta"))
        XCTAssertTrue(BLEMatcher.vendorsAgree("Shenzhen", "Shenzhen Ltd"))
    }

    func test_vendorsAgreeTable() {
        XCTAssertTrue(BLEMatcher.vendorsAgree("Sonos, Inc.", "Sonos Inc"))
        XCTAssertTrue(BLEMatcher.vendorsAgree("Apple, Inc.", "Apple"))
        XCTAssertFalse(BLEMatcher.vendorsAgree(nil, "Apple"))
        XCTAssertFalse(BLEMatcher.vendorsAgree("Google LLC", "Apple, Inc."))
    }

    func test_higherTierWinsOverLowerCandidates() {
        let s = subj("Sonos Roam", "Sonos, Inc.")
        let strong = cand("Sonos Roam", "Sonos Inc")
        let weak = cand("Roam Kitchen", "Sonos Inc")
        let t = BLEMatcher.match(subjects: [s], candidates: [strong, weak])
        XCTAssertEqual(t.suggestions.count, 1)
        XCTAssertEqual(t.suggestions.first?.deviceID, strong.id)
        XCTAssertEqual(t.suggestions.first?.tier, .strong)
        XCTAssertTrue(t.ties.isEmpty)
    }

    func test_tieLeavesPeripheralUnmatched() {
        let s = subj("Roam", "Sonos, Inc.")
        let a = cand("Sonos Roam One", "Sonos Inc"), b = cand("Sonos Roam Two", "Sonos Inc")
        let t = BLEMatcher.match(subjects: [s], candidates: [a, b])
        XCTAssertTrue(t.suggestions.isEmpty)
        XCTAssertEqual(t.ties.count, 1)
        XCTAssertEqual(t.ties.first?.deviceIDs, [a.id, b.id].sorted { $0.uuidString < $1.uuidString })
        XCTAssertEqual(t.ties.first?.tier, .possible)
        XCTAssertTrue(t.suggestedDeviceIDs.isEmpty)
        XCTAssertNotNil(t.tie(forPeripheral: s.id))
    }

    func test_oneDeviceMayHoldSeveralSuggestions() {
        let m = cand("Studio", nil, vid: 1, pid: 2)
        let earbuds = subj(nil, nil, vid: 1, pid: 2), box = subj(nil, nil, vid: 1, pid: 2)
        let t = BLEMatcher.match(subjects: [earbuds, box], candidates: [m])
        XCTAssertEqual(t.suggestions(forDevice: m.id).count, 2)
        XCTAssertEqual(t.suggestedPeripheralIDs, [earbuds.id, box.id])
    }

    func test_normalizedNameStripsLocalAndCounter() {
        XCTAssertEqual(BLEMatcher.normalizedName("Ana's iPhone (2).local"), "anasiphone")
    }
}
