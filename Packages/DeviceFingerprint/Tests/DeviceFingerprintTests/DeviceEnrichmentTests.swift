import XCTest
@testable import DeviceFingerprint

final class DeviceEnrichmentTests: XCTestCase {
    func test_ubiquitiSource_winsOverEverythingElse_forManufacturerMacOS() {
        let existing = EnrichedFields(mac: "aa:bb:cc:dd:ee:ff", manufacturer: "Some OUI Guess",
                                       inferredOS: "Linux (likely)", openPorts: [80])
        let incoming = [
            DeviceEnrichment(mac: "11:22:33:44:55:66", manufacturer: "Ubiquiti Networks Inc.",
                              inferredOS: "UniFi OS", openPorts: [443], source: .ubiquitiDiscovery),
            DeviceEnrichment(mac: nil, manufacturer: "Wrong Guess", inferredOS: "Windows (likely)",
                              openPorts: [22], source: .ttlGuess)
        ]
        let result = merge(existing: existing, incoming: incoming)
        XCTAssertEqual(result.mac, "11:22:33:44:55:66")
        XCTAssertEqual(result.manufacturer, "Ubiquiti Networks Inc.")
        XCTAssertEqual(result.inferredOS, "UniFi OS")
    }

    func test_noUbiquitiSource_firstNonNilWinsInPrecedenceOrder() {
        let existing = EnrichedFields(mac: nil, manufacturer: nil, inferredOS: nil, openPorts: [])
        let incoming = [
            DeviceEnrichment(mac: nil, manufacturer: nil, inferredOS: "Linux (likely)", openPorts: [],
                              source: .ttlGuess),
            DeviceEnrichment(mac: nil, manufacturer: "Synology Inc.", inferredOS: nil, openPorts: [],
                              source: .ssdpDescription)
        ]
        let result = merge(existing: existing, incoming: incoming)
        // ssdpDescription outranks ttlGuess, so its manufacturer wins...
        XCTAssertEqual(result.manufacturer, "Synology Inc.")
        // ...but ssdpDescription had no inferredOS, so ttlGuess's weaker answer still fills the gap.
        XCTAssertEqual(result.inferredOS, "Linux (likely)")
    }

    func test_openPorts_isUnionAcrossAllSources_notPrecedence() {
        let existing = EnrichedFields(mac: nil, manufacturer: nil, inferredOS: nil, openPorts: [80])
        let incoming = [
            DeviceEnrichment(mac: nil, manufacturer: nil, inferredOS: nil, openPorts: [22, 80],
                              source: .portBanner),
            DeviceEnrichment(mac: nil, manufacturer: nil, inferredOS: nil, openPorts: [443],
                              source: .ubiquitiDiscovery)
        ]
        let result = merge(existing: existing, incoming: incoming)
        XCTAssertEqual(Set(result.openPorts), Set([22, 80, 443]))
    }

    func test_existingRealAnswer_isNeverOverriddenByTTLGuess() {
        let existing = EnrichedFields(mac: nil, manufacturer: "Apple, Inc.", inferredOS: nil, openPorts: [])
        let incoming = [
            DeviceEnrichment(mac: nil, manufacturer: "Wrong Guess", inferredOS: "Linux (likely)",
                              openPorts: [], source: .ttlGuess)
        ]
        let result = merge(existing: existing, incoming: incoming)
        XCTAssertEqual(result.manufacturer, "Apple, Inc.")
    }

    func test_strengthSort_betweenNonUbiquitiSources_reverseOrderInArray() {
        // Test that when two non-Ubiquiti sources both answer the same field,
        // the stronger source wins even if listed in reverse strength order in the array.
        // ouiLookup (rawValue 1) is stronger than portBanner (rawValue 3).
        let existing = EnrichedFields(mac: nil, manufacturer: nil, inferredOS: nil, openPorts: [])
        let incoming = [
            DeviceEnrichment(mac: nil, manufacturer: "Wrong Guess", inferredOS: nil,
                              openPorts: [], source: .portBanner),  // weaker, listed first
            DeviceEnrichment(mac: nil, manufacturer: "Correct OUI", inferredOS: nil,
                              openPorts: [], source: .ouiLookup)    // stronger, listed second
        ]
        let result = merge(existing: existing, incoming: incoming)
        // ouiLookup should win despite being listed second, because it's stronger
        XCTAssertEqual(result.manufacturer, "Correct OUI")
    }
}
