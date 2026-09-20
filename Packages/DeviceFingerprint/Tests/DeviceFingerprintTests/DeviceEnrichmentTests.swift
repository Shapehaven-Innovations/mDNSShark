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
        // Test that when two non-ground-truth sources both answer the same
        // field, the stronger source wins even if listed in reverse
        // strength order in the array. ouiLookup (rawValue 3) is stronger
        // than portBanner (rawValue 5).
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

    func test_asusSource_winsOverEverythingElse_forManufacturerMacOS() {
        // Mirrors test_ubiquitiSource_winsOverEverythingElse_forManufacturerMacOS:
        // asusDiscovery is an equally-strong ground-truth tier, so it must
        // unconditionally override existing (possibly stale/weaker) fields
        // the same way ubiquitiDiscovery does, not merely win the general
        // strength-sorted fallback for still-nil fields.
        let existing = EnrichedFields(mac: "aa:bb:cc:dd:ee:ff", manufacturer: "Some OUI Guess",
                                       inferredOS: "Linux (likely)", openPorts: [80])
        let incoming = [
            DeviceEnrichment(mac: "11:22:33:44:55:66", manufacturer: "ASUS",
                              inferredOS: "ASUS (RT-AC68U)", openPorts: [], source: .asusDiscovery),
            DeviceEnrichment(mac: nil, manufacturer: "Wrong Guess", inferredOS: "Windows (likely)",
                              openPorts: [22], source: .ttlGuess)
        ]
        let result = merge(existing: existing, incoming: incoming)
        XCTAssertEqual(result.mac, "11:22:33:44:55:66")
        XCTAssertEqual(result.manufacturer, "ASUS")
        XCTAssertEqual(result.inferredOS, "ASUS (RT-AC68U)")
    }

    func test_jnapHnapSource_winsOverEverythingElse_forManufacturerMacOS() {
        // Mirrors test_asusSource_winsOverEverythingElse_forManufacturerMacOS:
        // jnapHnapDiscovery is the same ground-truth tier, so it must
        // unconditionally override existing (possibly stale/weaker) fields,
        // not merely win the general strength-sorted fallback for still-nil
        // fields. (mac stays nil here since JNAP/HNAP doesn't report one -
        // existing.mac is untouched by the `?? result.mac` fallback.)
        let existing = EnrichedFields(mac: "aa:bb:cc:dd:ee:ff", manufacturer: "Some OUI Guess",
                                       inferredOS: "Linux (likely)", openPorts: [80])
        let incoming = [
            DeviceEnrichment(mac: nil, manufacturer: "Linksys",
                              inferredOS: "Linksys MX5500 (1.0.03.204078)", openPorts: [], source: .jnapHnapDiscovery),
            DeviceEnrichment(mac: nil, manufacturer: "Wrong Guess", inferredOS: "Windows (likely)",
                              openPorts: [22], source: .ttlGuess)
        ]
        let result = merge(existing: existing, incoming: incoming)
        XCTAssertEqual(result.mac, "aa:bb:cc:dd:ee:ff")
        XCTAssertEqual(result.manufacturer, "Linksys")
        XCTAssertEqual(result.inferredOS, "Linksys MX5500 (1.0.03.204078)")
    }

    func test_asusBeatsJnapHnap_whenBothGroundTruthSourcesAnswer() {
        // asusDiscovery (rawValue 1) is declared before jnapHnapDiscovery
        // (rawValue 2), so it's the stronger of the two when both somehow
        // answered for the same device.
        let existing = EnrichedFields(mac: nil, manufacturer: nil, inferredOS: nil, openPorts: [])
        let incoming = [
            DeviceEnrichment(mac: nil, manufacturer: "Linksys", inferredOS: "Linksys MX5500",
                              openPorts: [], source: .jnapHnapDiscovery),
            DeviceEnrichment(mac: "aa:aa:aa:aa:aa:aa", manufacturer: "ASUS", inferredOS: "ASUS (RT-AC68U)",
                              openPorts: [], source: .asusDiscovery)
        ]
        let result = merge(existing: existing, incoming: incoming)
        XCTAssertEqual(result.manufacturer, "ASUS")
    }

    func test_bothGroundTruthSourcesPresent_strongestWins() {
        // ubiquitiDiscovery (rawValue 0) is declared before asusDiscovery
        // (rawValue 1), so it's the stronger of the two ground-truth
        // sources when both somehow answered for the same device.
        let existing = EnrichedFields(mac: nil, manufacturer: nil, inferredOS: nil, openPorts: [])
        let incoming = [
            DeviceEnrichment(mac: "aa:aa:aa:aa:aa:aa", manufacturer: "ASUS", inferredOS: "ASUS (RT-AC68U)",
                              openPorts: [], source: .asusDiscovery),
            DeviceEnrichment(mac: "bb:bb:bb:bb:bb:bb", manufacturer: "Ubiquiti Networks Inc.", inferredOS: "UniFi OS",
                              openPorts: [], source: .ubiquitiDiscovery)
        ]
        let result = merge(existing: existing, incoming: incoming)
        XCTAssertEqual(result.manufacturer, "Ubiquiti Networks Inc.")
    }

    func test_enrichmentSource_currentRawValueOrdering() {
        // Documents the actual declaration order (and therefore precedence)
        // as of this file's writing — catches an accidental reordering that
        // would silently change precedence without any other test noticing.
        XCTAssertEqual(EnrichmentSource.ubiquitiDiscovery.rawValue, 0)
        XCTAssertEqual(EnrichmentSource.asusDiscovery.rawValue, 1)
        XCTAssertEqual(EnrichmentSource.jnapHnapDiscovery.rawValue, 2)
        XCTAssertEqual(EnrichmentSource.ouiLookup.rawValue, 3)
        XCTAssertEqual(EnrichmentSource.ssdpDescription.rawValue, 4)
        XCTAssertEqual(EnrichmentSource.portBanner.rawValue, 5)
        XCTAssertEqual(EnrichmentSource.ttlGuess.rawValue, 6)
        XCTAssertTrue(EnrichmentSource.asusDiscovery.isGroundTruth)
        XCTAssertTrue(EnrichmentSource.jnapHnapDiscovery.isGroundTruth)
        XCTAssertTrue(EnrichmentSource.asusDiscovery < EnrichmentSource.ouiLookup)
        XCTAssertTrue(EnrichmentSource.jnapHnapDiscovery < EnrichmentSource.ouiLookup)
    }
}
