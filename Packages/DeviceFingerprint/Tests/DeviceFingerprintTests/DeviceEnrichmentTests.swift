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
        // strength order in the array. ouiLookup (rawValue 4) is stronger
        // than portBanner (rawValue 6).
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

    func test_googleWifiSource_winsOverEverythingElse_forManufacturerMacOS() {
        // Mirrors test_jnapHnapSource_winsOverEverythingElse_forManufacturerMacOS:
        // googleWifiDiscovery is the same ground-truth tier, so it must
        // unconditionally override existing (possibly stale/weaker) fields.
        let existing = EnrichedFields(mac: "aa:bb:cc:dd:ee:ff", manufacturer: "Some OUI Guess",
                                       inferredOS: "Linux (likely)", openPorts: [80])
        let incoming = [
            DeviceEnrichment(mac: nil, manufacturer: "Google",
                              inferredOS: "Google Wifi (15068.66.1)", openPorts: [], source: .googleWifiDiscovery),
            DeviceEnrichment(mac: nil, manufacturer: "Wrong Guess", inferredOS: "Windows (likely)",
                              openPorts: [22], source: .ttlGuess)
        ]
        let result = merge(existing: existing, incoming: incoming)
        XCTAssertEqual(result.mac, "aa:bb:cc:dd:ee:ff")
        XCTAssertEqual(result.manufacturer, "Google")
        XCTAssertEqual(result.inferredOS, "Google Wifi (15068.66.1)")
    }

    func test_jnapHnapBeatsGoogleWifi_whenBothGroundTruthSourcesAnswer() {
        // jnapHnapDiscovery (rawValue 2) is declared before
        // googleWifiDiscovery (rawValue 3), so it's the stronger of the two
        // when both somehow answered for the same device.
        let existing = EnrichedFields(mac: nil, manufacturer: nil, inferredOS: nil, openPorts: [])
        let incoming = [
            DeviceEnrichment(mac: nil, manufacturer: "Google", inferredOS: "Google Wifi",
                              openPorts: [], source: .googleWifiDiscovery),
            DeviceEnrichment(mac: nil, manufacturer: "Linksys", inferredOS: "Linksys MX5500",
                              openPorts: [], source: .jnapHnapDiscovery)
        ]
        let result = merge(existing: existing, incoming: incoming)
        XCTAssertEqual(result.manufacturer, "Linksys")
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
        XCTAssertEqual(EnrichmentSource.googleWifiDiscovery.rawValue, 3)
        XCTAssertEqual(EnrichmentSource.arpTableLookup.rawValue, 4)
        XCTAssertEqual(EnrichmentSource.ouiLookup.rawValue, 5)
        XCTAssertEqual(EnrichmentSource.ssdpDescription.rawValue, 6)
        XCTAssertEqual(EnrichmentSource.portBanner.rawValue, 7)
        XCTAssertEqual(EnrichmentSource.ttlGuess.rawValue, 8)
        XCTAssertTrue(EnrichmentSource.asusDiscovery.isGroundTruth)
        XCTAssertTrue(EnrichmentSource.googleWifiDiscovery.isGroundTruth)
        XCTAssertTrue(EnrichmentSource.googleWifiDiscovery < EnrichmentSource.ouiLookup)
        XCTAssertTrue(EnrichmentSource.jnapHnapDiscovery.isGroundTruth)
        XCTAssertTrue(EnrichmentSource.asusDiscovery < EnrichmentSource.ouiLookup)
        XCTAssertTrue(EnrichmentSource.jnapHnapDiscovery < EnrichmentSource.ouiLookup)
        // arpTableLookup is a real per-IP link-layer read (not a guess), but
        // deliberately NOT ground truth — the device didn't tell us about
        // itself, and the entitlement it depends on is undocumented and
        // unconfirmed-reliable (todo.md item 4). It still outranks
        // ouiLookup/ssdpDescription/portBanner/ttlGuess for `mac` since,
        // when non-nil, it's a direct kernel read rather than an inference.
        XCTAssertFalse(EnrichmentSource.arpTableLookup.isGroundTruth)
        XCTAssertTrue(EnrichmentSource.arpTableLookup < EnrichmentSource.ouiLookup)
        XCTAssertTrue(EnrichmentSource.googleWifiDiscovery < EnrichmentSource.arpTableLookup)
    }

    func test_arpTableLookup_doesNotOverrideGroundTruthMac() {
        // Ground truth (device told us directly) must still win outright
        // over arpTableLookup even though arpTableLookup is a real kernel
        // read, per isGroundTruth's contract.
        let existing = EnrichedFields(mac: nil, manufacturer: nil, inferredOS: nil, openPorts: [])
        let incoming = [
            DeviceEnrichment(mac: "aa:aa:aa:aa:aa:aa", manufacturer: nil, inferredOS: nil,
                              openPorts: [], source: .arpTableLookup),
            DeviceEnrichment(mac: "bb:bb:bb:bb:bb:bb", manufacturer: "Ubiquiti Networks Inc.", inferredOS: "UniFi OS",
                              openPorts: [], source: .ubiquitiDiscovery)
        ]
        let result = merge(existing: existing, incoming: incoming)
        XCTAssertEqual(result.mac, "bb:bb:bb:bb:bb:bb")
    }

    func test_arpTableLookup_winsMacOverOUILookup() {
        let existing = EnrichedFields(mac: nil, manufacturer: nil, inferredOS: nil, openPorts: [])
        let incoming = [
            DeviceEnrichment(mac: "cc:cc:cc:cc:cc:cc", manufacturer: "Some Vendor", inferredOS: nil,
                              openPorts: [], source: .ouiLookup),
            DeviceEnrichment(mac: "aa:aa:aa:aa:aa:aa", manufacturer: nil, inferredOS: nil,
                              openPorts: [], source: .arpTableLookup)
        ]
        let result = merge(existing: existing, incoming: incoming)
        XCTAssertEqual(result.mac, "aa:aa:aa:aa:aa:aa")
    }

    // MARK: - manufacturer -> OS fallback is deliberately NOT applied inside merge()

    func test_ouiResolvedManufacturer_withNoOSSource_mergeLeavesInferredOSNil() {
        // manufacturer arrives via OUI lookup with no source ever providing
        // inferredOS - merge() itself must NOT guess one (that's a
        // display-time-only fallback now, via DiscoveredDevice.displayInferredOS
        // / inferredOSFamily), so a later, more specific non-ground-truth
        // answer arriving in a SEPARATE merge() call is never blocked.
        let existing = EnrichedFields(mac: "aa:bb:cc:dd:ee:ff", manufacturer: nil,
                                       inferredOS: nil, openPorts: [])
        let incoming = [
            DeviceEnrichment(mac: nil, manufacturer: "Netgear", inferredOS: nil,
                              openPorts: [80], source: .ouiLookup)
        ]
        let result = merge(existing: existing, incoming: incoming)
        XCTAssertEqual(result.manufacturer, "Netgear")
        XCTAssertNil(result.inferredOS)
    }

    func test_incrementalMerges_laterSpecificOSAnswer_isNeverBlockedByAnEarlierManufacturerOnlyMerge() {
        // Reproduces the exact race a manufacturer-based fallback INSIDE
        // merge() would cause: a fast SSDP fetch resolves manufacturer
        // first (one merge() call), then a slower banner probe brings a
        // real, specific OS answer in a SEPARATE, later merge() call using
        // the first call's output as its `existing`. The second answer
        // must land - manufacturer being known from call 1 must not have
        // pre-filled (and thereby locked) inferredOS.
        let afterSSDP = merge(
            existing: EnrichedFields(mac: nil, manufacturer: nil, inferredOS: nil, openPorts: []),
            incoming: [DeviceEnrichment(mac: nil, manufacturer: "GL.iNet", inferredOS: nil,
                                         openPorts: [], source: .ssdpDescription)]
        )
        XCTAssertEqual(afterSSDP.manufacturer, "GL.iNet")
        XCTAssertNil(afterSSDP.inferredOS)

        let afterBanner = merge(
            existing: afterSSDP,
            incoming: [DeviceEnrichment(mac: nil, manufacturer: nil, inferredOS: "Linux (OpenWrt, likely)",
                                         openPorts: [], source: .portBanner)]
        )
        XCTAssertEqual(afterBanner.inferredOS, "Linux (OpenWrt, likely)")
    }

    func test_realOSAnswer_isNeverOverriddenByTheGenericFallback() {
        // A source that already supplied a specific OS answer must win over
        // the generic curated fallback, even for a vendor the fallback also
        // recognizes.
        let existing = EnrichedFields(mac: nil, manufacturer: nil, inferredOS: nil, openPorts: [])
        let incoming = [
            DeviceEnrichment(mac: nil, manufacturer: "MikroTik", inferredOS: "RouterOS 7.15 (exact)",
                              openPorts: [], source: .ssdpDescription)
        ]
        let result = merge(existing: existing, incoming: incoming)
        XCTAssertEqual(result.inferredOS, "RouterOS 7.15 (exact)")
    }
}
