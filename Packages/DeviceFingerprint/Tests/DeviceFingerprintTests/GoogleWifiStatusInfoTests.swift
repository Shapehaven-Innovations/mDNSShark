import XCTest
@testable import DeviceFingerprint

final class GoogleWifiStatusInfoTests: XCTestCase {
    func test_validResponse_parsesAllFields() {
        // Community-observed real values are board codenames, not friendly
        // names ("MISTRAL" = Nest Wifi router, "GALE" = Google Wifi,
        // "BREEZE" = Nest Wifi point; hardwareId is codename + per-unit
        // serial) - using codename-shaped fixtures here deliberately, so
        // this test doesn't encode a false assumption that these fields are
        // human-readable. The coordinator never surfaces either field
        // directly to the UI for exactly this reason.
        let json = """
        {"system":{"hardwareId":"MISTRAL D2C-A2A-A3R-I9R","modelId":"MISTRAL","countryCode":"us","groupRole":"root"},
         "software":{"softwareVersion":"15068.66.1","updateChannel":"stable-channel"},
         "wan":{"online":true}}
        """.data(using: .utf8)!
        let info = GoogleWifiStatusParser.parse(json)
        XCTAssertEqual(info?.hardwareId, "MISTRAL D2C-A2A-A3R-I9R")
        XCTAssertEqual(info?.modelId, "MISTRAL")
        XCTAssertEqual(info?.softwareVersion, "15068.66.1")
    }

    func test_hardwareIdOnly_stillParses() {
        let json = "{\"system\":{\"hardwareId\":\"MISTRAL D2C-A2A-A3R-I9R\"}}".data(using: .utf8)!
        let info = GoogleWifiStatusParser.parse(json)
        XCTAssertEqual(info?.hardwareId, "MISTRAL D2C-A2A-A3R-I9R")
        XCTAssertNil(info?.modelId)
    }

    func test_modelIdOnly_stillParses() {
        let json = "{\"system\":{\"modelId\":\"GALE\"}}".data(using: .utf8)!
        let info = GoogleWifiStatusParser.parse(json)
        XCTAssertEqual(info?.modelId, "GALE")
    }

    func test_softwareVersionAlone_withoutIdentityField_returnsNil() {
        // softwareVersion alone isn't an identity signal - without
        // hardwareId or modelId this must not be treated as a match, so an
        // unrelated JSON server that happens to have a "software" object
        // can't produce a false positive.
        let json = "{\"software\":{\"softwareVersion\":\"1.0\"}}".data(using: .utf8)!
        XCTAssertNil(GoogleWifiStatusParser.parse(json))
    }

    func test_missingSystemObject_returnsNil() {
        let json = "{\"wan\":{\"online\":true}}".data(using: .utf8)!
        XCTAssertNil(GoogleWifiStatusParser.parse(json))
    }

    func test_malformedJSON_returnsNil() {
        let json = "not json".data(using: .utf8)!
        XCTAssertNil(GoogleWifiStatusParser.parse(json))
    }

    func test_emptyJSONObject_returnsNil() {
        let json = "{}".data(using: .utf8)!
        XCTAssertNil(GoogleWifiStatusParser.parse(json))
    }
}
