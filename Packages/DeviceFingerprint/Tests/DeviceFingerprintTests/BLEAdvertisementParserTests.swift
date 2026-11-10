import XCTest
@testable import DeviceFingerprint

final class BLEAdvertisementParserTests: XCTestCase {
    let parser = BLEAdvertisementParser(companies: BLECompanyTable(text: "76\tApple, Inc.\n6\tMicrosoft"), services: BLEServiceNameTable(text: "180A\tDevice Information\n180F\tBattery\n1812\tHuman Interface Device"))
    func test_appleProximityPairingIsEarbudsWithHint() {
        let p = parser.parse(BLEAdvertisementFields(manufacturerData: Data([0x4C, 0x00, 0x07, 0x04, 0x01, 0x0E, 0x20, 0x55])))
        XCTAssertEqual(p.companyName, "Apple, Inc."); XCTAssertEqual(p.kind, .earbuds); XCTAssertEqual(p.continuityModelHint, "AirPods Pro")
    }
    func test_hidServiceIsInputDeviceAndNamesServices() {
        let p = parser.parse(BLEAdvertisementFields(localName: "Keyboard", serviceUUIDs: ["00001812-0000-1000-8000-00805F9B34FB", "180f", "180F"]))
        XCTAssertEqual(p.serviceUUIDs, ["180F", "1812"]); XCTAssertEqual(p.serviceNames["1812"], "Human Interface Device"); XCTAssertEqual(p.kind, .inputDevice)
        XCTAssertEqual(p.kindReason, "Advertises the Human Interface Device service")
    }
    func test_matterServiceDataWinsOverEverything() {
        let p = parser.parse(BLEAdvertisementFields(serviceUUIDs: ["FFF6"], serviceData: ["FFF6": Data([0x00, 0x34, 0x02, 0xF1, 0xFF, 0x01, 0x80, 0x00])]))
        XCTAssertEqual(p.kind, .smartHome); XCTAssertEqual(p.matter?.vendorID, 0xFFF1)
    }
    func test_unknownStaysUnknownWithNoReason() {
        let p = parser.parse(BLEAdvertisementFields(manufacturerData: Data([0x99, 0x09, 0x01])))
        XCTAssertEqual(p.kind, .unknown); XCTAssertNil(p.kindReason); XCTAssertNil(p.companyName); XCTAssertEqual(p.companyID, 0x0999)
    }
    func test_cachedNameIsUsedOnlyWhenNothingIsAdvertised() {
        XCTAssertEqual(parser.parse(BLEAdvertisementFields(cachedName: "Alex\u{2019}s Watch")).displayName, "Alex\u{2019}s Watch")
        XCTAssertEqual(parser.parse(BLEAdvertisementFields(localName: "Live", cachedName: "Old")).displayName, "Live")
        XCTAssertNil(parser.parse(BLEAdvertisementFields(cachedName: "\u{202E}  ")).displayName)
    }
    func test_displayNameIsSanitized() { XCTAssertEqual(parser.parse(BLEAdvertisementFields(localName: "\u{202E}Tile")).displayName, "Tile") }
    func test_tileServicesAreTrackers() {
        for uuid in ["FEED", "FEEC", "0000FEEC-0000-1000-8000-00805F9B34FB"] {
            let p = parser.parse(BLEAdvertisementFields(serviceUUIDs: [uuid]))
            XCTAssertEqual(p.kind, .tracker, uuid); XCTAssertEqual(p.kindReason, "Advertises the Tile tracker service", uuid)
        }
    }
    func test_everyKindHasLabelAndSymbol() { for k in BLEKind.allCases { XCTAssertFalse(k.label.isEmpty); XCTAssertFalse(k.symbol.isEmpty) } }
}
