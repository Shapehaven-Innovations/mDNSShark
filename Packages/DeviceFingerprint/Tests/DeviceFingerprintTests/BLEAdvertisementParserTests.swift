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
    func test_sigHealthAndAudioServicesAreTyped() {
        for (uuid, kind, name) in [("1808", BLEKind.health, "Glucose"), ("181F", .health, "Continuous Glucose Monitoring"), ("1854", .health, "Hearing Access"),
                                   ("184E", .audio, "Audio Stream Control"), ("1850", .audio, "Published Audio Capabilities")] {
            let p = parser.parse(BLEAdvertisementFields(serviceUUIDs: [uuid]))
            XCTAssertEqual(p.kind, kind, uuid); XCTAssertEqual(p.kindReason, "Advertises the \(name) service", uuid)
        }
    }
    func test_appleFindMyIsFindMyNotTracker() {
        let p = parser.parse(BLEAdvertisementFields(manufacturerData: Data([0x4C, 0x00, 0x12, 0x02, 0x00, 0x00])))
        XCTAssertEqual(p.kind, .findMy); XCTAssertEqual(p.kindReason, "Sends an Apple Find My message")
        XCTAssertFalse(BLEKind.findMy.offersDeviceInfoRead); XCTAssertFalse(BLEKind.tracker.offersDeviceInfoRead); XCTAssertTrue(BLEKind.phone.offersDeviceInfoRead)
    }
    func test_companyAloneNeverSetsAKind() {
        let garmin = parser.parse(BLEAdvertisementFields(manufacturerData: Data([0x87, 0x00, 0x01])))
        XCTAssertEqual(garmin.kind, .unknown); XCTAssertNil(garmin.kindReason); XCTAssertEqual(garmin.companyID, 135)
        let apple = parser.parse(BLEAdvertisementFields(manufacturerData: Data([0x4C, 0x00, 0x10, 0x02, 0xAA, 0xBB, 0x0C, 0x01, 0x00])))
        XCTAssertEqual(apple.kind, .unknown); XCTAssertNil(apple.kindReason); XCTAssertEqual(apple.companyName, "Apple, Inc.")
        XCTAssertEqual(apple.continuity.compactMap(\.type), [.nearbyInfo, .handoff])
        XCTAssertEqual(parser.parse(BLEAdvertisementFields(manufacturerData: Data([0x4C, 0x00, 0x09, 0x01, 0x00]))).kind, .unknown)
    }
    func test_pairingBeaconsKeepTheirDataButNoKind() {
        let fastPair = parser.parse(BLEAdvertisementFields(serviceUUIDs: ["FE2C"], serviceData: ["FE2C": Data([0x2C, 0xFE, 0x01])]))
        XCTAssertEqual(fastPair.kind, .unknown); XCTAssertNil(fastPair.kindReason); XCTAssertEqual(fastPair.fastPair?.modelID, 0x2CFE01)
        let swiftPair = parser.parse(BLEAdvertisementFields(manufacturerData: Data([0x06, 0x00, 0x03, 0x00, 0x80] + Array("Surface Keyboard".utf8))))
        XCTAssertEqual(swiftPair.kind, .unknown); XCTAssertEqual(swiftPair.displayName, "Surface Keyboard"); XCTAssertEqual(swiftPair.companyName, "Microsoft")
    }
    func test_findHubFrameIsATrackerAndEddystoneIsABeacon() {
        let eid = [UInt8](repeating: 0xAB, count: 20)
        for type in [UInt8(0x40), 0x41] {
            let p = parser.parse(BLEAdvertisementFields(serviceUUIDs: ["FEAA"], serviceData: ["FEAA": Data([type] + eid + [0x00])]))
            XCTAssertEqual(p.kind, .tracker); XCTAssertEqual(p.kindReason, "Sends a Google Find Hub frame")
        }
        let url = parser.parse(BLEAdvertisementFields(serviceData: ["FEAA": Data([0x10, 0xEE, 0x01, 0x61, 0x00])]))
        XCTAssertEqual(url.kind, .beacon); XCTAssertEqual(url.kindReason, "Sends an Eddystone frame")
        XCTAssertEqual(parser.parse(BLEAdvertisementFields(serviceData: ["FEAA": Data([0x50, 0x00])])).kind, .unknown)
    }
    func test_serviceDataKeysCountAsServicesButTheListStaysLiteral() {
        let p = parser.parse(BLEAdvertisementFields(serviceData: ["0000180D-0000-1000-8000-00805F9B34FB": Data([0x00, 0x48])]))
        XCTAssertEqual(p.kind, .health); XCTAssertEqual(p.kindReason, "Advertises the Heart Rate service"); XCTAssertEqual(p.serviceUUIDs, [])
        XCTAssertEqual(parser.parse(BLEAdvertisementFields(serviceData: ["FEED": Data([0x01])])).kind, .tracker)
    }
    func test_everyKindHasLabelAndSymbol() { for k in BLEKind.allCases { XCTAssertFalse(k.label.isEmpty); XCTAssertFalse(k.symbol.isEmpty) } }
}
