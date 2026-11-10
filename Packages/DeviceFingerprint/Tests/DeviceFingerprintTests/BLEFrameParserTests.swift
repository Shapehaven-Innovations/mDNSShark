import XCTest
@testable import DeviceFingerprint

final class BLEFrameParserTests: XCTestCase {
    func test_matterCommissionable() {
        let data = Data([0x00, 0x34, 0x02, 0xF1, 0xFF, 0x01, 0x80, 0x00])
        XCTAssertEqual(MatterBLEAdvertisement.parse(serviceData: data), MatterBLEAdvertisement(discriminator: 0x234, vendorID: 0xFFF1, productID: 0x8001))
        XCTAssertNil(MatterBLEAdvertisement.parse(serviceData: Data([0x00, 0x34])))
        XCTAssertNil(MatterBLEAdvertisement.parse(serviceData: Data([0x01, 0x34, 0x02, 0xF1, 0xFF, 0x01, 0x80, 0x00])))
    }
    func test_eddystoneURL() {
        XCTAssertEqual(EddystoneFrame.parse(serviceData: Data([0x10, 0xEE, 0x01, 0x61, 0x62, 0x63, 0x00])), .url("https://www.abc.com/", txPower: -18))
    }
    func test_eddystoneUIDAndUnknown() {
        let uid = Data([0x00, 0xE7] + [UInt8](repeating: 0xAB, count: 10) + [UInt8](repeating: 0x01, count: 6))
        XCTAssertEqual(EddystoneFrame.parse(serviceData: uid), .uid(namespace: String(repeating: "AB", count: 10), instance: "010101010101", txPower: -25))
        XCTAssertEqual(EddystoneFrame.parse(serviceData: Data([0x50, 0x00])), .unknown(0x50))
        XCTAssertNil(EddystoneFrame.parse(serviceData: Data()))
    }
    func test_findHubFrameNeedsAFullEID() {
        let eid20 = [UInt8](repeating: 0xAB, count: 20), eid32 = [UInt8](repeating: 0xCD, count: 32)
        XCTAssertEqual(EddystoneFrame.parse(serviceData: Data([0x40] + eid20)), .findHub(trackingProtection: false))
        XCTAssertEqual(EddystoneFrame.parse(serviceData: Data([0x41] + eid20 + [0x01])), .findHub(trackingProtection: true))
        XCTAssertEqual(EddystoneFrame.parse(serviceData: Data([0x40] + eid32 + [0x00])), .findHub(trackingProtection: false))
        XCTAssertNil(EddystoneFrame.parse(serviceData: Data([0x40, 0x00])))
        XCTAssertNil(EddystoneFrame.parse(serviceData: Data([0x41] + eid20 + [0x01, 0x02])))
    }
    func test_fastPairModelOnlyForThreeBytes() {
        XCTAssertEqual(FastPairAdvertisement.parse(serviceData: Data([0x2C, 0xFE, 0x01]))?.modelID, 0x2CFE01)
        XCTAssertNil(FastPairAdvertisement.parse(serviceData: Data([0x00, 0x11, 0x22, 0x33, 0x44]))?.modelID)
    }
    func test_swiftPair() {
        let payload = Data([0x03, 0x01, 0x80] + Array("Surface Keyboard".utf8))
        XCTAssertEqual(SwiftPairAdvertisement.parse(manufacturerPayload: payload), SwiftPairAdvertisement(scenario: 1, displayName: "Surface Keyboard"))
        XCTAssertNil(SwiftPairAdvertisement.parse(manufacturerPayload: Data([0x01, 0x00])))
    }
    func test_continuityTLVWalkStopsAtTruncation() {
        let payload = Data([0x10, 0x02, 0xAA, 0xBB, 0x0C, 0x05, 0x01])
        let msgs = AppleContinuity.messages(in: payload)
        XCTAssertEqual(msgs.count, 1); XCTAssertEqual(msgs[0].type, .nearbyInfo); XCTAssertEqual(msgs[0].payload, Data([0xAA, 0xBB]))
    }
    func test_continuityUnknownTypeKeepsRaw() { XCTAssertEqual(AppleContinuity.messages(in: Data([0x7F, 0x01, 0x00]))[0].type, nil) }
    func test_proximityPairingModelHint() {
        XCTAssertEqual(AppleContinuity.proximityPairingModelHint(Data([0x01, 0x0E, 0x20, 0x55])), "AirPods Pro")
        XCTAssertNil(AppleContinuity.proximityPairingModelHint(Data([0x01])))
    }
    func test_homeKit() {
        var bytes = [UInt8](repeating: 0, count: 14); bytes[1] = 0x01; bytes[8] = 0x11
        let hk = HomeKitBLEAdvertisement.parse(continuityPayload: Data(bytes))
        XCTAssertEqual(hk?.category, 17); XCTAssertEqual(hk?.pairingEnabled, true); XCTAssertEqual(hk?.categoryKind, .camera)
        XCTAssertNil(HomeKitBLEAdvertisement.parse(continuityPayload: Data(bytes.prefix(10))))
    }
    func test_fieldsCompanyIDLittleEndian() {
        let f = BLEAdvertisementFields(manufacturerData: Data([0x4C, 0x00, 0x10, 0x05]))
        XCTAssertEqual(f.companyID, 0x004C); XCTAssertEqual(f.manufacturerPayload, Data([0x10, 0x05]))
        XCTAssertNil(BLEAdvertisementFields(manufacturerData: Data([0x4C])).companyID)
    }
}
