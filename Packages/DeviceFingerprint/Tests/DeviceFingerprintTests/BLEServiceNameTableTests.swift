import Foundation
import XCTest
@testable import DeviceFingerprint

final class BLEServiceNameTableTests: XCTestCase {
    func test_shortFormCollapsesBaseUUID() { XCTAssertEqual(BLEServiceNameTable.shortForm("0000180a-0000-1000-8000-00805f9b34fb"), "180A") }
    func test_shortFormKeepsVendorUUID() { XCTAssertEqual(BLEServiceNameTable.shortForm("6e400001-b5a3-f393-e0a9-e50e24dcca9e"), "6E400001-B5A3-F393-E0A9-E50E24DCCA9E") }
    func test_bundledNamesDeviceInformationBatteryFastPairEddystone() {
        let t = BLEServiceNameTable.bundled
        XCTAssertEqual(t.name(forUUID: "180A"), "Device Information"); XCTAssertEqual(t.name(forUUID: "180f"), "Battery Service")
        XCTAssertNotNil(t.name(forUUID: "FE2C")); XCTAssertNotNil(t.name(forUUID: "FEAA"))
    }
}
