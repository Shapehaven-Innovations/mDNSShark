import XCTest
@testable import DeviceFingerprint

final class ManufacturerOSHintTests: XCTestCase {
    func test_synologyAndMikroTik_returnVendorSpecificOS() {
        XCTAssertEqual(inferredOSFamily(forManufacturer: "Synology Inc."), "DSM (Synology, Linux-based, likely)")
        XCTAssertEqual(inferredOSFamily(forManufacturer: "MikroTik"), "RouterOS (MikroTik, Linux-based, likely)")
    }

    func test_espressif_returnsESPIDF() {
        XCTAssertEqual(inferredOSFamily(forManufacturer: "Espressif Inc."), "ESP-IDF (Espressif, FreeRTOS-based, likely)")
    }

    func test_lgElectronics_returnsWebOS() {
        XCTAssertEqual(inferredOSFamily(forManufacturer: "LG Electronics"), "webOS (LG, Linux-based, likely)")
    }

    func test_bareLGSubstring_doesNotMatch() {
        XCTAssertNil(inferredOSFamily(forManufacturer: "Algo Communication Products"))
    }

    func test_amcrest_returnsEmbeddedLinux() {
        XCTAssertEqual(inferredOSFamily(forManufacturer: "Amcrest Technologies"), "Linux (embedded, likely)")
    }

    func test_unlistedVendor_returnsNil() {
        XCTAssertNil(inferredOSFamily(forManufacturer: "Apple, Inc."))
    }
}
