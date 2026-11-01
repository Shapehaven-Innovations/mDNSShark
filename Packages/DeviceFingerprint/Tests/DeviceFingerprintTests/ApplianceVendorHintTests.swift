import XCTest
@testable import DeviceFingerprint

final class ApplianceVendorHintTests: XCTestCase {
    private func bundledTable() throws -> [String: String] {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let text = try String(contentsOf: repoRoot.appendingPathComponent("mDNSShark/Resources/oui-database.txt"), encoding: .utf8)
        return OUIDataset.parse(text)
    }

    func test_everyListedName_isARealTableString_andMatches() throws {
        let vendors = Set(try bundledTable().values)
        XCTAssertEqual(ApplianceVendorHint.vendorNames.count, 60)
        XCTAssertEqual(try bundledTable().filter { ApplianceVendorHint.vendorNames.contains($0.value) }.count, 147)
        for name in ApplianceVendorHint.vendorNames {
            XCTAssertTrue(vendors.contains(name), "\(name) is not spelled this way in oui-database.txt")
            XCTAssertTrue(ApplianceVendorHint.isApplianceVendor(name), name)
        }
    }

    func test_lookalikeTraps_doNotMatch() {
        let traps = ["Whisker Labs - Ting", "EMPORIA TELECOM Produktions- und VertriebsgesmbH & Co KG", "Genie Industries, Inc.",
                     "Chamberlain Access Solutions", "Carrier Access Corporation", "Carrier Fire & Security", "Orbit Avionic & Communication",
                     "Smith Myers Communications Ltd.", "Insensi", "Saab Sensis Corporation"]
        for trap in traps { XCTAssertFalse(ApplianceVendorHint.isApplianceVendor(trap), trap) }
    }

    func test_otherVendors_doNotMatch() {
        for name in ["Apple, Inc.", "Google, Inc.", "Samsung Electronics Co.,Ltd", "Tuya Smart Inc.", "Mitsubishi Electric Corporation",
                     "Carrier Corporation", "Tesla,Inc.", "Arcelik A.S", "Prusa Research s.r.o.", "Formlabs", "Ultimaker B.V.",
                     "MakerBot Industries", "Qidi Technology (shanghai) Co.,Ltd.", "Espressif Inc.", "Nest Labs Inc.", "Netatmo", ""] {
            XCTAssertFalse(ApplianceVendorHint.isApplianceVendor(name), name)
        }
    }

    func test_matchIsCaseSensitiveAndWhole() {
        XCTAssertFalse(ApplianceVendorHint.isApplianceVendor("electrolux"))
        XCTAssertFalse(ApplianceVendorHint.isApplianceVendor("Electrolux AB"))
        XCTAssertFalse(ApplianceVendorHint.isApplianceVendor("Trane "))
        XCTAssertFalse(ApplianceVendorHint.isApplianceVendor("Rational AG"))
    }
}
