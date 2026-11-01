import XCTest
@testable import DeviceFingerprint

final class InfrastructureVendorHintTests: XCTestCase {
    private func bundledTable() throws -> [String: String] {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let text = try String(contentsOf: repoRoot.appendingPathComponent("mDNSShark/Resources/oui-database.txt"), encoding: .utf8)
        return OUIDataset.parse(text)
    }

    func test_everyListedName_isARealTableString_andMatches() throws {
        let vendors = Set(try bundledTable().values)
        for name in InfrastructureVendorHint.vendorNames {
            XCTAssertTrue(vendors.contains(name), "\(name) is not spelled this way in oui-database.txt")
            XCTAssertTrue(InfrastructureVendorHint.isInfrastructureVendor(name), name)
        }
        XCTAssertEqual(InfrastructureVendorHint.vendorNames.count, 25)
    }

    func test_realPrefixes_resolveToAnInfrastructureVendor() throws {
        let db = try bundledTable()
        for prefix in ["000481", "0004cc", "1cc11a", "00147b", "b41e52", "001d4d", "000e65"] {
            let vendor = try XCTUnwrap(db[prefix], prefix)
            XCTAssertTrue(InfrastructureVendorHint.isInfrastructureVendor(vendor), "\(prefix) \(vendor)")
        }
        XCTAssertEqual(db.values.filter(InfrastructureVendorHint.isInfrastructureVendor).count, 25)
    }

    func test_ambiguousAndNearMissNames_doNotMatch() throws {
        let vendors = Set(try bundledTable().values)
        for name in ["FLIR Systems", "Daktronics, Inc.", "Kapsch Ag", "GENETEC Corporation", "Pelcombe Group Ltd.", "Genetec Inc.", "Tattile SRL"] {
            XCTAssertTrue(vendors.contains(name), "fixture \(name) should be a real table string")
            XCTAssertFalse(InfrastructureVendorHint.isInfrastructureVendor(name), name)
        }
        for name in ["Genetec", "genetec inc.", " Genetec Inc.", "Wavetronix LLC", "Flock", ""] {
            XCTAssertFalse(InfrastructureVendorHint.isInfrastructureVendor(name), name)
        }
    }
}
