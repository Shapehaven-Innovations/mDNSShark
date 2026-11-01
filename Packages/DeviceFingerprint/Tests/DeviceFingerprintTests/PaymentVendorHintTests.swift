import XCTest
@testable import DeviceFingerprint

final class PaymentVendorHintTests: XCTestCase {
    /// The app's bundled OUI table, reached across the package boundary the same way `OUIDatasetTests` does.
    private func bundledTable() throws -> [String: String] {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let text = try String(contentsOf: repoRoot.appendingPathComponent("mDNSShark/Resources/oui-database.txt"), encoding: .utf8)
        return OUIDataset.parse(text)
    }

    func test_everyListedName_isARealTableString_andMatches() throws {
        let vendors = Set(try bundledTable().values)
        for name in PaymentVendorHint.vendorNames {
            XCTAssertTrue(vendors.contains(name), "\(name) is not spelled this way in oui-database.txt")
            XCTAssertTrue(PaymentVendorHint.isPaymentVendor(name), name)
        }
    }

    func test_realPrefixes_resolveToAPaymentVendor() throws {
        let db = try bundledTable()
        let prefixes = ["00176f", "000b4f", "000381", "101eda", "547f54", "04c103", "445925", "f4331c",
                        "383c9c", "cc4d74", "1ceec9", "001da9", "c81072",
                        "001dfa", "4c9157", "e89aff", "7408de", "287184", "0040ef", "88c242"]
        for prefix in prefixes {
            let vendor = try XCTUnwrap(db[prefix], prefix)
            XCTAssertTrue(PaymentVendorHint.isPaymentVendor(vendor), "\(prefix) \(vendor)")
        }
        XCTAssertEqual(db.values.filter(PaymentVendorHint.isPaymentVendor).count, 36)
    }

    func test_nearMissTableNames_doNotMatch() throws {
        let vendors = Set(try bundledTable().values)
        let nearMisses = ["Square D Company", "Kendall Square Research Corp.", "IP SQUARE Co, Ltd.", "Pax AB", "PAXCOMM, Inc.",
                          "Paxton Access Ltd", "Clovertech, Inc.", "Blue Clover Devices", "Clover Electronics Co.,Ltd.",
                          "Newland Design + Assoc. Inc.", "Fujian Newland Auto-ID Tech Co.,Ltd.",
                          "Star Micronics Co.,Ltd.", "Seiko Epson Corporation", "Apple, Inc.", "Google, Inc."]
        for name in nearMisses {
            XCTAssertTrue(vendors.contains(name), "fixture \(name) should be a real table string")
            XCTAssertFalse(PaymentVendorHint.isPaymentVendor(name), name)
        }
    }

    func test_alteredSpellings_doNotMatch() {
        for name in ["Square Inc", "square inc.", " Square Inc.", "Square Inc. ", "Square Inc. Ltd", "Hypercom Corp", "Poynt Corporation", "Spire", "PAX", "Verifone", "Ingenico Ltd", "", "Acme Payments"] {
            XCTAssertFalse(PaymentVendorHint.isPaymentVendor(name), name)
        }
    }
}
