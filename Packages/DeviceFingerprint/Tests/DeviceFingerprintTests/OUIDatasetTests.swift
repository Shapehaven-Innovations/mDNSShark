import XCTest
@testable import DeviceFingerprint

final class OUIDatasetTests: XCTestCase {
    let sample = """
    00156d\tUbiquiti Networks Inc.
    245a4c\tUbiquiti Networks Inc.
    a4cf99\tApple, Inc.
    """

    func test_looksUpKnownPrefix_caseInsensitive_anySeparator() {
        let db = OUIDataset(text: sample)
        XCTAssertEqual(db.manufacturer(for: "00:15:6D"), "Ubiquiti Networks Inc.")
        XCTAssertEqual(db.manufacturer(for: "24-5a-4c"), "Ubiquiti Networks Inc.")
        XCTAssertEqual(db.manufacturer(for: "A4:CF:99"), "Apple, Inc.")
    }

    func test_unknownPrefix_returnsNil() {
        let db = OUIDataset(text: sample)
        XCTAssertNil(db.manufacturer(for: "de:ad:be"))
    }

    func test_malformedLines_areSkippedNotCrashed() {
        let db = OUIDataset(text: "not-a-valid-line\n\n00156d\tUbiquiti Networks Inc.")
        XCTAssertEqual(db.manufacturer(for: "00:15:6d"), "Ubiquiti Networks Inc.")
    }

    /// Loads the real bundled `oui-database.txt` (app resource, not a test
    /// fixture — `OUIDataset` itself stays bundle-free per its doc comment,
    /// so this test reaches across the package boundary via `#filePath`
    /// instead) and confirms the mesh/router vendors relevant to device
    /// fingerprinting (todo.md item 1) resolve through it. Regressions here
    /// mean either the vendored table lost coverage or its manufacturer
    /// string formatting changed underneath every probe that relies on it.
    func test_bundledDatabase_coversMeshVendorPrefixes() throws {
        let thisFile = URL(fileURLWithPath: #filePath)
        let repoRoot = thisFile
            .deletingLastPathComponent() // OUIDatasetTests.swift -> DeviceFingerprintTests/
            .deletingLastPathComponent() // -> Tests/
            .deletingLastPathComponent() // -> DeviceFingerprint/
            .deletingLastPathComponent() // -> Packages/
            .deletingLastPathComponent() // -> repo root
        let databaseURL = repoRoot.appendingPathComponent("mDNSShark/Resources/oui-database.txt")
        let text = try String(contentsOf: databaseURL, encoding: .utf8)
        let db = OUIDataset(text: text)

        let knownMeshVendorPrefixes: [(prefix: String, expectedSubstring: String)] = [
            ("00:0C:6E", "ASUS"),
            ("00:1A:11", "Google"),
            ("00:09:5B", "Netgear"),
            ("00:04:5A", "Linksys"),
            ("00:0A:EB", "Tp-Link"),
            ("00:AB:48", "eero"),
        ]

        for (prefix, expectedSubstring) in knownMeshVendorPrefixes {
            let manufacturer = db.manufacturer(for: prefix)
            XCTAssertNotNil(manufacturer, "expected a manufacturer for OUI prefix \(prefix)")
            XCTAssertTrue(
                manufacturer?.localizedCaseInsensitiveContains(expectedSubstring) ?? false,
                "expected \(prefix) to resolve to a manufacturer containing '\(expectedSubstring)', got \(manufacturer ?? "nil")"
            )
        }
    }
}
