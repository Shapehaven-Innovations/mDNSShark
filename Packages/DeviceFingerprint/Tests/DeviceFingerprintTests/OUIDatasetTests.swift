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
}
