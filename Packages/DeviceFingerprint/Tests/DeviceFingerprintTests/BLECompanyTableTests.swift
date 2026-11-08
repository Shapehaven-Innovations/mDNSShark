import Foundation
import XCTest
@testable import DeviceFingerprint

final class BLECompanyTableTests: XCTestCase {
    let sample = "76\tApple, Inc.\n6\tMicrosoft\nnot a line\n65535\tReserved"
    func test_parsesDecimalCodes() { XCTAssertEqual(BLECompanyTable(text: sample).name(for: 0x004C), "Apple, Inc.") }
    func test_unknownIsNil() { XCTAssertNil(BLECompanyTable(text: sample).name(for: 1234)) }
    func test_bundledKnowsAppleMicrosoftAndGoogle() {
        let t = BLECompanyTable.bundled
        XCTAssertEqual(t.name(for: 0x004C), "Apple, Inc."); XCTAssertNotNil(t.name(for: 0x0006)); XCTAssertNotNil(t.name(for: 0x00E0))
        XCTAssertGreaterThan(BLECompanyTable.parse(try! String(contentsOf: Bundle.module.url(forResource: "bluetooth-company-ids", withExtension: "txt")!, encoding: .utf8)).count, 3000)
    }
    func test_licenseAndSourceShip() {
        XCTAssertNotNil(Bundle.module.url(forResource: "bluetooth-numbers-database-LICENSE", withExtension: "txt"))
        XCTAssertNotNil(Bundle.module.url(forResource: "bluetooth-numbers-database-SOURCE", withExtension: "txt"))
    }
}
