import XCTest
@testable import DeviceFingerprint

final class MatterTXTTests: XCTestCase {
    func test_vendorAndProduct() {
        XCTAssertEqual(MatterTXT.vendorProduct(["VP": "65521+32769"])?.vendorID, 65521)
        XCTAssertEqual(MatterTXT.vendorProduct(["VP": "65521+32769"])?.productID, 32769)
    }

    func test_vendorOnlyAndGarbage() {
        XCTAssertEqual(MatterTXT.vendorProduct(["VP": "4874"])?.vendorID, 4874)
        XCTAssertNil(MatterTXT.vendorProduct(["VP": "4874"])?.productID)
        XCTAssertNil(MatterTXT.vendorProduct(["VP": "x+y"]))
        XCTAssertNil(MatterTXT.vendorProduct([:]))
    }

    func test_onlyASCIIDigitsCount() {
        XCTAssertNil(MatterTXT.vendorProduct(["VP": "+4874"]))
        XCTAssertNil(MatterTXT.vendorProduct(["VP": "4874++1"]))
        XCTAssertNil(MatterTXT.vendorProduct(["VP": "4874+-1"]))
        XCTAssertNil(MatterTXT.vendorProduct(["VP": "\u{0664}874"]))
        XCTAssertNil(MatterTXT.vendorProduct(["VP": "4874+\u{FF11}"]))
        XCTAssertEqual(MatterTXT.vendorProduct(["VP": " 4874+1 "])?.productID, 1)
    }
}
