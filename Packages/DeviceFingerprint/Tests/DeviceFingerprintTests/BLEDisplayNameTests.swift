import XCTest
@testable import DeviceFingerprint

final class BLEDisplayNameTests: XCTestCase {
    func test_sanitizeStripsControlBidiAndZeroWidth() {
        XCTAssertEqual(BLEDisplayName.sanitized("\u{202E}Sonos\u{200B} Roam\u{0007}\u{2066}"), "Sonos Roam")
    }
    func test_sanitizeTruncatesTo64Scalars() { XCTAssertEqual(BLEDisplayName.sanitized(String(repeating: "a", count: 200))?.unicodeScalars.count, 64) }
    func test_emptyAndWhitespaceAreNil() { XCTAssertNil(BLEDisplayName.sanitized("  \t ")); XCTAssertNil(BLEDisplayName.sanitized(nil)) }
    func test_emojiAndCJKSurvive() { XCTAssertEqual(BLEDisplayName.sanitized("Taro の iPhone 📱"), "Taro の iPhone 📱") }
}
