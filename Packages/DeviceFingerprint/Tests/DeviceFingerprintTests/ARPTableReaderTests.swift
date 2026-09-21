import XCTest
@testable import DeviceFingerprint

final class ARPTableReaderTests: XCTestCase {
    // Smoke test only: `readEntries()` hits the real kernel routing table,
    // so its content is host-dependent (and on iOS 18-26 / macOS without the
    // iOS 27 entitlement every `macAddress` will be nil) — this only proves
    // the sysctl(2) call sequence itself doesn't crash or return malformed
    // data ARPTableParser can't handle. Real MAC-resolution behavior is
    // verified against synthetic buffers in ARPTableParserTests, and against
    // real hardware on an iOS 27 test device per todo.md item 4.
    func test_readEntries_doesNotCrash_andReturnsWellFormedEntries() {
        let entries = ARPTableReader.readEntries()
        for entry in entries {
            XCTAssertFalse(entry.ipAddress.isEmpty)
            if let mac = entry.macAddress {
                XCTAssertEqual(mac.count, 17, "expected xx:xx:xx:xx:xx:xx, got \(mac)")
            }
        }
    }

    func test_macAddress_forUnknownIP_returnsNil() {
        XCTAssertNil(ARPTableReader.macAddress(forIP: "203.0.113.254"))
    }
}
