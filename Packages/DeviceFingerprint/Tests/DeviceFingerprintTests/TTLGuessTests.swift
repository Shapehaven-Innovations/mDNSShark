import XCTest
@testable import DeviceFingerprint

final class TTLGuessTests: XCTestCase {
    func test_ttl64_guessesLinuxLikely() {
        XCTAssertEqual(guessOSFamily(ttl: 64), "Linux/Unix-like (likely)")
    }

    func test_ttlSlightlyBelow64_stillWithinHopBudget_guessesLinuxLikely() {
        // Real-world TTLs are (initial - hop count), so an exact 64 is rare;
        // anything from 50 to 64 is treated as "started at 64".
        XCTAssertEqual(guessOSFamily(ttl: 60), "Linux/Unix-like (likely)")
    }

    func test_ttl128_guessesWindowsLikely() {
        XCTAssertEqual(guessOSFamily(ttl: 128), "Windows (likely)")
    }

    func test_ttl255_guessesNetworkGearLikely() {
        XCTAssertEqual(guessOSFamily(ttl: 255), "Cisco/Solaris (likely)")
    }

    func test_ttlBelowAnyKnownBand_returnsNil() {
        XCTAssertNil(guessOSFamily(ttl: 10))
    }
}
