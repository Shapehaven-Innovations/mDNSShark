import XCTest
@testable import DeviceFingerprint

final class BannerHeuristicTests: XCTestCase {
    func test_dropbearSSHBanner_guessesEmbeddedLinux() {
        let guess = guessFromBanner("SSH-2.0-dropbear_2019.78")
        XCTAssertEqual(guess.os, "Linux (embedded, likely)")
    }

    func test_openSSHDebianBanner_guessesLinuxAndDebianHint() {
        let guess = guessFromBanner("SSH-2.0-OpenSSH_8.4p1 Debian-5")
        XCTAssertEqual(guess.os, "Linux (likely)")
    }

    func test_synologyServerHeader_guessesManufacturer() {
        let guess = guessFromBanner("HTTP/1.1 200 OK\r\nServer: Synology/DSM")
        XCTAssertEqual(guess.manufacturer, "Synology")
    }

    func test_unrecognizedBanner_returnsAllNil() {
        let guess = guessFromBanner("garbage bytes \u{0001}\u{0002}")
        XCTAssertNil(guess.os)
        XCTAssertNil(guess.manufacturer)
    }

    func test_emptyBanner_returnsAllNil() {
        let guess = guessFromBanner("")
        XCTAssertNil(guess.os)
        XCTAssertNil(guess.manufacturer)
    }
}
