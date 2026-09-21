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

    func test_linksysServerHeader_guessesManufacturer() {
        let guess = guessFromBanner("HTTP/1.1 200 OK\r\nServer: Linksys-EA7500")
        XCTAssertEqual(guess.manufacturer, "Linksys")
    }

    func test_tplinkServerHeader_guessesManufacturer() {
        let guess = guessFromBanner("HTTP/1.1 200 OK\r\nServer: TP-LINK Router")
        XCTAssertEqual(guess.manufacturer, "TP-Link")
    }

    func test_glInetTitle_guessesManufacturer() {
        let guess = guessFromBanner("<html><title>GL.iNet Admin Panel</title></html>")
        XCTAssertEqual(guess.manufacturer, "GL.iNet")
    }

    func test_luciTitleWithoutVendor_guessesOpenWrtOSOnly() {
        let guess = guessFromBanner("<html><title>LuCI - OpenWrt</title></html>")
        XCTAssertEqual(guess.os, "Linux (OpenWrt, likely)")
        XCTAssertNil(guess.manufacturer)
    }

    func test_luciTitleWithGlInet_bothManufacturerAndOSSet() {
        let guess = guessFromBanner("<title>GL.iNet LuCI</title>")
        XCTAssertEqual(guess.manufacturer, "GL.iNet")
        XCTAssertEqual(guess.os, "Linux (OpenWrt, likely)")
    }

    func test_asuswrtServerHeader_guessesManufacturer() {
        let guess = guessFromBanner("Server: ASUSWRT-Merlin")
        XCTAssertEqual(guess.manufacturer, "ASUS")
    }

    func test_netgearTitle_guessesManufacturer() {
        let guess = guessFromBanner("<title>NETGEAR Router R7000</title>")
        XCTAssertEqual(guess.manufacturer, "Netgear")
    }

    func test_tplinkAlternateSpelling_guessesManufacturer() {
        let guess = guessFromBanner("Server: tplink-httpd")
        XCTAssertEqual(guess.manufacturer, "TP-Link")
    }

    func test_glInetHyphenSpelling_guessesManufacturer() {
        let guess = guessFromBanner("<title>gl-inet router</title>")
        XCTAssertEqual(guess.manufacturer, "GL.iNet")
    }

    /// Real GL-MT6000 hardware response: generic Server/Title, only
    /// "gl-ui" (GL.iNet's own admin-UI product name) in the page body.
    func test_glUIBodyMarkerWithGenericServerAndTitle_guessesManufacturer() {
        let guess = guessFromBanner(
            "Server: nginx/1.26.1 | Title: Admin Panel | " +
            "<noscript>We're sorry but gl-ui doesn't work properly without JavaScript enabled.</noscript>"
        )
        XCTAssertEqual(guess.manufacturer, "GL.iNet")
    }

    // MARK: - Generalized manufacturer -> OS fallback

    func test_glInetWithNoOSSignalInBanner_stillInfersEmbeddedLinux() {
        // No "luci"/"openwrt" string anywhere - matches GL.iNet's real web
        // UI, which carries no OS-naming text at all, only the vendor one.
        let guess = guessFromBanner("Server: nginx/1.26.1 | Title: Admin Panel | gl-ui")
        XCTAssertEqual(guess.manufacturer, "GL.iNet")
        XCTAssertEqual(guess.os, "Linux (embedded, likely)")
    }

    func test_synologyWithNoOSSignal_infersDSM() {
        let guess = guessFromBanner("Server: Synology/DSM")
        XCTAssertEqual(guess.manufacturer, "Synology")
        XCTAssertEqual(guess.os, "DSM (Synology, Linux-based, likely)")
    }

    func test_mikrotikWithNoOSSignal_infersRouterOS() {
        let guess = guessFromBanner("Server: RouterOS")
        XCTAssertEqual(guess.manufacturer, "MikroTik")
        XCTAssertEqual(guess.os, "RouterOS (MikroTik, Linux-based, likely)")
    }

    func test_glInetWithLuciSignal_keepsOpenWrtOSNotGenericFallback() {
        // The specific "luci" match must win over the generic
        // manufacturer-based fallback when both are present.
        let guess = guessFromBanner("<title>GL.iNet LuCI</title>")
        XCTAssertEqual(guess.manufacturer, "GL.iNet")
        XCTAssertEqual(guess.os, "Linux (OpenWrt, likely)")
    }

    func test_unmatchedManufacturer_noGenericOSFallbackApplied() {
        let guess = guessFromBanner("Server: some-random-unrecognized-httpd")
        XCTAssertNil(guess.manufacturer)
        XCTAssertNil(guess.os)
    }

    func test_sshBannerWithLuciSubstring_keepsSSHDerivedOS() {
        let guess = guessFromBanner("SSH-2.0-dropbear luci")
        XCTAssertEqual(guess.os, "Linux (embedded, likely)")
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
