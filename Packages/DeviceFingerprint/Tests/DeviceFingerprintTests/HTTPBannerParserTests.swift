import XCTest
@testable import DeviceFingerprint

final class HTTPBannerParserTests: XCTestCase {
    func test_wellFormedResponse_allThreeFieldsPresent() {
        let raw = """
        HTTP/1.1 401 Unauthorized\r
        Server: lighttpd/1.4.45\r
        WWW-Authenticate: Basic realm="NETGEAR R7000"\r
        Content-Type: text/html\r
        \r
        <html><head><title>401 Authorization Required</title></head><body>nope</body></html>
        """.data(using: .utf8)!

        let info = HTTPBannerParser.parse(raw)
        XCTAssertEqual(info?.server, "lighttpd/1.4.45")
        XCTAssertEqual(info?.title, "401 Authorization Required")
        XCTAssertEqual(info?.authRealm, "NETGEAR R7000")
    }

    func test_responseMissingSomeFields() {
        let raw = """
        HTTP/1.1 200 OK\r
        Server: nginx\r
        Content-Type: text/html\r
        \r
        <html><body>No title here, no auth header</body></html>
        """.data(using: .utf8)!

        let info = HTTPBannerParser.parse(raw)
        XCTAssertEqual(info?.server, "nginx")
        XCTAssertNil(info?.title)
        XCTAssertNil(info?.authRealm)
    }

    func test_noHeadersAtAll_justBody() {
        let raw = """
        \r
        <html><head><title>Just A Body</title></head></html>
        """.data(using: .utf8)!

        let info = HTTPBannerParser.parse(raw)
        XCTAssertNil(info?.server)
        XCTAssertNil(info?.authRealm)
        XCTAssertEqual(info?.title, "Just A Body")
    }

    func test_completelyNonHTTPResponse_garbageBytes() {
        let raw = Data([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x01, 0x02, 0x03])
        // Must never crash; either nil or all-nil fields is acceptable.
        let info = HTTPBannerParser.parse(raw)
        if let info = info {
            XCTAssertNil(info.server)
            XCTAssertNil(info.title)
            XCTAssertNil(info.authRealm)
        }
    }

    func test_emptyResponse() {
        let info = HTTPBannerParser.parse(Data())
        XCTAssertNil(info?.server)
        XCTAssertNil(info?.title)
        XCTAssertNil(info?.authRealm)
    }

    func test_lowercaseHeaders_caseInsensitiveMatch() {
        let raw = """
        HTTP/1.1 401 Unauthorized\r
        server: Boa/0.94.14rc21\r
        www-authenticate: Basic realm="TP-LINK Wireless N Router WR841N"\r
        \r
        <html><head><title>lowercase test</title></head></html>
        """.data(using: .utf8)!

        let info = HTTPBannerParser.parse(raw)
        XCTAssertEqual(info?.server, "Boa/0.94.14rc21")
        XCTAssertEqual(info?.authRealm, "TP-LINK Wireless N Router WR841N")
        XCTAssertEqual(info?.title, "lowercase test")
    }
}
