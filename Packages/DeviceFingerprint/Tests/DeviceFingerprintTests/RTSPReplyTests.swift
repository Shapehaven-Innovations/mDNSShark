import XCTest
@testable import DeviceFingerprint

final class RTSPReplyTests: XCTestCase {
    func test_requestBytes_areExactlyOneOptions() {
        let expected = "OPTIONS rtsp://192.168.1.20:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        XCTAssertEqual(RTSPReply.optionsRequest(ip: "192.168.1.20"), Data(expected.utf8))
    }

    func test_requestBytes_bracketIPv6Literals() {
        XCTAssertEqual(RTSPReply.optionsRequest(ip: "2001:db8::7", port: 554), Data("OPTIONS rtsp://[2001:db8::7]:554/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".utf8))
    }

    func test_noStreamingMethodsExistInTheRTSPSources() throws {
        let sources = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/DeviceFingerprint")
        let scanner = sources.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("mDNSShark/Discovery/ScannedPort.swift")
        let files = ["RTSPReply.swift", "CameraPortBanner.swift", "BannerHeuristic.swift"].map { sources.appendingPathComponent($0) } + [scanner]
        let pattern = try NSRegularExpression(pattern: "\\b(DESCRIBE|SETUP|PLAY|PAUSE|RECORD|TEARDOWN|SET_PARAMETER|ANNOUNCE|REDIRECT|GET_PARAMETER)\\b")
        for file in files {
            let text = try String(contentsOf: file, encoding: .utf8)
            XCTAssertNil(pattern.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)), file.lastPathComponent)
        }
    }

    func test_parsesDigestChallenge() throws {
        let raw = "RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nServer: Dahua Rtsp Server\r\nWWW-Authenticate: Digest realm=\"Login to 4K0123\", nonce=\"abc\"\r\n\r\n"
        let reply = try XCTUnwrap(RTSPReply.parse(Data(raw.utf8)))
        XCTAssertEqual(reply.statusCode, 401)
        XCTAssertEqual(reply.statusLine, "RTSP/1.0 401 Unauthorized")
        XCTAssertEqual(reply.server, "Dahua Rtsp Server")
        XCTAssertEqual(reply.wwwAuthenticate, ["Digest realm=\"Login to 4K0123\", nonce=\"abc\""])
        XCTAssertEqual(guessFromBanner(reply.bannerText).manufacturer, "Dahua")
    }

    func test_parsesPublicAndMixedCaseNames() throws {
        let reply = try XCTUnwrap(RTSPReply.parse("RTSP/1.0 200 OK\r\nserver:  Hipcam RealServer/V1.0 \r\nPUBLIC: OPTIONS, TEARDOWN\r\n\r\n"))
        XCTAssertEqual(reply.statusCode, 200)
        XCTAssertEqual(reply.server, "Hipcam RealServer/V1.0")
        XCTAssertEqual(reply.publicMethods, "OPTIONS, TEARDOWN")
        XCTAssertEqual(reply.bannerText, "RTSP/1.0 200 OK | Server: Hipcam RealServer/V1.0 | Public: OPTIONS, TEARDOWN")
    }

    func test_toleratesBareNewlinesAndMissingCode() throws {
        let reply = try XCTUnwrap(RTSPReply.parse("RTSP/1.0\nServer: x\n"))
        XCTAssertNil(reply.statusCode)
        XCTAssertEqual(reply.server, "x")
    }

    func test_malformedInput_returnsNilWithoutCrashing() {
        XCTAssertNil(RTSPReply.parse(Data()))
        XCTAssertNil(RTSPReply.parse(""))
        XCTAssertNil(RTSPReply.parse(Data([0xff, 0xfe, 0x00, 0x01, 0x80])))
        XCTAssertNil(RTSPReply.parse("HTTP/1.1 200 OK\r\n\r\n"))
        XCTAssertNotNil(RTSPReply.parse("RTSP/1.0 4"))
        XCTAssertNil(RTSPReply.parse("RTSP"))
        let garbage = Data((0..<4096).map { UInt8(truncatingIfNeeded: $0 &* 31) })
        _ = RTSPReply.parse(garbage)
    }

    func test_oneMegabyteInput_isBounded() throws {
        var raw = Data("RTSP/1.0 200 OK\r\nServer: big\r\n".utf8)
        raw.append(Data(repeating: UInt8(ascii: "a"), count: 1_000_000))
        let reply = try XCTUnwrap(RTSPReply.parse(raw))
        XCTAssertEqual(reply.server, "big")
        XCTAssertNil(RTSPReply.parse(Data(repeating: 0, count: 1_000_000)))
    }

    func test_cameraFingerprints() {
        XCTAssertEqual(guessFromBanner("RTSP/1.0 401 Unauthorized | WWW-Authenticate: Digest realm=\"Hikvision\"").manufacturer, "Hikvision")
        XCTAssertEqual(guessFromBanner("Server: Dahua Rtsp Server").manufacturer, "Dahua")
        XCTAssertEqual(guessFromBanner("Server: AvigilonOnvifNvt/1.0").manufacturer, "Avigilon")
        XCTAssertEqual(guessFromBanner("Server: H264DVR 1.0").manufacturer, "Xiongmai")
        XCTAssertNil(guessFromBanner("Server: Hipcam RealServer/V1.0").manufacturer)
        XCTAssertNil(guessFromBanner("Server: HiIpcam/V100R003 VodServer/1.0.0").manufacturer)
        XCTAssertNil(guessFromBanner("Server: Indigo-Security/1.0").manufacturer)
        XCTAssertNil(guessFromBanner("Server: GStreamer RTSP server").manufacturer)
    }

    func test_port8000_hikvisionBinaryBanner() {
        let banner = Data([0, 0, 0, 0x10, 0, 0, 0, 0x1e, 0, 0, 0, 0x1e, 0, 0, 0, 0])
        XCTAssertEqual(CameraPortBanner.label(port8000: banner), "Hikvision camera control port (binary banner)")
        XCTAssertEqual(CameraPortBanner.label(port8000: banner + Data([1, 2, 3])), CameraPortBanner.hikvisionControlLabel)
        XCTAssertEqual(guessFromBanner(CameraPortBanner.hikvisionControlLabel).manufacturer, "Hikvision")
    }

    func test_port8000_nonMatching_truncated_andZeroDVariant() {
        XCTAssertNil(CameraPortBanner.label(port8000: Data([0, 0, 0, 0x10, 0, 0, 0, 0x1e])))
        XCTAssertNil(CameraPortBanner.label(port8000: Data()))
        XCTAssertNil(CameraPortBanner.label(port8000: Data("HTTP/1.1 200 OK".utf8)))
        XCTAssertNil(CameraPortBanner.label(port8000: Data([0, 0, 0, 0x10, 0, 0, 0, 0x0d, 0, 0, 0, 0x0d, 0, 0, 0, 0])))
    }

    func test_rowLooksLikeCamera() {
        XCTAssertTrue(CameraHint.rowLooksLikeCamera(manufacturer: nil, serviceType: "_rtsp._tcp", serviceName: "x", txtRecords: nil))
        XCTAssertTrue(CameraHint.rowLooksLikeCamera(manufacturer: nil, serviceType: "_hap._tcp", serviceName: "x", txtRecords: ["ci": "17"]))
        XCTAssertTrue(CameraHint.rowLooksLikeCamera(manufacturer: "Dahua Technology", serviceType: "_http._tcp", serviceName: "x", txtRecords: nil))
        XCTAssertFalse(CameraHint.rowLooksLikeCamera(manufacturer: "Apple, Inc.", serviceType: "_airplay._tcp", serviceName: "TV", txtRecords: [:]))
    }
}
