import XCTest
@testable import DeviceFingerprint

final class CameraHintTests: XCTestCase {
    func test_cameraOnlyVendorNames_match() {
        for name in ["Hangzhou Hikvision Digital Technology Co.,Ltd.", "Zhejiang Dahua Technology Co., Ltd.",
                     "Amcrest Technologies", "Axis Communications AB", "Ring LLC", "Blink by Amazon", "Arlo Technology"] {
            XCTAssertTrue(CameraHint.isCameraVendor(name), name)
        }
    }

    func test_licensePlateCameraVendors_matchAnchored_andGenetecTattileDoNot() {
        for name in ["Flock Safety", "Adaptive Recognition Hungary, Inc"] { XCTAssertTrue(CameraHint.isCameraVendor(name), name) }
        for name in ["Genetec Inc.", "Tattile SRL", "Not Flock Safety", "Recognition Adaptive"] { XCTAssertFalse(CameraHint.isCameraVendor(name), name) }
    }

    func test_unrelatedVendorsContainingShortWords_doNotMatch() {
        for name in ["Carlo Gavazzi Controls SpA", "enblink Technology", "Align Engineering LLC", "TP-Link Technologies", "Ubiquiti Inc", "Apple, Inc."] {
            XCTAssertFalse(CameraHint.isCameraVendor(name), name)
        }
    }

    func test_cameraServiceTypes_matchFullAndBareForms() {
        XCTAssertTrue(CameraHint.isCameraServiceType("_axis-video._tcp"))
        XCTAssertTrue(CameraHint.isCameraServiceType("_rtsp._tcp"))
        XCTAssertTrue(CameraHint.isCameraServiceType("_cctv"))
        XCTAssertFalse(CameraHint.isCameraServiceType("_http._tcp"))
        XCTAssertFalse(CameraHint.isCameraServiceType("_airplay._tcp"))
    }

    func test_instanceNames() {
        XCTAssertTrue(CameraHint.isCameraInstanceName("AMC060E7AF0A5BCE81"))
        XCTAssertTrue(CameraHint.isCameraInstanceName("HIKVISION-DS-2CD2143G0"))
        XCTAssertFalse(CameraHint.isCameraInstanceName("AMC Studio Mac"))
        XCTAssertFalse(CameraHint.isCameraInstanceName("AMC12"))
    }

    func test_hapCategory_onlyCameraAndDoorbell() {
        XCTAssertTrue(CameraHint.isCameraHAPCategory("17"))
        XCTAssertTrue(CameraHint.isCameraHAPCategory("18"))
        XCTAssertFalse(CameraHint.isCameraHAPCategory("11"))
        XCTAssertFalse(CameraHint.isCameraHAPCategory("2"))
    }

    func test_matterDeviceType_cameraFamilyOnly() {
        XCTAssertTrue(CameraHint.isCameraMatterDeviceType("322"))
        XCTAssertTrue(CameraHint.isCameraMatterDeviceType("323"))
        XCTAssertFalse(CameraHint.isCameraMatterDeviceType("326"))
        XCTAssertFalse(CameraHint.isCameraMatterDeviceType("327"))
        XCTAssertFalse(CameraHint.isCameraMatterDeviceType("abc"))
    }

    func test_cameraBanners_guessManufacturer() {
        XCTAssertEqual(guessFromBanner("Server: App-webs/").manufacturer, "Hikvision")
        XCTAssertEqual(guessFromBanner("Server: DNVRS-Webs").manufacturer, "Hikvision")
        XCTAssertEqual(guessFromBanner("Server: uc-httpd 1.0.0").manufacturer, "Xiongmai")
        XCTAssertEqual(guessFromBanner("<title>Amcrest Web</title>").manufacturer, "Amcrest")
        XCTAssertEqual(guessFromBanner("Server: UniFi").manufacturer, "Ubiquiti")
    }

    func test_gatewayAndSerialServerBanners_guessManufacturerOnly() {
        XCTAssertEqual(guessFromBanner("Server: CradlepointHTTPService/1.0").manufacturer, "Cradlepoint")
        XCTAssertEqual(guessFromBanner("<title>CradlePoint MBR1400 Gateway</title>").manufacturer, "Cradlepoint")
        XCTAssertEqual(guessFromBanner("Server: Sierra Wireless Inc, Embedded Server").manufacturer, "Sierra Wireless")
        XCTAssertEqual(guessFromBanner("realm=\"Modem@AirLink.com\"").manufacturer, "Sierra Wireless")
        XCTAssertEqual(guessFromBanner("Welcome to the ALEOS Environment").manufacturer, "Sierra Wireless")
        XCTAssertEqual(guessFromBanner("Server: MoxaHttp/1.0").manufacturer, "Moxa")
        XCTAssertEqual(guessFromBanner("<title>NPort Web Console</title>").manufacturer, "Moxa")
        XCTAssertEqual(guessFromBanner("SSH-2.0-moxa_1.0").manufacturer, "Moxa")
        XCTAssertEqual(guessFromBanner("<title>Lantronix Web Manager</title>").manufacturer, "Lantronix")
        XCTAssertEqual(guessFromBanner("<title>Digi Configuration and Management</title>").manufacturer, "Digi")
        XCTAssertEqual(guessFromBanner("<title>TransPort WR21 Configuration</title>").manufacturer, "Digi")
        XCTAssertNil(guessFromBanner("Server: CradlepointHTTPService/1.0").os)
        XCTAssertNil(guessFromBanner("Server: MoxaHttp/1.0").os)
        XCTAssertEqual(guessFromBanner("Server: AsusWRT").manufacturer, "ASUS")
    }
}
