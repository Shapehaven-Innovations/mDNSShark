import XCTest
@testable import DeviceFingerprint

final class CameraHintTests: XCTestCase {
    func test_cameraOnlyVendorNames_match() {
        for name in ["Hangzhou Hikvision Digital Technology Co.,Ltd.", "Zhejiang Dahua Technology Co., Ltd.",
                     "Amcrest Technologies", "Axis Communications AB", "Ring LLC", "Blink by Amazon", "Arlo Technology"] {
            XCTAssertTrue(CameraHint.isCameraVendor(name), name)
        }
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
}
