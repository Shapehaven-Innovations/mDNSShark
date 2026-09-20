import XCTest
@testable import DeviceFingerprint

final class JNAPHNAPInfoTests: XCTestCase {
    // MARK: - JNAP

    func test_jnapValidResponse_parsesAllFields() {
        let json = """
        {"result":"OK","output":{"manufacturer":"Linksys","modelNumber":"MX5500","description":"Linksys Velop MX5500","firmwareVersion":"1.0.03.204078"}}
        """.data(using: .utf8)!
        let info = JNAPHNAPParser.parseJNAP(json)
        XCTAssertEqual(info?.vendorName, "Linksys")
        XCTAssertEqual(info?.modelName, "MX5500")
        XCTAssertEqual(info?.modelDescription, "Linksys Velop MX5500")
        XCTAssertEqual(info?.firmwareVersion, "1.0.03.204078")
    }

    func test_jnapMissingOutput_returnsNil() {
        let json = "{\"result\":\"ERROR\"}".data(using: .utf8)!
        XCTAssertNil(JNAPHNAPParser.parseJNAP(json))
    }

    func test_jnapMalformedJSON_returnsNil() {
        let json = "not json".data(using: .utf8)!
        XCTAssertNil(JNAPHNAPParser.parseJNAP(json))
    }

    func test_jnapEmptyOutput_returnsNil() {
        let json = "{\"result\":\"OK\",\"output\":{}}".data(using: .utf8)!
        XCTAssertNil(JNAPHNAPParser.parseJNAP(json))
    }

    // MARK: - HNAP

    func test_hnapValidResponse_parsesAllFields() {
        let xml = """
        <?xml version="1.0" encoding="utf-8"?>
        <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
        <GetDeviceSettingsResponse xmlns="http://purenetworks.com/HNAP1/">
        <VendorName>D-Link</VendorName>
        <ModelName>DIR-885L</ModelName>
        <ModelDescription>AC3150 Ultra Wi-Fi Router</ModelDescription>
        <FirmwareVersion>1.13B04</FirmwareVersion>
        </GetDeviceSettingsResponse>
        </soap:Body>
        </soap:Envelope>
        """.data(using: .utf8)!
        let info = JNAPHNAPParser.parseHNAP(xml)
        XCTAssertEqual(info?.vendorName, "D-Link")
        XCTAssertEqual(info?.modelName, "DIR-885L")
        XCTAssertEqual(info?.modelDescription, "AC3150 Ultra Wi-Fi Router")
        XCTAssertEqual(info?.firmwareVersion, "1.13B04")
    }

    func test_hnapDeviceNameFallback_usedWhenModelNameMissing() {
        let xml = """
        <GetDeviceSettingsResponse xmlns="http://purenetworks.com/HNAP1/">
        <DeviceName>Linksys03472</DeviceName>
        </GetDeviceSettingsResponse>
        """.data(using: .utf8)!
        let info = JNAPHNAPParser.parseHNAP(xml)
        XCTAssertEqual(info?.modelName, "Linksys03472")
    }

    func test_hnapModelNamePresent_deviceNameNotUsed() {
        let xml = """
        <GetDeviceSettingsResponse xmlns="http://purenetworks.com/HNAP1/">
        <ModelName>DIR-885L</ModelName>
        <DeviceName>Linksys03472</DeviceName>
        </GetDeviceSettingsResponse>
        """.data(using: .utf8)!
        let info = JNAPHNAPParser.parseHNAP(xml)
        XCTAssertEqual(info?.modelName, "DIR-885L")
    }

    func test_hnapMalformedXML_returnsNil() {
        let xml = "not xml".data(using: .utf8)!
        XCTAssertNil(JNAPHNAPParser.parseHNAP(xml))
    }

    func test_hnapEmptyDocument_returnsNil() {
        let xml = "<GetDeviceSettingsResponse xmlns=\"http://purenetworks.com/HNAP1/\"></GetDeviceSettingsResponse>".data(using: .utf8)!
        XCTAssertNil(JNAPHNAPParser.parseHNAP(xml))
    }
}
