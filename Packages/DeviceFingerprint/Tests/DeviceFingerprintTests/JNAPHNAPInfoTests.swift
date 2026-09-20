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

    func test_jnapNonOKResultWithOutput_returnsNil() {
        // Guards against accepting a 200 response shaped like the envelope
        // but where the device itself reported failure.
        let json = """
        {"result":"ERROR","output":{"manufacturer":"Linksys","modelNumber":"MX5500"}}
        """.data(using: .utf8)!
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
        <GetDeviceSettingsResult>OK</GetDeviceSettingsResult>
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

    func test_hnapNonOKResult_returnsNil() {
        let xml = """
        <GetDeviceSettingsResponse xmlns="http://purenetworks.com/HNAP1/">
        <GetDeviceSettingsResult>ERROR</GetDeviceSettingsResult>
        <ModelName>DIR-885L</ModelName>
        </GetDeviceSettingsResponse>
        """.data(using: .utf8)!
        XCTAssertNil(JNAPHNAPParser.parseHNAP(xml))
    }

    func test_hnapMissingResult_returnsNil() {
        // No GetDeviceSettingsResult element at all - result defaults to nil,
        // which must not be treated as success.
        let xml = """
        <GetDeviceSettingsResponse xmlns="http://purenetworks.com/HNAP1/">
        <ModelName>DIR-885L</ModelName>
        </GetDeviceSettingsResponse>
        """.data(using: .utf8)!
        XCTAssertNil(JNAPHNAPParser.parseHNAP(xml))
    }

    func test_hnapDeviceNameAlone_neverUsedAsModelName() {
        // DeviceName is the user-editable host name, not a model - even
        // with GetDeviceSettingsResult == OK, a DeviceName-only response
        // carries no real identity and must return nil, not fabricate a
        // modelName from it.
        let xml = """
        <GetDeviceSettingsResponse xmlns="http://purenetworks.com/HNAP1/">
        <GetDeviceSettingsResult>OK</GetDeviceSettingsResult>
        <DeviceName>Living Room</DeviceName>
        </GetDeviceSettingsResponse>
        """.data(using: .utf8)!
        XCTAssertNil(JNAPHNAPParser.parseHNAP(xml))
    }

    func test_hnapMalformedXML_returnsNil() {
        let xml = "not xml".data(using: .utf8)!
        XCTAssertNil(JNAPHNAPParser.parseHNAP(xml))
    }

    func test_hnapEmptyDocument_returnsNil() {
        let xml = "<GetDeviceSettingsResponse xmlns=\"http://purenetworks.com/HNAP1/\"><GetDeviceSettingsResult>OK</GetDeviceSettingsResult></GetDeviceSettingsResponse>".data(using: .utf8)!
        XCTAssertNil(JNAPHNAPParser.parseHNAP(xml))
    }
}
