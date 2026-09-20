import XCTest
@testable import DeviceFingerprint

final class SSDPDeviceDescriptionTests: XCTestCase {
    func test_parsesManufacturerModelSerial() {
        let xml = """
        <?xml version="1.0"?>
        <root xmlns="urn:schemas-upnp-org:device-1-0">
          <device>
            <manufacturer>Synology Inc.</manufacturer>
            <modelName>DS920+</modelName>
            <serialNumber>ABC123</serialNumber>
          </device>
        </root>
        """.data(using: .utf8)!

        let info = SSDPDeviceDescription.parse(xml)
        XCTAssertEqual(info?.manufacturer, "Synology Inc.")
        XCTAssertEqual(info?.modelName, "DS920+")
        XCTAssertEqual(info?.serialNumber, "ABC123")
    }

    func test_missingFields_areNilNotCrash() {
        let xml = "<root><device><modelName>Thing</modelName></device></root>".data(using: .utf8)!
        let info = SSDPDeviceDescription.parse(xml)
        XCTAssertNil(info?.manufacturer)
        XCTAssertEqual(info?.modelName, "Thing")
    }

    func test_malformedXML_returnsNil() {
        XCTAssertNil(SSDPDeviceDescription.parse(Data("not xml at all".utf8)))
    }

    func test_nestedEmbeddedDevices_rootDeviceValuesWin() {
        // Modeled on the UPnP Internet Gateway Device template: a router's
        // root <device> is followed by <deviceList> containing embedded
        // sub-devices (WANDevice, WANConnectionDevice) each with their own
        // manufacturer/modelName/serialNumber. The root device's values must
        // win, not the last one seen in document order.
        let xml = """
        <?xml version="1.0"?>
        <root xmlns="urn:schemas-upnp-org:device-1-0">
          <device>
            <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
            <manufacturer>Netgear</manufacturer>
            <modelName>Nighthawk R7000</modelName>
            <serialNumber>ROOT-SERIAL-1</serialNumber>
            <deviceList>
              <device>
                <deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
                <manufacturer>Embedded WAN Inc.</manufacturer>
                <modelName>WANDevice</modelName>
                <serialNumber>WAN-SERIAL-2</serialNumber>
                <deviceList>
                  <device>
                    <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
                    <manufacturer>Embedded WANConnection Inc.</manufacturer>
                    <modelName>WANConnectionDevice</modelName>
                    <serialNumber>WANCONN-SERIAL-3</serialNumber>
                  </device>
                </deviceList>
              </device>
            </deviceList>
          </device>
        </root>
        """.data(using: .utf8)!

        let info = SSDPDeviceDescription.parse(xml)
        XCTAssertEqual(info?.manufacturer, "Netgear")
        XCTAssertEqual(info?.modelName, "Nighthawk R7000")
        XCTAssertEqual(info?.serialNumber, "ROOT-SERIAL-1")
    }
}
