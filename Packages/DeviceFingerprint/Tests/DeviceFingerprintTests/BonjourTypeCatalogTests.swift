import XCTest
@testable import DeviceFingerprint

final class BonjourTypeCatalogTests: XCTestCase {
    private let legacyTypes = ["_airplay._tcp", "_hap._tcp", "_raop._tcp", "_smb._tcp", "_adisk._tcp", "_octoprint._tcp"]

    func testBrowseTypesHaveNoDuplicates() {
        XCTAssertEqual(Set(BonjourTypeCatalog.browseTypes).count, BonjourTypeCatalog.browseTypes.count)
    }

    func testBrowseTypesMatchShape() {
        for type in BonjourTypeCatalog.browseTypes {
            XCTAssertNotNil(type.wholeMatch(of: BonjourTypeCatalog.legacyTypeShape), type)
            XCTAssertTrue(type.hasSuffix("._tcp") || type.hasSuffix("._udp"), type)
        }
    }

    func testTablesOnlyNameKnownTypes() {
        let known = Set(BonjourTypeCatalog.browseTypes + legacyTypes)
        for key in BonjourTypeCatalog.kinds.keys { XCTAssertTrue(known.contains(key), key) }
    }

    func testCameraKindsComeFromCameraHint() {
        for type in BonjourTypeCatalog.browseTypes where CameraHint.isCameraServiceType(type) {
            XCTAssertEqual(BonjourTypeCatalog.kinds[type], .camera, type)
        }
        XCTAssertEqual(BonjourTypeCatalog.kinds.values.filter { $0 == .camera }.count, 8)
    }

    private func kind(_ type: String, _ name: String = "x", _ txt: [String: String] = [:]) -> DeviceKind? {
        BonjourTypeCatalog.kind(serviceType: type, instanceName: name, txt: txt)
    }

    func testKindTable() {
        XCTAssertEqual(kind("_sonos._tcp"), .audio)
        XCTAssertEqual(kind("_sonos._tcp."), .audio)
        XCTAssertEqual(kind("_hue._tcp"), .smartHome)
        XCTAssertEqual(kind("_qdiscover._tcp"), .nas)
        XCTAssertNil(kind("_meshcop._udp"))
        XCTAssertNil(kind("_matter._tcp"))
    }

    func testHAPCategories() {
        XCTAssertEqual(kind("_hap._tcp", "x", ["ci": "17"]), .camera)
        XCTAssertEqual(kind("_hap._tcp", "x", ["ci": "26"]), .audio)
        XCTAssertEqual(kind("_hap._tcp", "x", ["ci": "31"]), .tv)
        XCTAssertEqual(kind("_hap._tcp", "x", ["ci": "5"]), .smartHome)
        for ci in ["3", "4", "13", "15", "20", "21", "22", "23", "28", "29", "30"] {
            XCTAssertEqual(kind("_hap._tcp", "x", ["ci": ci]), .smartHome, ci)
        }
        XCTAssertEqual(kind("_hap._tcp", "x", ["ci": "34"]), .audio)
        XCTAssertEqual(kind("_hap._tcp", "x", ["ci": "35"]), .tv)
        XCTAssertEqual(kind("_hap._tcp", "x", ["ci": "36"]), .tv)
        XCTAssertNil(kind("_hap._tcp", "x", ["ci": "99"]))
        XCTAssertNil(kind("_hap._tcp"))
    }

    func testMidiAndWhisperplayCarryNoKind() {
        XCTAssertNil(kind("_apple-midi._udp"))
        XCTAssertNil(kind("_amzn-wplay._tcp"))
        XCTAssertTrue(BonjourTypeCatalog.browseTypes.contains("_apple-midi._udp"))
        XCTAssertTrue(BonjourTypeCatalog.browseTypes.contains("_amzn-wplay._tcp"))
    }

    func testMatterCommissionableDeviceType() {
        XCTAssertEqual(kind("_matterc._udp", "x", ["DT": "322"]), .camera)
        XCTAssertEqual(kind("_matterc._udp", "x", ["DT": "257"]), .smartHome)
        XCTAssertNil(kind("_matterc._udp", "x", ["DT": "abc"]))
    }

    func testAlexaTypeOnlyMarksRoomba() {
        XCTAssertEqual(kind("_amzn-alexa._tcp", "roomba-123"), .smartHome)
        XCTAssertNil(kind("_amzn-alexa._tcp", "Echo"))
    }

    func testAudioOnlyAirPlayCaptures() {
        func audio(_ features: String) -> Bool { BonjourTypeCatalog.isAudioOnlyAirPlay(txt: ["features": features]) }
        XCTAssertFalse(audio("0x7F8AD0,0x38BCB46"))
        XCTAssertFalse(audio("0x7F8AD0,0x10BCF46"))
        XCTAssertTrue(audio("0x4A7FCA00,0x3C356BD0"))
        XCTAssertTrue(audio("0x445F8A00,0x1C340"))
        XCTAssertTrue(audio("0x444F8A00"))
        XCTAssertTrue(audio("0x444C0A00"))
        XCTAssertTrue(audio("0x445D0A00,0x1C340"))
    }

    func testAudioOnlyAirPlayEdgeCases() {
        func audio(_ txt: [String: String]) -> Bool { BonjourTypeCatalog.isAudioOnlyAirPlay(txt: txt) }
        XCTAssertFalse(audio(["features": "0x7F8AD0"]))
        XCTAssertTrue(audio(["features": "0x200"]))
        XCTAssertFalse(audio(["features": "0x201"]))
        XCTAssertTrue(audio(["features": "200,1"]))
        XCTAssertFalse(audio(["features": "xyz"]))
        XCTAssertFalse(audio(["features": ""]))
        XCTAssertFalse(audio([:]))
        XCTAssertFalse(audio(["features": "0x200,0x1,0x2"]))
        XCTAssertFalse(audio(["features": "0x200", "manufacturer": "Samsung"]))
        XCTAssertFalse(audio(["features": "0x200", "model": "BRAVIA 4K"]))
        XCTAssertTrue(audio(["features": "0x0", "model": "AudioAccessory5,1"]))
        XCTAssertTrue(audio(["features": "0x0", "model": "AirPort10,115"]))
    }

    func testVendorTXTKeysNameKnownTypes() {
        XCTAssertEqual(BonjourTypeCatalog.vendorTXTKeys["_airplay._tcp"], "manufacturer")
        XCTAssertEqual(BonjourTypeCatalog.vendorTXTKeys["_meshcop._udp"], "vn")
    }

    func testApplianceTypesAreBrowsedWithKinds() {
        let smartHome = ["_mieleathome._tcp", "_dkapi._tcp", "_openevse._tcp", "_rabbitair._udp", "_hwenergy._tcp", "_homewizard._tcp",
                         "_360eye_mqtt._tcp", "_aicu-http._tcp"]
        for type in smartHome {
            XCTAssertTrue(BonjourTypeCatalog.browseTypes.contains(type), type)
            XCTAssertEqual(kind(type), .smartHome, type)
        }
        for type in ["_moonraker._tcp", "_prusalink._tcp"] {
            XCTAssertTrue(BonjourTypeCatalog.browseTypes.contains(type), type)
            XCTAssertEqual(kind(type), .printer, type)
        }
        XCTAssertEqual(kind("_octoprint._tcp"), .printer)
        XCTAssertEqual(kind("_homeconnect._tcp"), .smartHome)
        XCTAssertEqual(BonjourTypeCatalog.browseTypes.filter { $0 == "_homeconnect._tcp" }.count, 1)
    }

    func testSideplayIsEcobeeGated() {
        XCTAssertTrue(BonjourTypeCatalog.browseTypes.contains("_sideplay._tcp"))
        XCTAssertEqual(kind("_sideplay._tcp", "x", ["mdl": "eb-STATe5-01"]), .smartHome)
        XCTAssertEqual(kind("_sideplay._tcp", "x", ["mdl": "Ecobee3"]), .smartHome)
        XCTAssertNil(kind("_sideplay._tcp", "x", ["mdl": "AcmeBox"]))
        XCTAssertNil(kind("_sideplay._tcp"))
    }

    func testHomeKitHubTypeHasNoKind() {
        XCTAssertTrue(BonjourTypeCatalog.browseTypes.contains("_homekit._tcp"))
        XCTAssertNil(kind("_homekit._tcp"))
    }

    func testApplianceVendorTXTKeys() {
        XCTAssertEqual(BonjourTypeCatalog.vendorTXTKeys["_homeconnect._tcp"], "brand")
        XCTAssertEqual(BonjourTypeCatalog.vendorTXTKeys["_octoprint._tcp"], "vendor")
    }

    func testMatterDeviceTypeNames() {
        let expected: [String: String] = [
            "10": "Door Lock", "23": "Solar Power", "24": "Battery Storage", "45": "Air Purifier", "64": "Irrigation System",
            "66": "Water Valve", "112": "Refrigerator", "113": "Temperature Controlled Cabinet", "114": "Room Air Conditioner",
            "115": "Laundry Washer", "116": "Robotic Vacuum Cleaner", "117": "Dishwasher", "120": "Cooktop", "121": "Microwave Oven",
            "122": "Extractor Hood", "123": "Oven", "124": "Laundry Dryer", "125": "Humidity Conditioner", "769": "Thermostat",
            "777": "Heat Pump", "1292": "EVSE", "1295": "Water Heater",
        ]
        for (dt, name) in expected { XCTAssertEqual(BonjourTypeCatalog.matterDeviceTypeName(dt), name, dt) }
        XCTAssertNil(BonjourTypeCatalog.matterDeviceTypeName("99999"))
        XCTAssertNil(BonjourTypeCatalog.matterDeviceTypeName("abc"))
        XCTAssertNil(BonjourTypeCatalog.matterDeviceTypeName(""))
    }
}
