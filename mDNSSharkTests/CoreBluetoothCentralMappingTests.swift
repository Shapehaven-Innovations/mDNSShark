import Testing
import Foundation
import CoreBluetooth
import DeviceFingerprint
@testable import mDNSShark

@Suite("CoreBluetoothCentral advertisement mapping") struct CoreBluetoothCentralMappingTests {
    @Test func mapsEveryAdvertisementKey() {
        let adv: [String: Any] = [CBAdvertisementDataLocalNameKey: "Tile", CBAdvertisementDataManufacturerDataKey: Data([0x4C, 0x00]),
            CBAdvertisementDataServiceUUIDsKey: [CBUUID(string: "FEED")], CBAdvertisementDataOverflowServiceUUIDsKey: [CBUUID(string: "180F")],
            CBAdvertisementDataServiceDataKey: [CBUUID(string: "FEAA"): Data([0x10])], CBAdvertisementDataTxPowerLevelKey: NSNumber(value: -4),
            CBAdvertisementDataIsConnectable: NSNumber(value: true)]
        let s = CoreBluetoothCentral.sighting(identifier: UUID(), advertisement: adv, rssi: NSNumber(value: -70), at: Date())
        #expect(s.fields.localName == "Tile" && s.fields.serviceUUIDs == ["FEED", "180F"] && s.fields.serviceData["FEAA"] == Data([0x10]) && s.fields.txPower == -4 && s.fields.isConnectable == true && s.rssi == -70)
        #expect(s.fields.manufacturerData == Data([0x4C, 0x00]))
    }

    @Test func cachedNameStaysSeparateFromLocalName() {
        let s = CoreBluetoothCentral.sighting(identifier: UUID(), advertisement: [CBAdvertisementDataLocalNameKey: "Adv"], rssi: NSNumber(value: -60), at: Date(), cachedName: "Cached")
        #expect(s.fields.localName == "Adv" && s.fields.cachedName == "Cached")
    }

    @Test func missingKeysAreNil() {
        let id = UUID()
        let at = Date(timeIntervalSince1970: 1_800_000_000)
        let s = CoreBluetoothCentral.sighting(identifier: id, advertisement: [:], rssi: NSNumber(value: -90), at: at)
        #expect(s.identifier == id && s.at == at && s.rssi == -90)
        #expect(s.fields.localName == nil && s.fields.manufacturerData == nil && s.fields.txPower == nil && s.fields.isConnectable == nil)
        #expect(s.fields.serviceUUIDs.isEmpty && s.fields.serviceData.isEmpty)
    }

    @Test func wrongValueTypesAreIgnored() {
        let adv: [String: Any] = [CBAdvertisementDataLocalNameKey: 42, CBAdvertisementDataManufacturerDataKey: "not data",
                                  CBAdvertisementDataServiceUUIDsKey: ["FEED"], CBAdvertisementDataServiceDataKey: ["FEAA": 1]]
        let s = CoreBluetoothCentral.sighting(identifier: UUID(), advertisement: adv, rssi: NSNumber(value: -50), at: Date())
        #expect(s.fields.localName == nil && s.fields.manufacturerData == nil)
        #expect(s.fields.serviceUUIDs.isEmpty && s.fields.serviceData.isEmpty)
    }

    @Test func hexFormatting() {
        #expect(HexFormatting.hex(Data([0x4C, 0x00, 0x10])) == "4C 00 10")
        #expect(HexFormatting.hex(Data([0x4C, 0x00, 0x10, 0x05])) == "4C 00 10 05")
        #expect(HexFormatting.hex(Data()) == "")
        // The lookup table prints exactly what per-byte String(format:) printed.
        let all = Data((0...255).map(UInt8.init))
        #expect(HexFormatting.hex(all) == all.map { String(format: "%02X", $0) }.joined(separator: " "))
    }

    @Test func gattValuesAreSanitized() {
        var info = BLEDeviceInfo()
        CoreBluetoothCentral.apply(Data("Acme\u{0}\u{202E}  Corp\n".utf8), characteristic: "2A29", to: &info)
        CoreBluetoothCentral.apply(Data([0xFF, 0xFE]), characteristic: "2A24", to: &info)
        CoreBluetoothCentral.apply(Data("1.2.3".utf8), characteristic: "2A26", to: &info)
        CoreBluetoothCentral.apply(Data([101]), characteristic: "2A19", to: &info)
        #expect(info.manufacturer == "Acme Corp")
        #expect(info.firmware == "1.2.3")
        #expect(info.batteryPercent == nil)
        CoreBluetoothCentral.apply(Data([87]), characteristic: "2A19", to: &info)
        #expect(info.batteryPercent == 87)
        CoreBluetoothCentral.apply(Data("ignored".utf8), characteristic: "2A00", to: &info)
        #expect(info.model == "\u{FFFD}\u{FFFD}" || info.model == nil)
    }

    @Test func powerStateMapping() {
        #expect(BLEPowerState(.poweredOn) == .poweredOn)
        #expect(BLEPowerState(.poweredOff) == .poweredOff)
        #expect(BLEPowerState(.unsupported) == .unsupported)
        #expect(BLEPowerState(.resetting) == .resetting)
        #expect(BLEPowerState(.unknown) == .unknown)
        #expect(BLEPowerState(.unauthorized) == .unknown)
    }
}
