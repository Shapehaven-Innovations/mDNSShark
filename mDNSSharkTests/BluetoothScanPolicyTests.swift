import Testing
import Foundation
@testable import mDNSShark

@Suite("Bluetooth scan policy") struct BluetoothScanPolicyTests {
    @Test func onlyAllowedWithSettingOn() {
        #expect(BluetoothScanPolicy.headerScanStartsBluetooth(authorization: .allowed, includeSetting: true))
        for a in [BLEAuthorization.undetermined, .denied, .restricted] { #expect(!BluetoothScanPolicy.headerScanStartsBluetooth(authorization: a, includeSetting: true)) }
        #expect(!BluetoothScanPolicy.headerScanStartsBluetooth(authorization: .allowed, includeSetting: false))
    }
    @Test func settingDefaultsOn() {
        let d = UserDefaults(suiteName: "BluetoothScanPolicyTests.\(UUID().uuidString)")!
        #expect(SharedSettings.includeBluetoothInScan(in: d)); d.set(false, forKey: "includeBluetoothInScan"); #expect(!SharedSettings.includeBluetoothInScan(in: d))
    }
}
