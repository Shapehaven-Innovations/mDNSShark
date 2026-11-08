import Testing
import Foundation
@testable import mDNSShark

@Suite("Bluetooth usage string") struct BluetoothUsageStringTests {
    @Test func plistCarriesASpecificPurpose() {
        let s = Bundle.main.object(forInfoDictionaryKey: "NSBluetoothAlwaysUsageDescription") as? String
        #expect(s != nil)
        let text = s
        #expect(text?.contains("advertisements") == true)
        #expect(text?.contains("never connects") == true)
        #expect(text?.contains("nothing leaves your phone") == true)
        #expect(text?.lowercased().contains("pair") == false)
        #expect(text?.contains("MAC") == false)
    }
}
