import Foundation

enum BluetoothScanPolicy {
    /// The header Scan adds Bluetooth only when access is already allowed and the setting is on, so it never shows the system prompt.
    static func headerScanStartsBluetooth(authorization: BLEAuthorization, includeSetting: Bool) -> Bool {
        authorization == .allowed && includeSetting
    }
}
