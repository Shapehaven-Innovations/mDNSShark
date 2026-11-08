// mDNSSharkTests/BluetoothSymbolTests.swift
import Testing
import WidgetSnapshot
@testable import mDNSShark

@Suite("One Bluetooth symbol for every surface")
struct BluetoothSymbolTests {

    @Test("the app and the widget use the same Bluetooth symbol")
    func appAndWidgetAgree() {
        #expect(BluetoothSymbol.name == "wave.3.right")
        #expect(BluetoothSymbol.name == WidgetCopy.bluetoothSymbol)
    }
}
