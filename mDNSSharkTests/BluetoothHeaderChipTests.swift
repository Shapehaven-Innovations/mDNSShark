// mDNSSharkTests/BluetoothHeaderChipTests.swift
import Testing
@testable import mDNSShark

@Suite("Bluetooth header chip") struct BluetoothHeaderChipTests {
    @Test func hiddenWhenNothingNearbyAndIdle() { #expect(BluetoothHeaderChip.text(nearby: 0, isScanning: false) == nil) }
    @Test func scanningTextWins() { #expect(BluetoothHeaderChip.text(nearby: 0, isScanning: true) == "Bluetooth scanning…"); #expect(BluetoothHeaderChip.text(nearby: 4, isScanning: true) == "Bluetooth scanning…") }
    @Test func scanningValue() {
        #expect(BluetoothHeaderChip.accessibilityValue(isScanning: true) == "Scanning")
        #expect(BluetoothHeaderChip.accessibilityValue(isScanning: false) == "")
    }
    @Test func countText() { #expect(BluetoothHeaderChip.text(nearby: 4, isScanning: false) == "4 Bluetooth nearby") }
    @Test func accessibility() { #expect(BluetoothHeaderChip.accessibilityLabel(nearby: 1) == "1 Bluetooth device nearby, from advertisements"); #expect(BluetoothHeaderChip.hint == "Opens Devices filtered to Bluetooth") }
}
