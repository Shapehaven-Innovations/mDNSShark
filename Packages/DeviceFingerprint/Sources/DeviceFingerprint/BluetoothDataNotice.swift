import Foundation

/// The attribution notice for the bundled Bluetooth company and service name tables.
/// BSD-3-Clause asks that binary distributions reproduce it, so the app shows it in Settings.
public enum BluetoothDataNotice {
    public static let title = "Bluetooth Numbers Database"
    public static let sourceURL = URL(string: "https://github.com/NordicSemiconductor/bluetooth-numbers-database")!
    public static let source = "Nordic Semiconductor ASA"
    public static let licenseName = "BSD 3-Clause"

    /// Full license text from the bundled resource. A short fallback if the resource is missing; never crashes.
    public static let licenseText: String = {
        guard let url = Bundle.module.url(forResource: "bluetooth-numbers-database-LICENSE", withExtension: "txt"),
              let text = try? String(contentsOf: url, encoding: .utf8) else {
            return "Copyright (c) 2019 - 2020, Nordic Semiconductor ASA. BSD 3-Clause License."
        }
        return text
    }()
}

/// One upstream project whose data ships in the bundled lookup tables, with its full license text for Settings > About > Acknowledgements.
public struct DataNotice: Identifiable, Sendable {
    public let title: String
    public let summary: String
    public let sourceURL: URL
    public let licenseName: String
    /// Name of the bundled `.txt` resource holding the upstream license file, copied unchanged.
    public let licenseResource: String

    public var id: String { title }

    /// Full license text from the bundled resource, or a pointer to the source if the resource is missing; never crashes.
    public var licenseText: String {
        guard let url = Bundle.module.url(forResource: licenseResource, withExtension: "txt"),
              let text = try? String(contentsOf: url, encoding: .utf8) else {
            return "\(licenseName). See \(sourceURL.absoluteString)."
        }
        return text
    }

    public static let all: [DataNotice] = [
        DataNotice(title: BluetoothDataNotice.title, summary: "Bluetooth service names.",
                   sourceURL: BluetoothDataNotice.sourceURL, licenseName: "\(BluetoothDataNotice.licenseName) License",
                   licenseResource: "bluetooth-numbers-database-LICENSE"),
        DataNotice(title: "AppleDB", summary: "Apple model identifiers and names.",
                   sourceURL: URL(string: "https://github.com/littlebyteorg/appledb")!, licenseName: "MIT License",
                   licenseResource: "appledb-LICENSE"),
        DataNotice(title: "Home Assistant", summary: "Bluetooth advertisement matchers, from homeassistant/generated/bluetooth.py.",
                   sourceURL: URL(string: "https://github.com/home-assistant/core")!, licenseName: "Apache License 2.0",
                   licenseResource: "home-assistant-LICENSE"),
        DataNotice(title: "xiaomi-ble", summary: "Xiaomi MiBeacon product IDs and names, from src/xiaomi_ble/devices.py.",
                   sourceURL: URL(string: "https://github.com/Bluetooth-Devices/xiaomi-ble")!, licenseName: "Apache License 2.0",
                   licenseResource: "xiaomi-ble-LICENSE"),
    ]
}
