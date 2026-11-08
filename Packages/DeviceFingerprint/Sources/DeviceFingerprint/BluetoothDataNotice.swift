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
