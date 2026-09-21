//  OUIDatabase.swift

import Foundation
import os
import DeviceFingerprint

class OUIDatabase {
    static let shared = OUIDatabase()

    private let logger = Logger(subsystem: "com.mDNSShark", category: "OUIDatabase")
    private let dataset: OUIDataset

    private init() {
        guard let url = Bundle.main.url(forResource: "oui-database", withExtension: "txt"),
              let text = try? String(contentsOf: url, encoding: .utf8) else {
            logger.fault("OUIDatabase: bundled oui-database.txt missing or unreadable — manufacturer lookups will return nil")
            self.dataset = OUIDataset(text: "")
            return
        }
        self.dataset = OUIDataset(text: text)
        self.logger.info("OUIDatabase: loaded bundled dataset from \(url.lastPathComponent)")
    }

    func manufacturer(for oui: String) -> String? {
        dataset.manufacturer(for: oui)
    }
}
