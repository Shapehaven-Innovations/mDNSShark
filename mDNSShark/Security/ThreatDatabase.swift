// mDNSShark/Security/ThreatDatabase.swift
import Foundation
import os

struct ThreatEntry {
    enum ThreatSource { case cisa, nist }
    let cveID: String
    let vulnerabilityName: String
    let shortDescription: String
    let source: ThreatSource
}

actor ThreatDatabase {
    private var kevEntries: [CISAKEVEntry] = []
    private var nistMap = NistCPEMap(serviceTypes: [:], manufacturers: [:])
    private let logger = Logger(subsystem: "com.mDNSShark", category: "ThreatDatabase")

    init() { Task { await loadBundledData() } }

    private func loadBundledData() {
        if let url = Bundle.main.url(forResource: "cisa_kev_snapshot", withExtension: "json"),
           let data = try? Data(contentsOf: url),
           let catalog = try? JSONDecoder().decode(CISAKEVCatalog.self, from: data) {
            kevEntries = catalog.vulnerabilities
            logger.info("Loaded \(catalog.vulnerabilities.count) CISA KEV entries")
        }
        if let url = Bundle.main.url(forResource: "nist_cpe_map", withExtension: "json"),
           let data = try? Data(contentsOf: url),
           let map = try? JSONDecoder().decode(NistCPEMap.self, from: data) {
            nistMap = map
            logger.info("Loaded NIST CPE map")
        }
    }

    func refresh() async {
        guard let url = URL(string: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json") else { return }
        do {
            let (data, _) = try await URLSession.shared.data(from: url)
            let catalog = try JSONDecoder().decode(CISAKEVCatalog.self, from: data)
            kevEntries = catalog.vulnerabilities
            logger.info("Refreshed: \(catalog.vulnerabilities.count) CISA KEV entries")
        } catch {
            logger.error("CISA refresh failed: \(error.localizedDescription)")
        }
    }

    func lookup(manufacturer: String?, serviceType: String?, port: Int?) async -> [ThreatEntry] {
        var results: [ThreatEntry] = []

        if let st = serviceType, let entry = nistMap.serviceTypes[st], !entry.cves.isEmpty {
            for cve in entry.cves {
                if let kev = kevEntries.first(where: { $0.cveID == cve }) {
                    results.append(ThreatEntry(cveID: kev.cveID, vulnerabilityName: kev.vulnerabilityName,
                                               shortDescription: kev.shortDescription, source: .cisa))
                } else {
                    results.append(ThreatEntry(cveID: cve, vulnerabilityName: "\(st) Known Vulnerability",
                                               shortDescription: entry.description, source: .nist))
                }
            }
        }

        if let mfr = manufacturer {
            for (key, entry) in nistMap.manufacturers where mfr.lowercased().contains(key.lowercased()) {
                for cve in entry.cves {
                    if let kev = kevEntries.first(where: { $0.cveID == cve }) {
                        results.append(ThreatEntry(cveID: kev.cveID, vulnerabilityName: kev.vulnerabilityName,
                                                   shortDescription: kev.shortDescription, source: .cisa))
                    } else {
                        results.append(ThreatEntry(cveID: cve, vulnerabilityName: "\(key) Known Vulnerability",
                                                   shortDescription: entry.description, source: .nist))
                    }
                }
                break
            }
        }
        return results
    }
}

// MARK: - Decodable models

struct CISAKEVCatalog: Decodable { let vulnerabilities: [CISAKEVEntry] }
struct CISAKEVEntry: Decodable {
    let cveID: String
    let vendorProject: String
    let product: String
    let vulnerabilityName: String
    let shortDescription: String
}
struct NistCPEMap: Decodable {
    let serviceTypes: [String: NistServiceEntry]
    let manufacturers: [String: NistManufacturerEntry]
}
struct NistServiceEntry: Decodable { let cves: [String]; let description: String }
struct NistManufacturerEntry: Decodable { let cves: [String]; let description: String }
