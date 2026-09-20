// mDNSShark/Scanner/NetworkScanViewModel.swift
import Foundation
import Combine
import DeviceFingerprint
import os

@MainActor
final class NetworkScanViewModel: ObservableObject {
    @Published var devices: [DiscoveredDevice] = []
    @Published var isScanning: Bool = false

    private let scanner     = NetworkScanner()
    private let localUtil   = LocalDeviceScanner()
    private let ouiDB       = OUIDatabase.shared
    private let enrichmentCoordinator = DeviceEnrichmentCoordinator()
    private var cancellables = Set<AnyCancellable>()
    // Stable UUID assignment only — persists across re-scans so rows keep
    // identity, and is intentionally NOT used to gate enrichment dispatch
    // (see `enrichedIPsThisScan` below).
    private var knownIDs: [String: UUID] = [:]
    // Raw probe results per IP (not pre-merged fields) so a later rebuild of
    // a device's baseline (e.g. a stronger Bonjour identity resolving after
    // a bare port-80-sweep placeholder) re-runs precedence against whatever
    // is CURRENT, rather than blindly overlaying a merged snapshot that may
    // have been captured against a weaker, now-stale baseline.
    private var rawEnrichmentsByIP: [String: [DeviceEnrichment]] = [:]
    // Which IPs have already had `enrichDescription` dispatched this scan,
    // so a re-appearing `locationURL` across multiple raw Device rows for
    // the same IP only triggers one SSDP description fetch.
    private var fetchedDescriptionIPs = Set<String>()
    // Which IPs have already had `enrichGoogleWifi` dispatched this scan,
    // same one-shot-per-IP reasoning as `fetchedDescriptionIPs`.
    private var fetchedGoogleWifiIPs = Set<String>()
    // Which IPs have already had the main `enrich()` probe pass dispatched
    // THIS scan. Deliberately separate from `knownIDs`: a re-scan should
    // give every device a fresh enrichment pass (e.g. a host that was
    // offline during scan 1 and answers during scan 2), even though its
    // row keeps the same stable UUID.
    private var enrichedIPsThisScan = Set<String>()
    private let logger      = Logger(subsystem: "com.mDNSShark", category: "NetworkScanViewModel")

    init() {
        scanner.$devices
            .receive(on: DispatchQueue.main)
            .sink { [weak self] raw in
                guard let self else { return }
                self.devices = self.merge(raw: raw)
            }
            .store(in: &cancellables)

        scanner.$isScanning
            .receive(on: DispatchQueue.main)
            .assign(to: &$isScanning)

        enrichmentCoordinator.results
            .receive(on: DispatchQueue.main)
            .sink { [weak self] result in
                guard let self else { return }
                // Always accumulate the raw results, independent of whether
                // a matching device row currently exists — `merge(raw:)`
                // re-derives fields from this against the live baseline the
                // next time it rebuilds a row for this IP (Fix 2).
                self.rawEnrichmentsByIP[result.ip, default: []].append(contentsOf: result.enrichments)

                guard let index = self.devices.firstIndex(where: { $0.ipAddress == result.ip }) else { return }
                let existing = EnrichedFields(mac: self.devices[index].macAddress,
                                               manufacturer: self.devices[index].manufacturer,
                                               inferredOS: self.devices[index].inferredOS,
                                               openPorts: self.devices[index].openPorts)
                // Module-qualified: this type's own private `merge(raw:)` would
                // otherwise win unqualified lookup over the package function.
                let merged = DeviceFingerprint.merge(existing: existing, incoming: result.enrichments)
                self.devices[index].macAddress = merged.mac
                self.devices[index].manufacturer = merged.manufacturer
                self.devices[index].inferredOS = merged.inferredOS
                self.devices[index].openPorts = merged.openPorts
            }
            .store(in: &cancellables)
    }

    func startScan(duration: Double = 25.0) {
        // A fresh scan gets a genuinely fresh enrichment pass: cancel
        // whatever the previous scan still had in flight and clear all
        // per-scan enrichment state. `knownIDs` is deliberately untouched —
        // it serves only stable row-ID assignment across the device's
        // lifetime, unrelated to enrichment gating.
        guard !scanner.isScanning else { return }
        enrichmentCoordinator.cancelAll()
        enrichedIPsThisScan.removeAll()
        rawEnrichmentsByIP.removeAll()
        fetchedDescriptionIPs.removeAll()
        fetchedGoogleWifiIPs.removeAll()
        scanner.scanNetwork(duration: duration)
    }

    var networkCIDR: String {
        guard let prefix = localUtil.getLocalIPPrefix(), !prefix.isEmpty else { return "Unknown" }
        return "\(prefix)0/24"
    }

    private func merge(raw: [NetworkScanner.Device]) -> [DiscoveredDevice] {
        var byIP: [String: DiscoveredDevice] = [:]
        for device in raw {
            let ip = device.resolvedIPAddress ?? device.serviceName
            if var existing = byIP[ip] {
                let svc = BonjourService(
                    serviceType: device.serviceType,
                    serviceName: device.serviceName,
                    port: device.port ?? 0,
                    txtRecords: device.txtRecords ?? [:]
                )
                if !existing.bonjourServices.contains(where: { $0.serviceType == svc.serviceType }) {
                    existing.bonjourServices.append(svc)
                }
                if let p = device.port, !existing.openPorts.contains(p) {
                    existing.openPorts.append(p)
                }
                byIP[ip] = existing
                dispatchDescriptionFetchIfNeeded(ip: ip, locationURL: device.locationURL)
                dispatchGoogleWifiIfNeeded(ip: ip, serviceType: device.serviceType)
            } else {
                let mac = device.txtRecords?["mac"]
                var mfr = mac.flatMap { ouiDB.manufacturer(for: String($0.prefix(8))) }
                if mfr == nil, device.serviceType == "_googlecast._tcp",
                   let model = device.txtRecords?["md"], !model.isEmpty {
                    mfr = "Google"
                }
                if mfr == nil, device.serviceType == "_hap._tcp",
                   let model = device.txtRecords?["md"], model.localizedCaseInsensitiveContains("eero") {
                    mfr = "eero"
                }
                let svc = BonjourService(
                    serviceType: device.serviceType,
                    serviceName: device.serviceName,
                    port: device.port ?? 0,
                    txtRecords: device.txtRecords ?? [:]
                )
                let os = inferOS(serviceType: device.serviceType, manufacturer: mfr, txtRecords: device.txtRecords)
                let stableID = knownIDs[ip] ?? UUID()
                knownIDs[ip] = stableID
                var newDevice = DiscoveredDevice(
                    id:              stableID,
                    hostname:        device.identifier,
                    ipAddress:       ip,
                    macAddress:      mac,
                    manufacturer:    mfr,
                    inferredOS:      os,
                    openPorts:       device.port.map { [$0] } ?? [],
                    bonjourServices: [svc]
                )
                // Re-merge stored raw enrichments against the FRESH baseline
                // just built above, never against a stale pre-merged
                // snapshot — otherwise a later rebuild against a NOW-BETTER
                // baseline (e.g. a real Bonjour identity resolving after a
                // bare port-80-sweep placeholder) would have its good data
                // overwritten by an earlier weak snapshot (Fix 2).
                if let stored = rawEnrichmentsByIP[ip], !stored.isEmpty {
                    let baseline = EnrichedFields(mac: newDevice.macAddress, manufacturer: newDevice.manufacturer,
                                                   inferredOS: newDevice.inferredOS, openPorts: newDevice.openPorts)
                    let merged = DeviceFingerprint.merge(existing: baseline, incoming: stored)
                    newDevice.macAddress = merged.mac
                    newDevice.manufacturer = merged.manufacturer
                    newDevice.inferredOS = merged.inferredOS
                    newDevice.openPorts = merged.openPorts
                }
                byIP[ip] = newDevice
                if device.resolvedIPAddress != nil, !enrichedIPsThisScan.contains(ip) {
                    enrichedIPsThisScan.insert(ip)
                    enrichmentCoordinator.enrich(ip: ip, locationURL: device.locationURL)
                }
                dispatchDescriptionFetchIfNeeded(ip: ip, locationURL: device.locationURL)
                dispatchGoogleWifiIfNeeded(ip: ip, serviceType: device.serviceType)
            }
        }
        return Array(byIP.values).sorted { $0.ipAddress < $1.ipAddress }
    }

    /// Fires the SSDP description fetch the first time ANY raw `Device` row
    /// for this IP reveals a non-nil `locationURL` — regardless of whether
    /// it came from the new-device or existing-device branch above, and
    /// regardless of whether the main `enrich()` pass already fired for
    /// this IP (Fix 3).
    private func dispatchDescriptionFetchIfNeeded(ip: String, locationURL: URL?) {
        guard let locationURL, !fetchedDescriptionIPs.contains(ip) else { return }
        fetchedDescriptionIPs.insert(ip)
        enrichmentCoordinator.enrichDescription(ip: ip, locationURL: locationURL)
    }

    /// Fires the Google Wifi status probe the first time ANY raw `Device`
    /// row for this IP reveals `_googlecast._tcp` - regardless of whether
    /// it came from the new-device or existing-device branch of `merge()`,
    /// same reasoning as `dispatchDescriptionFetchIfNeeded`. This is the
    /// probe's only trigger; `enrich()` never fires it directly, so an
    /// active HTTP probe never fires against a host with no Google Cast
    /// mDNS hint at all.
    private func dispatchGoogleWifiIfNeeded(ip: String, serviceType: String) {
        guard serviceType == "_googlecast._tcp", !fetchedGoogleWifiIPs.contains(ip) else { return }
        fetchedGoogleWifiIPs.insert(ip)
        enrichmentCoordinator.enrichGoogleWifi(ip: ip)
    }

    private func inferOS(serviceType: String, manufacturer: String?, txtRecords: [String: String]? = nil) -> String? {
        let appleServices: Set<String> = [
            "_apple-mobdev2._tcp", "_airdrop._tcp", "_airplay._tcp",
            "_raop._tcp", "_device-info._tcp", "_daap._tcp"
        ]
        if appleServices.contains(serviceType) { return "Apple" }
        if serviceType == "_googlecast._tcp",
           let model = txtRecords?["md"], !model.isEmpty,
           model.contains("Nest Wifi") || model.contains("Google Wifi") {
            return model
        }
        // HomeKit alone is too generic a signal to imply "eero" (HomeKit
        // covers thousands of unrelated smart-home products); only treat it
        // as an eero hint when the HAP TXT record's "md" (model name, a
        // required HAP TXT key) corroborates it.
        if serviceType == "_hap._tcp",
           let model = txtRecords?["md"], model.localizedCaseInsensitiveContains("eero") {
            return "eero"
        }
        if let mfr = manufacturer {
            if mfr.contains("Apple")     { return "Apple" }
            if mfr.contains("Microsoft") { return "Windows" }
            if mfr.contains("Raspberry") { return "Linux" }
        }
        return nil
    }
}
