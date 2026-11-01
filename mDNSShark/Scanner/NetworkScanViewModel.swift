// mDNSShark/Scanner/NetworkScanViewModel.swift
import Foundation
import Combine
import DeviceFingerprint
import os

@MainActor
final class NetworkScanViewModel: ObservableObject {
    @Published var devices: [DiscoveredDevice] = []
    /// Advertisements with no resolved device (no IP, or a host name no device carries); shown as services, never counted as devices.
    @Published var unattachedServices: [DiscoveredService] = []
    @Published var isScanning: Bool = false
    /// Lets `AppCoordinator` skip its automatic first scan if the user already started one manually.
    private(set) var hasScannedAtLeastOnce = false
    /// True once the Local Network permission resolved as denied; drives the "Open Settings" banner in ContentView.
    @Published private(set) var isLocalNetworkDenied = false

    private let scanner     = NetworkScanner()
    private let localUtil   = LocalDeviceScanner()
    private let ouiDB       = OUIDatabase.shared
    private let enrichmentCoordinator = DeviceEnrichmentCoordinator()
    private var cancellables = Set<AnyCancellable>()
    // Row UUIDs keyed by identity: the host key when a device has one, else its IP, so a host keeps its UUID when its address changes.
    private var knownIDs: [String: UUID] = [:]
    /// A remembered value with the scan generation that last refreshed it, so `resetForNewScan` can forget stale ones.
    private struct Stamped<Value> {
        var value: Value
        var generation: Int
    }
    // Counts scans; entries stamped more than `rememberedScans` generations ago are dropped at the next reset.
    private var scanGeneration = 0
    private static let rememberedScans = 3
    // Maps any address seen on a host-keyed row to that host key, kept across scans so an address-only sweep or SSDP row that arrives
    // before the host's Bonjour row reuses the host's identity instead of minting a transient UUID. DHCP caveat: an address handed to
    // another device keeps the old identity until a row with a host key says otherwise, or until three scans pass without it.
    private var identityByIP: [String: Stamped<String>] = [:]
    // Raw probe results keyed by the probed address, so they survive a device's identity flipping from its IP to its host key.
    private var rawEnrichmentsByIP: [String: [DeviceEnrichment]] = [:]
    // Addresses whose full probe set answered this scan, or that the coordinator would refuse; a partial result alone never settles one.
    private var settledIPsThisScan = Set<String>()
    // The previous scan's results, shown for an address until this scan's probe of it answers, so a rescan does not blank enrichment.
    private var carriedEnrichmentsByIP: [String: Stamped<[DeviceEnrichment]>] = [:]
    // The scanner rows last applied, so an enrichment result rebuilds the same rows instead of patching one device in place.
    private var lastRaw: [NetworkScanner.Device] = []
    // True from scan start until its first non-empty raw result, so the previous list is held instead of blanked.
    private var holdingUntilFirstResult = false
    // The three sets below stay per IP on purpose: each probe targets one address, and a host's new address deserves its own probe.
    // One SSDP description fetch per IP per scan.
    private var fetchedDescriptionIPs = Set<String>()
    // One Google Wifi probe per IP per scan.
    private var fetchedGoogleWifiIPs = Set<String>()
    // Separate from `knownIDs` so a re-scan gives every device a fresh enrichment pass.
    private var enrichedIPsThisScan = Set<String>()
    // This device's own interface addresses, read once per scan; injectable so tests can supply them.
    private let ownAddressesProvider: () -> LocalInterfaces.OwnAddresses
    private var ownAddressesThisScan: LocalInterfaces.OwnAddresses?
    // The header reads networkCIDR on every render, so the interface walk behind it runs once per scan, not per render.
    private var networkCIDRThisScan: String?
    // Test seam standing in for the enrichment coordinator's enrich(ip:locationURL:); nil means the real coordinator.
    private let probeOverride: ((String, URL?) -> Void)?
    private let logger      = Logger(subsystem: "com.mDNSShark", category: "NetworkScanViewModel")

    /// Test seam: one address list stands for both the primary interface and all interfaces.
    convenience init(ownAddresses: @escaping () -> [String], probe: ((String, URL?) -> Void)? = nil) {
        self.init(ownAddresses: { LocalInterfaces.OwnAddresses(ownAddresses()) }, probe: probe)
    }

    init(ownAddresses: @escaping () -> LocalInterfaces.OwnAddresses = { LocalInterfaces.ownAddresses() },
         probe: ((String, URL?) -> Void)? = nil) {
        ownAddressesProvider = ownAddresses
        probeOverride = probe
        scanner.$devices
            .receive(on: DispatchQueue.main)
            .sink { [weak self] raw in self?.apply(raw: raw) }
            .store(in: &cancellables)

        scanner.$isScanning
            .receive(on: DispatchQueue.main)
            .sink { [weak self] scanning in
                guard let self else { return }
                self.isScanning = scanning
                // A scan that ended having found nothing releases the held list; a restart has already set the scanner scanning again.
                if !scanning, !self.scanner.isScanning, self.holdingUntilFirstResult {
                    self.holdingUntilFirstResult = false
                    self.apply(raw: self.scanner.devices)
                }
            }
            .store(in: &cancellables)

        enrichmentCoordinator.results
            .receive(on: DispatchQueue.main)
            .sink { [weak self] result in
                self?.ingestEnrichment(ip: result.ip, enrichments: result.enrichments, completesProbeSet: result.completesProbeSet)
            }
            .store(in: &cancellables)
    }

    func startScan(duration: Double = 25.0) {
        guard !scanner.isScanning else { return }
        beginScan(duration: duration)
    }

    /// Cancels any in-flight scan and starts a fresh one, so its probes use whatever route is live right now.
    func restartScan(duration: Double = 25.0) {
        scanner.cancelScan()
        beginScan(duration: duration)
    }

    private func beginScan(duration: Double) {
        hasScannedAtLeastOnce = true
        resetForNewScan()
        scanner.scanNetwork(duration: duration)
        // Runs alongside the scan, never ahead of it, so a denied permission can explain the near-empty result.
        Task {
            let decision = await LocalNetworkPermissionGate.waitForDecision(timeout: 10)
            apply(permissionDecision: decision)
        }
    }

    /// Per-scan state reset. `knownIDs` persists so rows keep their identity; remembered identities and carried enrichment persist until
    /// their address goes unseen for three whole scans, so a recycled DHCP address does not inherit a long-gone host.
    func resetForNewScan() {
        enrichmentCoordinator.cancelAll()
        enrichedIPsThisScan.removeAll()
        fetchedDescriptionIPs.removeAll()
        fetchedGoogleWifiIPs.removeAll()
        for (ip, raw) in rawEnrichmentsByIP { carriedEnrichmentsByIP[ip] = Stamped(value: raw, generation: scanGeneration) }
        rawEnrichmentsByIP.removeAll()
        settledIPsThisScan.removeAll()
        scanGeneration += 1
        let oldest = scanGeneration - Self.rememberedScans
        identityByIP = identityByIP.filter { $0.value.generation >= oldest }
        carriedEnrichmentsByIP = carriedEnrichmentsByIP.filter { $0.value.generation >= oldest }
        ownAddressesThisScan = nil
        networkCIDRThisScan = nil
        holdingUntilFirstResult = true
    }

    private func currentOwnAddresses() -> LocalInterfaces.OwnAddresses {
        if let cached = ownAddressesThisScan { return cached }
        let addresses = ownAddressesProvider()
        ownAddressesThisScan = addresses
        return addresses
    }

    /// Fires the probe set for an address once per scan. An address the coordinator would refuse (not LAN-local) gets an empty
    /// result recorded at once, so its probes count as settled instead of pending forever.
    private func dispatchProbesIfNeeded(ip: String, locationURL: URL?) {
        guard !enrichedIPsThisScan.contains(ip) else { return }
        enrichedIPsThisScan.insert(ip)
        guard SSDPDescriptionFetcher.isLANLocalAddress(ip) else {
            settledIPsThisScan.insert(ip)
            return
        }
        if let probeOverride { probeOverride(ip, locationURL) } else { enrichmentCoordinator.enrich(ip: ip, locationURL: locationURL) }
    }

    /// True once any address of the group had its full probe set answer this scan (an all-timeout set counts) or carries last scan's.
    /// The phone's own row is no exception: only its row address is probed, so it settles when that probe set answers or is refused.
    private func probesSettled(forAddresses addresses: Set<String>) -> Bool {
        addresses.contains { settledIPsThisScan.contains($0) || carriedEnrichmentsByIP[$0] != nil }
    }

    /// A device's addresses in display order: LAN IPv4, link-local IPv4, routable IPv6, then fe80, each raw as received.
    nonisolated static func orderedAddresses(_ addresses: Set<String>) -> [String] {
        addresses.sorted(by: NetworkScanner.isAddressOrdered)
    }

    func apply(permissionDecision decision: LocalNetworkPermissionGate.Decision) {
        isLocalNetworkDenied = decision.showsDeniedBanner(current: isLocalNetworkDenied)
    }

    /// Cached once a prefix is found; "Unknown" is never cached, so a link that comes up before the first scan is still picked up.
    var networkCIDR: String {
        if let cached = networkCIDRThisScan { return cached }
        guard let prefix = localUtil.getLocalIPPrefix(), !prefix.isEmpty else { return "Unknown" }
        let cidr = "\(prefix)0/24"
        networkCIDRThisScan = cidr
        return cidr
    }

    /// Stores a probe result under the address it probed and rebuilds the rows; only a full probe set settles the address and retires
    /// its carried result. While the scan start still holds the previous list, the result is stored without rebuilding last scan's rows.
    func ingestEnrichment(ip: String, enrichments: [DeviceEnrichment], completesProbeSet: Bool = true) {
        rawEnrichmentsByIP[ip, default: []].append(contentsOf: enrichments)
        if completesProbeSet {
            settledIPsThisScan.insert(ip)
            carriedEnrichmentsByIP.removeValue(forKey: ip)
        }
        guard !holdingUntilFirstResult else { return }
        apply(raw: lastRaw)
    }

    /// Merges and publishes, assigning only when the result changed so SwiftUI and the assess pipeline see real changes only.
    private func apply(raw: [NetworkScanner.Device]) {
        lastRaw = raw
        let merged = mergeScan(raw: raw)
        // The last scan's rows stay on screen until this scan resolves its first device or service, so a rescan never flashes the empty state.
        if holdingUntilFirstResult {
            guard !merged.devices.isEmpty || !merged.services.isEmpty else { return }
            holdingUntilFirstResult = false
        }
        if merged.devices != devices { devices = merged.devices }
        if merged.services != unattachedServices { unattachedServices = merged.services }
    }

    /// The device rows and the advertisements that resolved to no device.
    struct ScanMerge {
        var devices: [DiscoveredDevice]
        var services: [DiscoveredService]
    }

    func merge(raw: [NetworkScanner.Device]) -> [DiscoveredDevice] { mergeScan(raw: raw).devices }

    /// The pure part of a merge: where each raw row lands and what each device row is called, grouped and identified, with no
    /// view-model state read or written. `mergeScan` turns it into rows, UUIDs, probes and identity memory.
    struct MergePlan: Equatable {
        /// Parallel to the raw rows: the device address a row lands on, nil for a row that is a service or still resolving.
        var effectiveIPByRow: [String?]
        /// Identity key per device address: a host key, a remembered host key, or the address itself.
        var identityByEffectiveIP: [String: String]
        /// Every address a device row carries, raw as received, including the phone's own on its row.
        var addressesByEffectiveIP: [String: Set<String>]
        /// The raw Bonjour host name shown for a device address.
        var hostNameByIP: [String: String]
        /// Addresses seen on host-keyed rows mapped to that host key, for the cross-scan identity memory; address-keyed groups are left out.
        var hostIdentityByAddress: [String: String]
    }

    /// Plans a merge. One host's services can each resolve to a different address (LAN IPv4, self-assigned 169.254, or IPv6), so
    /// every row sharing a host key collapses onto that host's preferred address; `remembered` is the identity memory from past scans.
    nonisolated static func plan(raw: [NetworkScanner.Device], own: LocalInterfaces.OwnAddresses,
                                 remembered: [String: String]) -> MergePlan {
        var addressesByHost: [String: [String]] = [:]
        for device in raw {
            if let key = device.hostKey, let ip = device.resolvedIPAddress { addressesByHost[key, default: []].append(ip) }
        }
        let addressByHost = addressesByHost.compactMapValues { NetworkScanner.preferredAddress(from: $0) }
        let hostIPs: [String?] = raw.map { device in device.hostKey.flatMap { addressByHost[$0] } ?? device.resolvedIPAddress }

        // This device: any group holding one of the phone's own addresses on any interface (a set intersection on zone-free keys,
        // since it has several IPv6 addresses) folds onto the phone's Wi-Fi IPv4, so it is listed under 192.168.x.y rather than an
        // fe80 address. It is never hidden.
        var rawAddressesByHostIP: [String: Set<String>] = [:]
        for (device, hostIP) in zip(raw, hostIPs) {
            guard let hostIP else { continue }
            rawAddressesByHostIP[hostIP, default: [hostIP]].insert(device.resolvedIPAddress ?? hostIP)
        }
        let ownKeys = Set(own.all.map(LocalInterfaces.addressMatchKey))
        let ownGroupIPs = Set(rawAddressesByHostIP.filter { !ownKeys.isDisjoint(with: $0.value.map(LocalInterfaces.addressMatchKey)) }.keys)
        // Display address: the primary interface's IPv4, then any own IPv4, then the primary's best address, then anything own or resolved.
        func ipv4(_ addresses: [String]) -> [String] { addresses.filter { !$0.contains(":") } }
        let thisDeviceIP: String? = ownGroupIPs.isEmpty ? nil
            : [ipv4(own.primary), ipv4(own.all), own.primary, own.all + ownGroupIPs].lazy.compactMap(NetworkScanner.preferredAddress).first
        let effectiveIPByRow: [String?] = hostIPs.map { hostIP in
            hostIP.map { ownGroupIPs.contains($0) ? (thisDeviceIP ?? $0) : $0 }
        }

        // Identity key per address group: the smallest host key at that address, else the identity last remembered for the address,
        // else the address. A key is claimed by one group only.
        var hostKeysByIP: [String: Set<String>] = [:]
        for (device, ip) in zip(raw, effectiveIPByRow) {
            if let ip, let key = device.hostKey { hostKeysByIP[ip, default: []].insert(key) }
        }
        var identityByEffectiveIP: [String: String] = [:]
        var claimed = Set<String>()
        let effectiveIPs = Set(effectiveIPByRow.compactMap { $0 }).sorted()
        for ip in effectiveIPs {
            if let key = hostKeysByIP[ip]?.sorted().first(where: { !claimed.contains($0) }) {
                identityByEffectiveIP[ip] = key
                claimed.insert(key)
            }
        }
        // Second pass, so a host key seen on a row in this merge always beats a remembered one (see the DHCP caveat on `identityByIP`).
        for ip in effectiveIPs where identityByEffectiveIP[ip] == nil {
            if let remembered = remembered[ip], !claimed.contains(remembered) {
                identityByEffectiveIP[ip] = remembered
                claimed.insert(remembered)
            } else {
                identityByEffectiveIP[ip] = ip
            }
        }
        // Probe results arrive tagged with whichever address was probed, so every address a host-keyed row carries maps to its key;
        // an address that is itself a device row keeps its own identity.
        var hostIdentityByAddress = identityByEffectiveIP.filter { $0.key != $0.value }
        var addressesByEffectiveIP: [String: Set<String>] = [:]
        for (device, ip) in zip(raw, effectiveIPByRow) {
            guard let ip else { continue }
            addressesByEffectiveIP[ip, default: [ip]].insert(device.resolvedIPAddress ?? ip)
            if let address = device.resolvedIPAddress, identityByEffectiveIP[address] == nil, hostIdentityByAddress[address] == nil,
               let identity = identityByEffectiveIP[ip], identity != ip {
                hostIdentityByAddress[address] = identity
            }
        }
        if let thisDeviceIP {
            // The phone's own addresses join its row raw; one already present under another zone spelling is not listed twice.
            var group = addressesByEffectiveIP[thisDeviceIP] ?? [thisDeviceIP]
            let present = Set(group.map(LocalInterfaces.addressMatchKey))
            group.formUnion(own.all.filter { !present.contains(LocalInterfaces.addressMatchKey($0)) })
            addressesByEffectiveIP[thisDeviceIP] = group
        }

        // The row's display name is the raw Bonjour host name as received; when rows at one IP carry different names the
        // lexicographically smallest is chosen (a selection, not a transformation) so it does not depend on resolve order.
        var hostNameByIP: [String: String] = [:]
        for (device, ip) in zip(raw, effectiveIPByRow) {
            guard let host = device.hostName, let ip else { continue }
            if hostNameByIP[ip].map({ host < $0 }) ?? true { hostNameByIP[ip] = host }
        }
        return MergePlan(effectiveIPByRow: effectiveIPByRow, identityByEffectiveIP: identityByEffectiveIP,
                         addressesByEffectiveIP: addressesByEffectiveIP, hostNameByIP: hostNameByIP,
                         hostIdentityByAddress: hostIdentityByAddress)
    }

    /// Builds the device rows from the scanner's raw results. `openPorts` is never seeded from `Device.port`: that port is only
    /// advertised (Bonjour resolve or SSDP LOCATION) and stays on the service; open ports arrive solely via the enrichment sink.
    /// A row with no address of its own borrows its host's (matched by `Device.hostKey`); a row with neither is a service, not a device.
    func mergeScan(raw: [NetworkScanner.Device]) -> ScanMerge {
        let plan = Self.plan(raw: raw, own: currentOwnAddresses(), remembered: identityByIP.mapValues(\.value))
        for (address, identity) in plan.hostIdentityByAddress {
            identityByIP[address] = Stamped(value: identity, generation: scanGeneration)
        }
        let identityByEffectiveIP = plan.identityByEffectiveIP
        let addressesByEffectiveIP = plan.addressesByEffectiveIP
        let hostNameByIP = plan.hostNameByIP
        var byIP: [String: DiscoveredDevice] = [:]

        var services: [DiscoveredService] = []
        for (device, ip) in zip(raw, plan.effectiveIPByRow) {
            guard let ip else {
                // A Bonjour row whose resolve has not answered yet is neither a device nor a service, so it never flashes a services node.
                guard device.resolveSettled else { continue }
                // The id uses the dot-stripped type key; the displayed serviceType stays exactly as received.
                services.append(DiscoveredService(id: "\(device.serviceTypeKey)|\(device.serviceName)|\(device.serviceDomain)",
                                                  name: device.identifier, serviceType: device.serviceType,
                                                  port: device.port, hostName: device.hostName))
                continue
            }
            // Port-sweep and SSDP rows carry a non-Bonjour placeholder type; only real "_x._tcp" types are services.
            let svc: BonjourService? = device.serviceType.hasPrefix("_") ? BonjourService(
                serviceType: device.serviceType,
                serviceName: device.serviceName,
                port: device.port ?? 0,
                txtRecords: device.txtRecords ?? [:]
            ) : nil
            if var existing = byIP[ip] {
                // Deduped on type and name: one host may advertise several services of the same type.
                if let svc, !existing.bonjourServices.contains(where: { $0.serviceType == svc.serviceType && $0.serviceName == svc.serviceName }) {
                    existing.bonjourServices.append(svc)
                }
                if existing.manufacturer == nil {
                    existing.manufacturer = appleManufacturer(serviceType: device.serviceType, txtRecords: device.txtRecords)
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
                if mfr == nil { mfr = appleManufacturer(serviceType: device.serviceType, txtRecords: device.txtRecords) }
                let os = inferOS(serviceType: device.serviceType, manufacturer: mfr, txtRecords: device.txtRecords)
                let identity = identityByEffectiveIP[ip] ?? ip
                let group = addressesByEffectiveIP[ip] ?? [ip]
                dispatchProbesIfNeeded(ip: ip, locationURL: device.locationURL)
                var newDevice = DiscoveredDevice(
                    id:              stableID(forIdentity: identity, ip: ip),
                    hostname:        hostNameByIP[ip] ?? device.identifier,
                    ipAddress:       ip,
                    macAddress:      mac,
                    manufacturer:    mfr,
                    inferredOS:      os,
                    bonjourServices: svc.map { [$0] } ?? [],
                    probesSettled:   probesSettled(forAddresses: group),
                    addresses:       Self.orderedAddresses(group)
                )
                // Re-merge stored raw enrichments against the fresh baseline, not a stale merged snapshot.
                let stored = enrichments(forAddresses: group)
                if !stored.isEmpty {
                    let baseline = EnrichedFields(mac: newDevice.macAddress, manufacturer: newDevice.manufacturer,
                                                   inferredOS: newDevice.inferredOS, openPorts: newDevice.openPorts)
                    let merged = DeviceFingerprint.merge(existing: baseline, incoming: stored)
                    newDevice.macAddress = merged.mac
                    newDevice.manufacturer = merged.manufacturer
                    newDevice.inferredOS = merged.inferredOS
                    newDevice.openPorts = merged.openPorts
                }
                byIP[ip] = newDevice
                dispatchDescriptionFetchIfNeeded(ip: ip, locationURL: device.locationURL)
                dispatchGoogleWifiIfNeeded(ip: ip, serviceType: device.serviceType)
            }
        }
        services.sort { ($0.name, $0.typeLabel, $0.id) < ($1.name, $1.typeLabel, $1.id) }
        let rows = Array(byIP.values).sorted { $0.ipAddress < $1.ipAddress }
        logger.debug("mergeScan: raw=\(raw.count) devices=\(rows.count) services=\(services.count)")
        for row in rows {
            let names = row.bonjourServices.map(\.serviceName).joined(separator: ", ")
            logger.debug("  device ip=\(row.ipAddress) identity=\(identityByEffectiveIP[row.ipAddress] ?? row.ipAddress) uuid=\(String(row.id.uuidString.prefix(4))) icon=\(row.deviceIcon) ports=\(row.openPorts) manufacturer=\(row.manufacturer ?? "nil") services=[\(names)]")
        }
        return ScanMerge(devices: rows, services: services)
    }

    /// Probe results for every address in a device's group: this scan's once its probe set answered, else the carried previous
    /// scan's together with whatever partial result has arrived so far (merge is order-independent).
    private func enrichments(forAddresses addresses: Set<String>) -> [DeviceEnrichment] {
        addresses.sorted().flatMap { ip -> [DeviceEnrichment] in
            let raw = rawEnrichmentsByIP[ip] ?? []
            return settledIPsThisScan.contains(ip) ? raw : (carriedEnrichmentsByIP[ip]?.value ?? []) + raw
        }
    }

    /// The row UUID for an identity key. A device first seen by address that later gains a host key keeps its UUID, and the address key is retired.
    private func stableID(forIdentity identity: String, ip: String) -> UUID {
        if let known = knownIDs[identity] {
            // Once the host identity is known, a UUID left under the bare address is an orphan from an address-only pass.
            if identity != ip, knownIDs.removeValue(forKey: ip) != nil {
                logger.debug("stableID known: identity=\(identity) ip=\(ip) uuid=\(String(known.uuidString.prefix(4))) (orphan address key removed)")
            } else {
                logger.debug("stableID known: identity=\(identity) ip=\(ip) uuid=\(String(known.uuidString.prefix(4)))")
            }
            return known
        }
        if identity != ip, let adopted = knownIDs.removeValue(forKey: ip) {
            knownIDs[identity] = adopted
            logger.debug("stableID adopted: identity=\(identity) ip=\(ip) uuid=\(String(adopted.uuidString.prefix(4)))")
            return adopted
        }
        let fresh = UUID()
        knownIDs[identity] = fresh
        logger.debug("stableID fresh: identity=\(identity) ip=\(ip) uuid=\(String(fresh.uuidString.prefix(4)))")
        return fresh
    }

    /// Fires the SSDP description fetch the first time any row for this IP reveals a `locationURL`.
    private func dispatchDescriptionFetchIfNeeded(ip: String, locationURL: URL?) {
        guard let locationURL, !fetchedDescriptionIPs.contains(ip) else { return }
        fetchedDescriptionIPs.insert(ip)
        enrichmentCoordinator.enrichDescription(ip: ip, locationURL: locationURL)
    }

    /// Fires the Google Wifi probe only for hosts that advertise `_googlecast._tcp`, never blindly.
    private func dispatchGoogleWifiIfNeeded(ip: String, serviceType: String) {
        guard serviceType == "_googlecast._tcp", !fetchedGoogleWifiIPs.contains(ip) else { return }
        fetchedGoogleWifiIPs.insert(ip)
        enrichmentCoordinator.enrichGoogleWifi(ip: ip)
    }

    /// AirPlay/RAOP advertise the hardware model ("model" / "am", e.g. "MacBookPro16,2"). Only those rows are
    /// trusted: NAS boxes put fake Mac models in `_device-info._tcp`, and the service types alone are used by third-party speakers and TVs.
    private func appleManufacturer(serviceType: String, txtRecords: [String: String]?) -> String? {
        // Continuity services no third-party device is known to advertise.
        if serviceType == "_rdlink._tcp" || serviceType == "_companion-link._tcp" { return "Apple" }
        guard serviceType == "_airplay._tcp" || serviceType == "_raop._tcp",
              let model = txtRecords?["model"] ?? txtRecords?["am"] else { return nil }
        let applePrefixes = ["Mac", "iMac", "iPhone", "iPad", "iPod", "AppleTV", "AudioAccessory", "AirPort", "Watch", "RealityDevice"]
        return applePrefixes.contains(where: { model.hasPrefix($0) }) ? "Apple" : nil
    }

    private func inferOS(serviceType: String, manufacturer: String?, txtRecords: [String: String]? = nil) -> String? {
        // Only Apple-exclusive types: AirPlay, RAOP, DAAP and device-info are also used by Sonos, Samsung TVs and NAS boxes.
        let appleServices: Set<String> = ["_apple-mobdev2._tcp", "_airdrop._tcp"]
        if appleServices.contains(serviceType) { return "Apple" }
        if serviceType == "_googlecast._tcp",
           let model = txtRecords?["md"], !model.isEmpty,
           model.contains("Nest Wifi") || model.contains("Google Wifi") {
            return model
        }
        // HomeKit alone is too generic; require the HAP "md" model name to mention eero.
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
