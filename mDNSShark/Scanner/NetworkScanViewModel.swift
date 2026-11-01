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
    /// Lets the launch gate skip its automatic first scan if the user already started one manually.
    private(set) var hasScannedAtLeastOnce = false
    /// True once the Local Network permission resolved as denied; drives the "Open Settings" banner in ContentView.
    @Published private(set) var isLocalNetworkDenied = false
    /// True once the launch Local Network check was granted; until then every foreground retries it so the system alert can never be lost.
    private(set) var launchGateSettled = false
    private var launchGateInFlight = false
    /// Set when the first scan ran before permission was granted, so granting later restarts it instead of leaving it near empty.
    private var autoScanNeedsRedo = false

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
    private(set) var rawEnrichmentsByIP: [String: [DeviceEnrichment]] = [:]
    // Addresses whose full probe set answered this scan, or that the coordinator would refuse; a partial result alone never settles one.
    private var settledIPsThisScan = Set<String>()
    // The previous scan's results, shown for an address until this scan's probe of it answers, so a rescan does not blank enrichment.
    private var carriedEnrichmentsByIP: [String: Stamped<[DeviceEnrichment]>] = [:]
    // UPnP friendly names by probed address, kept like `identityByIP` so a TV that is off during a rescan keeps its name for three scans.
    private var upnpNameByIP: [String: Stamped<String>] = [:]
    // The scanner rows last applied, so an enrichment result rebuilds the same rows instead of patching one device in place.
    private var lastRaw: [NetworkScanner.Device] = []
    // True from scan start until the scanner publishes its first rows, so a result landing meanwhile does not rebuild last scan's rows.
    private var holdingUntilFirstResult = false
    // Last scan's rows and unattached services, overlaid on this scan's results until each is re-resolved or the scan ends, so a rescan
    // repopulates in place instead of collapsing the list and regrowing it.
    private var heldDevicesByID: [UUID: DiscoveredDevice] = [:]
    private var heldServices: [DiscoveredService] = []
    // The three sets below stay per IP on purpose: each probe targets one address, and a host's new address deserves its own probe.
    // One SSDP description fetch per IP per scan.
    private var fetchedDescriptionIPs = Set<String>()
    // One Google Wifi probe per IP per scan.
    private var fetchedGoogleWifiIPs = Set<String>()
    // Separate from `knownIDs` so a re-scan gives every device a fresh enrichment pass.
    private var enrichedIPsThisScan = Set<String>()
    // Addresses refused as off-subnet, not marked enriched, so a later merge that adds an on-subnet address can still probe them.
    private var skippedOffSubnetIPs = Set<String>()
    // The payment-vendor gate per probed address this scan: ARP is read and the vendor decided before any probe, fetch or Google Wifi send.
    private enum VendorGateState { case waiting, passed, skipped }
    private var vendorGateByIP: [String: VendorGateState] = [:]
    // Description fetches and Google Wifi probes asked for while an address's gate waited on ARP; sent only if it passes.
    private var heldDescriptionURLByIP: [String: URL] = [:]
    private var heldGoogleWifiIPs = Set<String>()
    // ARP waits in flight, cancelled when a new scan starts.
    private var vendorGateTasks: [String: Task<Void, Never>] = [:]
    // The address probed for each row's effective address, which differs when only a later address of the group is on this phone's subnet.
    private var probeTargetByIP: [String: String] = [:]
    // Addresses the gate kept passive this scan because their MAC vendor makes payment equipment.
    private var paymentSkipByIP: [String: PaymentVendorSkip] = [:]
    // ARP seam for the vendor gate; with the probe seam and no ARP seam the table reads as hidden, so tests never read this Mac's table.
    private let arpLookup: @Sendable (String) -> ARPLookup
    // Stands in for the gate's one NBSTAT trigger (device test T9); with the probe seam and no trigger seam none is sent.
    private let arpTriggerOverride: ((String) async -> String?)?
    private let vendorGateTiming: PaymentVendorGate.Timing
    // This device's own interface addresses, read once per scan; injectable so tests can supply them.
    private let ownAddressesProvider: () -> LocalInterfaces.OwnAddresses
    private var ownAddressesThisScan: LocalInterfaces.OwnAddresses?
    // The header reads networkCIDR on every render, so the interface walk behind it runs once per scan, not per render.
    private var networkCIDRThisScan: String?
    // Test seam standing in for the enrichment coordinator's enrich(ip:locationURL:); nil means the real coordinator.
    private let probeOverride: ((String, URL?) -> Void)?
    // Test seams standing in for the SSDP description fetch and the Google Wifi probe; nil means the real coordinator.
    private let descriptionFetchOverride: ((String, URL) -> Void)?
    private let googleWifiOverride: ((String) -> Void)?
    private let logger      = Logger(subsystem: "com.mDNSShark", category: "NetworkScanViewModel")

    /// Test seam: one address list stands for both the primary interface and all interfaces.
    convenience init(ownAddresses: @escaping () -> [String], probe: ((String, URL?) -> Void)? = nil,
                     descriptionFetch: ((String, URL) -> Void)? = nil, googleWifi: ((String) -> Void)? = nil,
                     arpLookup: (@Sendable (String) -> ARPLookup)? = nil, arpTrigger: ((String) async -> String?)? = nil,
                     vendorGateTiming: PaymentVendorGate.Timing = .standard) {
        self.init(ownAddresses: { LocalInterfaces.OwnAddresses(ownAddresses()) }, probe: probe,
                  descriptionFetch: descriptionFetch, googleWifi: googleWifi,
                  arpLookup: arpLookup, arpTrigger: arpTrigger, vendorGateTiming: vendorGateTiming)
    }

    init(ownAddresses: @escaping () -> LocalInterfaces.OwnAddresses = { LocalInterfaces.liveOwnAddresses() },
         probe: ((String, URL?) -> Void)? = nil,
         descriptionFetch: ((String, URL) -> Void)? = nil, googleWifi: ((String) -> Void)? = nil,
         arpLookup: (@Sendable (String) -> ARPLookup)? = nil, arpTrigger: ((String) async -> String?)? = nil,
         vendorGateTiming: PaymentVendorGate.Timing = .standard) {
        ownAddressesProvider = ownAddresses
        descriptionFetchOverride = descriptionFetch
        googleWifiOverride = googleWifi
        if let arpLookup {
            self.arpLookup = arpLookup
        } else if probe == nil {
            let table = ARPTableProbe()
            self.arpLookup = { table.lookup(ip: $0) }
        } else {
            self.arpLookup = { _ in .hidden }
        }
        arpTriggerOverride = arpTrigger
        self.vendorGateTiming = vendorGateTiming
        _ = GatewayMonitor.shared   // starts reading the system's default gateway before the first merge asks for it
        probeOverride = probe
        // At most one merge per 250 ms while resolves stream in; the scan-ending sink below applies the final list, so nothing is lost.
        scanner.$devices
            .throttle(for: .milliseconds(250), scheduler: DispatchQueue.main, latest: true)
            .sink { [weak self] raw in self?.apply(raw: raw) }
            .store(in: &cancellables)

        scanner.$isScanning
            .receive(on: DispatchQueue.main)
            .sink { [weak self] scanning in
                guard let self else { return }
                self.isScanning = scanning
                // The scan ending drops whatever it did not re-find; a restart has already set the scanner scanning again.
                if !scanning, !self.scanner.isScanning, self.holdingUntilFirstResult || !self.heldDevicesByID.isEmpty || !self.heldServices.isEmpty {
                    self.holdingUntilFirstResult = false
                    self.heldDevicesByID = [:]
                    self.heldServices = []
                    self.apply(raw: self.scanner.devices)
                }
            }
            .store(in: &cancellables)

        enrichmentCoordinator.results
            .receive(on: DispatchQueue.main)
            .sink { [weak self] result in
                self?.ingestEnrichment(ip: result.ip, enrichments: result.enrichments, completesProbeSet: result.completesProbeSet, upnpName: result.upnpName)
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
        skippedOffSubnetIPs.removeAll()
        for task in vendorGateTasks.values { task.cancel() }
        vendorGateTasks.removeAll()
        vendorGateByIP.removeAll()
        probeTargetByIP.removeAll()
        heldDescriptionURLByIP.removeAll()
        heldGoogleWifiIPs.removeAll()
        paymentSkipByIP.removeAll()
        fetchedDescriptionIPs.removeAll()
        fetchedGoogleWifiIPs.removeAll()
        for (ip, raw) in rawEnrichmentsByIP { carriedEnrichmentsByIP[ip] = Stamped(value: raw, generation: scanGeneration) }
        rawEnrichmentsByIP.removeAll()
        settledIPsThisScan.removeAll()
        scanGeneration += 1
        let oldest = scanGeneration - Self.rememberedScans
        identityByIP = identityByIP.filter { $0.value.generation >= oldest }
        upnpNameByIP = upnpNameByIP.filter { $0.value.generation >= oldest }
        carriedEnrichmentsByIP = carriedEnrichmentsByIP.filter { $0.value.generation >= oldest }
        ownAddressesThisScan = nil
        networkCIDRThisScan = nil
        holdingUntilFirstResult = true
        heldDevicesByID = Dictionary(devices.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
        heldServices = unattachedServices
    }

    private func currentOwnAddresses() -> LocalInterfaces.OwnAddresses {
        if let cached = ownAddressesThisScan { return cached }
        let addresses = ownAddressesProvider()
        ownAddressesThisScan = addresses
        return addresses
    }

    /// Fires the probe set for an address once per scan. A host known to be off this phone's networks (reflected from another VLAN)
    /// and an address the coordinator would refuse (not LAN-local) get no probes and count as settled instead of pending forever.
    /// `ip` is the row's effective address; probes go to `probeIP`, the group's first address on a connected subnet.
    private func dispatchProbesIfNeeded(ip: String, probeIP: String, locationURL: URL?, onLocalSubnet: Bool?) {
        if onLocalSubnet == false {
            skippedOffSubnetIPs.insert(ip)
            settledIPsThisScan.insert(ip)
            return
        }
        if skippedOffSubnetIPs.remove(ip) != nil { settledIPsThisScan.remove(ip) }
        probeTargetByIP[ip] = probeIP
        guard !enrichedIPsThisScan.contains(probeIP) else { return }
        enrichedIPsThisScan.insert(probeIP)
        guard SSDPDescriptionFetcher.isLANLocalAddress(probeIP) else {
            settledIPsThisScan.insert(probeIP)
            return
        }
        startVendorGate(ip: probeIP, locationURL: locationURL)
    }

    /// Reads ARP before anything is sent. An entry already present decides at once, a missing one waits (bounded) on a task, and the
    /// phone's own row and IPv6 addresses (no ARP) are never gated.
    private func startVendorGate(ip: String, locationURL: URL?) {
        let ownKeys = Set(currentOwnAddresses().all.map(LocalInterfaces.addressMatchKey))
        let first: ARPLookup = ip.contains(":") ? .hidden : arpLookup(ip)
        if ownKeys.contains(LocalInterfaces.addressMatchKey(ip)) {
            passVendorGate(ip: ip, locationURL: locationURL, arpMAC: first.mac)
            return
        }
        switch first {
        case .resolved(let mac):
            decideVendorGate(ip: ip, locationURL: locationURL, reading: .init(mac: mac, source: .arpTableLookup, sentTrigger: false), applyNow: false)
        case .hidden:
            passVendorGate(ip: ip, locationURL: locationURL, arpMAC: nil)
        case .missing:
            vendorGateByIP[ip] = .waiting
            let generation = scanGeneration
            let lookup = arpLookup, trigger = vendorGateTrigger(), timing = vendorGateTiming
            vendorGateTasks[ip] = Task { [weak self] in
                let reading = await PaymentVendorGate.waitForMAC(ip: ip, lookup: lookup, trigger: trigger, timing: timing)
                guard !Task.isCancelled, let self, self.scanGeneration == generation else { return }
                self.vendorGateTasks[ip] = nil
                self.decideVendorGate(ip: ip, locationURL: locationURL, reading: reading, applyNow: true)
            }
        }
    }

    /// The NBSTAT trigger the gate sends after its wait, nil when the T9 constant turns it off or a test seam stands in for the probes.
    private func vendorGateTrigger() -> ((String) async -> String?)? {
        guard PaymentVendorGate.sendsNBSTATTriggerAfterWait else { return nil }
        if let arpTriggerOverride { return arpTriggerOverride }
        guard probeOverride == nil else { return nil }
        let coordinator = enrichmentCoordinator
        return { await coordinator.arpTrigger(ip: $0) }
    }

    /// A payment vendor gets only its ARP and OUI facts and counts as settled; anything else gets the probe set and any held sends.
    /// `applyNow` is false inside a merge, which reads the stored result itself.
    private func decideVendorGate(ip: String, locationURL: URL?, reading: PaymentVendorGate.Reading, applyNow: Bool) {
        guard let mac = reading.mac,
              let skip = PaymentVendorGate.vendorSkip(forMAC: mac, sentTrigger: reading.sentTrigger, vendorLookup: ouiDB.manufacturer(for:)) else {
            passVendorGate(ip: ip, locationURL: locationURL, arpMAC: reading.source == .arpTableLookup ? reading.mac : nil)
            return
        }
        vendorGateByIP[ip] = .skipped
        paymentSkipByIP[ip] = skip
        heldDescriptionURLByIP[ip] = nil
        heldGoogleWifiIPs.remove(ip)
        let passive = DeviceEnrichment(mac: mac, manufacturer: ouiDB.manufacturer(for: mac), inferredOS: nil, openPorts: [], source: reading.source)
        if applyNow { ingestEnrichment(ip: ip, enrichments: [passive]) } else { store(ip: ip, enrichments: [passive], completesProbeSet: true) }
    }

    private func passVendorGate(ip: String, locationURL: URL?, arpMAC: String?) {
        vendorGateByIP[ip] = .passed
        if let probeOverride { probeOverride(ip, locationURL) } else { enrichmentCoordinator.enrich(ip: ip, locationURL: locationURL, arpMAC: arpMAC) }
        if let url = heldDescriptionURLByIP.removeValue(forKey: ip) { sendDescriptionFetch(ip: ip, locationURL: url) }
        if heldGoogleWifiIPs.remove(ip) != nil { sendGoogleWifi(ip: ip) }
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

    enum LaunchGateAction: Equatable { case none, scan, restart }

    struct LaunchGatePlan: Equatable {
        var settles: Bool
        var action: LaunchGateAction
        var autoScanNeedsRedo: Bool
    }

    /// What to do with a launch gate result: only a grant settles it, the first scan runs once, and a grant after an unpermitted scan restarts it.
    nonisolated static func launchGatePlan(decision: LocalNetworkPermissionGate.Decision, hasScanned: Bool, autoScanNeedsRedo: Bool) -> LaunchGatePlan {
        if decision == .granted {
            let action: LaunchGateAction = autoScanNeedsRedo ? .restart : (hasScanned ? .none : .scan)
            return LaunchGatePlan(settles: true, action: action, autoScanNeedsRedo: false)
        }
        return LaunchGatePlan(settles: false, action: hasScanned ? .none : .scan, autoScanNeedsRedo: hasScanned ? autoScanNeedsRedo : true)
    }

    /// Never starts in the background, where iOS denies the operation without showing or recording the alert (TN3179).
    nonisolated static func shouldStartLaunchGate(settled: Bool, inFlight: Bool, isActive: Bool) -> Bool {
        !settled && !inFlight && isActive
    }

    /// Runs the Local Network check and the first scan once the splash is gone and the app is active; safe to call on every foreground.
    func startLaunchGateIfNeeded(isActive: Bool) {
        guard Self.shouldStartLaunchGate(settled: launchGateSettled, inFlight: launchGateInFlight, isActive: isActive) else { return }
        launchGateInFlight = true
        Task {
            let decision = await LocalNetworkPermissionGate.waitForDecision()
            launchGateInFlight = false
            apply(permissionDecision: decision)
            let plan = Self.launchGatePlan(decision: decision, hasScanned: hasScannedAtLeastOnce, autoScanNeedsRedo: autoScanNeedsRedo)
            launchGateSettled = plan.settles
            autoScanNeedsRedo = plan.autoScanNeedsRedo
            switch plan.action {
            case .scan:    startScan()
            case .restart: restartScan()
            case .none:    break
            }
        }
    }

    func apply(permissionDecision decision: LocalNetworkPermissionGate.Decision) {
        isLocalNetworkDenied = decision.showsDeniedBanner(current: isLocalNetworkDenied)
    }

    /// Cached once a prefix is found; "Unknown" is never cached, so a link that comes up before the first scan is still picked up.
    var networkCIDR: String {
        if let cached = networkCIDRThisScan { return cached }
        let cidr: String
        if let subnet = currentOwnAddresses().primarySubnet {
            cidr = subnet.cidr
        } else if let prefix = localUtil.getLocalIPPrefix(), !prefix.isEmpty {
            cidr = "\(prefix)0/24"
        } else { return "Unknown" }
        networkCIDRThisScan = cidr
        return cidr
    }

    /// Stores a probe result under the address it probed and rebuilds the rows; only a full probe set settles the address and retires
    /// its carried result. While the scan start still holds the previous list, the result is stored without rebuilding last scan's rows.
    func ingestEnrichment(ip: String, enrichments: [DeviceEnrichment], completesProbeSet: Bool = true, upnpName: String? = nil) {
        if let upnpName { upnpNameByIP[ip] = Stamped(value: upnpName, generation: scanGeneration) }
        store(ip: ip, enrichments: enrichments, completesProbeSet: completesProbeSet)
        guard !holdingUntilFirstResult else { return }
        apply(raw: lastRaw)
    }

    private func store(ip: String, enrichments: [DeviceEnrichment], completesProbeSet: Bool) {
        rawEnrichmentsByIP[ip, default: []].append(contentsOf: enrichments)
        if completesProbeSet {
            settledIPsThisScan.insert(ip)
            carriedEnrichmentsByIP.removeValue(forKey: ip)
        }
    }

    /// Merges and publishes, assigning only when the result changed so SwiftUI and the assess pipeline see real changes only.
    func apply(raw: [NetworkScanner.Device]) {
        lastRaw = raw
        holdingUntilFirstResult = false
        let merged = overlayingHeld(mergeScan(raw: raw), raw: raw)
        if merged.devices != devices { devices = merged.devices }
        if merged.services != unattachedServices { unattachedServices = merged.services }
    }

    /// Adds last scan's rows and services that this scan has not re-resolved yet. A service whose resolve settled this scan is final
    /// (live wins, even when it failed); an unsettled one is carried. A held row this scan has not found stays whole.
    private func overlayingHeld(_ merged: ScanMerge, raw: [NetworkScanner.Device]) -> ScanMerge {
        guard !heldDevicesByID.isEmpty || !heldServices.isEmpty else { return merged }
        let settledKeys = Set(raw.filter { $0.resolveSettled && $0.serviceType.hasPrefix("_") }.map { "\($0.serviceType)|\($0.serviceName)" })
        var devices = merged.devices
        for held in heldDevicesByID.values.sorted(by: { $0.ipAddress < $1.ipAddress }) {
            if let i = devices.firstIndex(where: { $0.id == held.id }) ?? devices.firstIndex(where: { $0.ipAddress == held.ipAddress }) {
                for service in held.bonjourServices where !settledKeys.contains(service.id) && !devices[i].bonjourServices.contains(where: { $0.id == service.id }) {
                    devices[i].bonjourServices.append(service)
                }
                devices[i].addresses = Self.orderedAddresses(Set(devices[i].addresses).union(held.addresses))
            } else {
                devices.append(held)
            }
        }
        devices.sort { $0.ipAddress < $1.ipAddress }
        var services = merged.services
        let attachedKeys = Set(devices.flatMap(\.bonjourServices).map(\.id))
        let liveServiceIDs = Set(services.map(\.id))
        for held in heldServices where !liveServiceIDs.contains(held.id) && !attachedKeys.contains("\(held.serviceType)|\(held.name)") {
            services.append(held)
        }
        services.sort { ($0.name, $0.typeLabel, $0.id) < ($1.name, $1.typeLabel, $1.id) }
        return ScanMerge(devices: devices, services: services)
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
        /// The display name for an address with no Bonjour host name, chosen from every row at the address by tier, not by arrival.
        var fallbackNameByIP: [String: String]
        /// Addresses seen on host-keyed rows mapped to that host key, for the cross-scan identity memory; address-keyed groups are left out.
        var hostIdentityByAddress: [String: String]
    }

    /// Plans a merge. One host's services can each resolve to a different address (LAN IPv4, self-assigned 169.254, or IPv6), so
    /// every row sharing a host key collapses onto that host's preferred address; `remembered` is the identity memory from past scans.
    nonisolated static func plan(raw: [NetworkScanner.Device], own: LocalInterfaces.OwnAddresses,
                                 remembered: [String: String], upnpNames: [String: String] = [:]) -> MergePlan {
        var addressesByHost: [String: [String]] = [:]
        for device in raw {
            if let key = device.hostKey, let ip = device.resolvedIPAddress { addressesByHost[key, default: []].append(ip) }
        }
        func isLANIPv4(_ ip: String) -> Bool { !ip.contains(":") && !ip.hasPrefix("169.254.") }
        // A host-less row (sweep, SSDP) at a LAN IPv4 remembered for a host in this merge joins that host when the host's own
        // resolves carry no LAN IPv4 yet, so the host's address does not depend on which record a resolve reported first.
        let adoptedKeyByRow: [String?] = raw.map { device in
            guard device.hostKey == nil, let ip = device.resolvedIPAddress, isLANIPv4(ip), let key = remembered[ip],
                  let resolved = addressesByHost[key], !resolved.contains(where: isLANIPv4) else { return nil }
            return key
        }
        for (device, key) in zip(raw, adoptedKeyByRow) {
            if let key, let ip = device.resolvedIPAddress { addressesByHost[key, default: []].append(ip) }
        }
        let addressByHost = addressesByHost.compactMapValues { NetworkScanner.preferredAddress(from: $0) }
        let keyByRow: [String?] = zip(raw, adoptedKeyByRow).map { $0.hostKey ?? $1 }
        let hostIPs: [String?] = zip(raw, keyByRow).map { device, key in key.flatMap { addressByHost[$0] } ?? device.resolvedIPAddress }

        // This device: any group holding one of the phone's own addresses on any interface (a set intersection on zone-free keys,
        // since it has several IPv6 addresses) folds onto the phone's Wi-Fi IPv4, so it is listed under 192.168.x.y rather than an
        // fe80 address. It is never hidden.
        var rawAddressesByHostIP: [String: Set<String>] = [:]
        for (device, hostIP) in zip(raw, hostIPs) {
            guard let hostIP else { continue }
            rawAddressesByHostIP[hostIP, default: [hostIP]].formUnion(device.resolvedAddresses.union([device.resolvedIPAddress ?? hostIP]))
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
        for (key, ip) in zip(keyByRow, effectiveIPByRow) {
            if let ip, let key { hostKeysByIP[ip, default: []].insert(key) }
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
            addressesByEffectiveIP[ip, default: [ip]].formUnion(device.resolvedAddresses.union([device.resolvedIPAddress ?? ip]))
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
        // No host name: a Bonjour instance name beats a RAOP "MAC@Name" one, which beats the UPnP friendly name, and anything else falls back
        // to the address (the SSDP SERVER header and a bare USN are never names). Within a tier the smallest wins, so the name never
        // depends on which row arrived first.
        var fallbackNameByIP: [String: (tier: Int, name: String)] = [:]
        func offer(_ ip: String, _ tier: Int, _ name: String) {
            if let current = fallbackNameByIP[ip], (current.tier, current.name) <= (tier, name) { return }
            fallbackNameByIP[ip] = (tier, name)
        }
        for (device, ip) in zip(raw, effectiveIPByRow) {
            guard let ip, hostNameByIP[ip] == nil, device.serviceType.hasPrefix("_") else { continue }
            let name = device.identifier
            offer(ip, name.contains("@") ? 1 : 0, name)
        }
        for ip in Set(effectiveIPByRow.compactMap { $0 }) where hostNameByIP[ip] == nil {
            for address in addressesByEffectiveIP[ip] ?? [ip] { if let name = upnpNames[address] { offer(ip, 2, name) } }
        }
        return MergePlan(effectiveIPByRow: effectiveIPByRow, identityByEffectiveIP: identityByEffectiveIP,
                         addressesByEffectiveIP: addressesByEffectiveIP, hostNameByIP: hostNameByIP,
                         fallbackNameByIP: fallbackNameByIP.mapValues(\.name),
                         hostIdentityByAddress: hostIdentityByAddress)
    }

    /// Builds the device rows from the scanner's raw results. `openPorts` is never seeded from `Device.port`: that port is only
    /// advertised (Bonjour resolve or SSDP LOCATION) and stays on the service; open ports arrive solely via the enrichment sink.
    /// A row with no address of its own borrows its host's (matched by `Device.hostKey`); a row with neither is a service, not a device.
    func mergeScan(raw: [NetworkScanner.Device]) -> ScanMerge {
        let own = currentOwnAddresses()
        let plan = Self.plan(raw: raw, own: own, remembered: identityByIP.mapValues(\.value),
                             upnpNames: upnpNameByIP.mapValues(\.value))
        for (address, identity) in plan.hostIdentityByAddress {
            identityByIP[address] = Stamped(value: identity, generation: scanGeneration)
        }
        let identityByEffectiveIP = plan.identityByEffectiveIP
        let addressesByEffectiveIP = plan.addressesByEffectiveIP
        let hostNameByIP = plan.hostNameByIP
        let fallbackNameByIP = plan.fallbackNameByIP
        var byIP: [String: DiscoveredDevice] = [:]

        var services: [DiscoveredService] = []
        for (device, ip) in zip(raw, plan.effectiveIPByRow) {
            guard let ip else {
                // A Bonjour row whose resolve has not answered yet is neither a device nor a service, so it never flashes a services node.
                guard device.resolveSettled else { continue }
                // The id uses the dot-stripped type key; the displayed serviceType stays exactly as received.
                services.append(DiscoveredService(id: "\(device.serviceTypeKey)|\(device.serviceName)|\(device.serviceDomain)",
                                                  name: device.friendlyName ?? device.ssdpServer ?? device.serviceName, serviceType: device.serviceType,
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
                if let server = device.ssdpServer { existing.ssdpServer = min(existing.ssdpServer ?? server, server) }
                if existing.manufacturer == nil {
                    existing.manufacturer = appleManufacturer(serviceType: device.serviceType, txtRecords: device.txtRecords)
                }
                byIP[ip] = existing
                dispatchDescriptionFetchIfNeeded(ip: ip, locationURL: device.locationURL, onLocalSubnet: existing.isOnLocalSubnet)
                dispatchGoogleWifiIfNeeded(ip: ip, serviceType: device.serviceType, onLocalSubnet: existing.isOnLocalSubnet)
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
                let onLocalSubnet = LocalInterfaces.isOnLocalSubnet(addresses: Array(group), subnets: own.ipv4Subnets)
                let probeIP = group.sorted(by: NetworkScanner.isAddressOrdered)
                    .first { LocalInterfaces.isOnLocalSubnet(addresses: [$0], subnets: own.ipv4Subnets) == true } ?? ip
                dispatchProbesIfNeeded(ip: ip, probeIP: probeIP, locationURL: device.locationURL, onLocalSubnet: onLocalSubnet)
                var newDevice = DiscoveredDevice(
                    id:              stableID(forIdentity: identity, ip: ip),
                    hostname:        hostNameByIP[ip] ?? fallbackNameByIP[ip] ?? ip,
                    ipAddress:       ip,
                    macAddress:      mac,
                    manufacturer:    mfr,
                    inferredOS:      os,
                    bonjourServices: svc.map { [$0] } ?? [],
                    probesSettled:   probesSettled(forAddresses: group),
                    addresses:       Self.orderedAddresses(group)
                )
                newDevice.ssdpServer = device.ssdpServer
                newDevice.isDefaultGateway = own.gatewaysIPv4.isEmpty ? nil : !own.gatewaysIPv4.filter(group.contains).isEmpty
                newDevice.isOnLocalSubnet = onLocalSubnet
                newDevice.paymentVendorSkip = group.sorted().lazy.compactMap { self.paymentSkipByIP[$0] }.first
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
                    newDevice.httpRedirectByPort = merged.httpRedirectByPort
                }
                byIP[ip] = newDevice
                dispatchDescriptionFetchIfNeeded(ip: ip, locationURL: device.locationURL, onLocalSubnet: onLocalSubnet)
                dispatchGoogleWifiIfNeeded(ip: ip, serviceType: device.serviceType, onLocalSubnet: onLocalSubnet)
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

    /// Fires the SSDP description fetch the first time any row for this IP reveals a `locationURL`, once the vendor gate allows it.
    private func dispatchDescriptionFetchIfNeeded(ip: String, locationURL: URL?, onLocalSubnet: Bool?) {
        guard onLocalSubnet != false, let locationURL, !fetchedDescriptionIPs.contains(ip) else { return }
        fetchedDescriptionIPs.insert(ip)
        let target = probeTargetByIP[ip] ?? ip
        switch vendorGateByIP[target] {
        case .skipped:         return
        case .waiting:         heldDescriptionURLByIP[target] = locationURL
        case .passed, .none:   sendDescriptionFetch(ip: target, locationURL: locationURL)
        }
    }

    private func sendDescriptionFetch(ip: String, locationURL: URL) {
        if let descriptionFetchOverride { descriptionFetchOverride(ip, locationURL) } else { enrichmentCoordinator.enrichDescription(ip: ip, locationURL: locationURL) }
    }

    /// Fires the Google Wifi probe only for hosts that advertise `_googlecast._tcp`, never blindly, and only once the vendor gate allows it.
    private func dispatchGoogleWifiIfNeeded(ip: String, serviceType: String, onLocalSubnet: Bool?) {
        guard onLocalSubnet != false, serviceType == "_googlecast._tcp", !fetchedGoogleWifiIPs.contains(ip) else { return }
        fetchedGoogleWifiIPs.insert(ip)
        let target = probeTargetByIP[ip] ?? ip
        switch vendorGateByIP[target] {
        case .skipped:         return
        case .waiting:         heldGoogleWifiIPs.insert(target)
        case .passed, .none:   sendGoogleWifi(ip: target)
        }
    }

    private func sendGoogleWifi(ip: String) {
        if let googleWifiOverride { googleWifiOverride(ip) } else { enrichmentCoordinator.enrichGoogleWifi(ip: ip) }
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
