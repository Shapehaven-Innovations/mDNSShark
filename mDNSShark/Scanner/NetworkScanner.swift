//NetworkScanner.swift

import SwiftUI
import Network
import Combine
import CoreFoundation
import os
import Darwin

// MARK: - NetworkScanner
class NetworkScanner: NSObject, ObservableObject, NetServiceDelegate {
    @Published var devices: [Device] = []
    // Logs every transition with seconds since scan start, to debug reports of the Scan button re-enabling early.
    @Published var isScanning: Bool = false {
        didSet {
            guard oldValue != isScanning else { return }
            let now = Date()
            if isScanning { scanStartedAt = now }
            let sinceStart = scanStartedAt.map { now.timeIntervalSince($0) } ?? 0
            logger.debug("isScanning -> \(self.isScanning) at \(now.timeIntervalSince1970, format: .fixed(precision: 3)) (\(sinceStart, format: .fixed(precision: 2))s since scan start)")
        }
    }
    private var scanStartedAt: Date?

    // List of service types to search for
    private let serviceTypes: [String] = [
        // MARK: - Common Services
        "_http._tcp",
        "_https._tcp",
        "_ftp._tcp",
        "_ssh._tcp",
        "_telnet._tcp",
        "_smb._tcp",
        "_afpovertcp._tcp",
        "_nfs._tcp",
        "_workstation._tcp",

        // MARK: - Apple / macOS / iOS Services
        "_airdrop._tcp",
        "_airplay._tcp",
        "_apple-mobdev2._tcp",
        "_adisk._tcp",
        "_time-machine._tcp",
        "_airport._tcp",
        "_device-info._tcp",
        "_companion-link._tcp",
        "_rdlink._tcp",
        "_sleep-proxy._udp",

        // MARK: - Printing & Scanning
        "_ipp._tcp",
        "_ipps._tcp",
        "_printer._tcp",
        "_pdl-datastream._tcp",
        "_scanner._tcp",

        // MARK: - Media & Streaming
        "_raop._tcp",
        "_daap._tcp",
        "_dacp._tcp",
        "_spotify-connect._tcp",
        "_googlecast._tcp",

        // MARK: - File Sharing & Sync
        "_bluetoothd2._tcp",
        "_btsync._tcp",
        "_distcc._tcp",
        "_webdav._tcp",

        // MARK: - Remote Screen / Management
        "_rfb._tcp",
        "_remotemanagement._tcp",

        // MARK: - IoT / HomeKit / Presence
        "_hap._tcp",
        "_presence._tcp",
        "_mqtt._tcp",
        "_coap._udp",
        "_peertalk._tcp",

        // MARK: - Security & Other
        "_time._udp",
        "_timedate._udp",
        "_tcpchat._tcp",
        "_acp-sync._tcp",

        // MARK: - Newly Added (Wireless / Common)
        "_touch-able._tcp",
        "_airpod._tcp",
        "_teamviewer._tcp",
        "_vnc._tcp",
        "_sftp-ssh._tcp",
        "_octoprint._tcp",
        "_xbmc-jsonrpc._tcp",
        "_plexmediasvr._tcp"
    ]
    
    // Dedicated queue for Bonjour browser tasks.
    private let bonjourQueue = DispatchQueue(label: "com.mDNSShark.bonjourQueue")
    
    private var bonjourBrowsers: [NWBrowser] = []
    private var serviceToDeviceId: [ObjectIdentifier: UUID] = [:]
    // Strong references for in-flight resolves: NetService.schedule(in:forMode:) does not retain it, so without this it is deallocated mid-resolve.
    // Held until netServiceDidStop or didNotResolve, because the resolve keeps reporting addresses until its timeout.
    private var activeNetServices: [ObjectIdentifier: NetService] = [:]
    // Services whose DNS-SD fallback already started, so a second address-less callback does not start another.
    private var fallbackStarted = Set<ObjectIdentifier>()
    
    // Logger
    private let logger = Logger(subsystem: "com.mDNSShark", category: "NetworkScanner")
    
    // Instance of the local subnet scanner.
    private let localScanner = LocalDeviceScanner()
    private var cancellables = Set<AnyCancellable>()
    // Held so cancelScan() can stop the pending end-of-scan block from ending a restarted scan early.
    private var scanEndWorkItem: DispatchWorkItem?
    // Held as one replaceable subscription so repeated scans do not stack duplicate $discoveredIPs sinks.
    private var discoveredIPsSubscription: AnyCancellable?
    // Held so cancelScan() can close the previous scan's SSDP socket instead of leaving it listening.
    private var ssdpSource: DispatchSourceRead?

    // A device discovered on the network.
    class Device: ObservableObject, Identifiable {
        let id = UUID()
        let serviceName: String
        let serviceDomain: String
        let serviceType: String
        /// `serviceType` with one trailing dot stripped, for ids and matching; the displayed type stays as received.
        let serviceTypeKey: String

        @Published var resolvedIPAddress: String? = nil
        @Published var friendlyName: String? = nil
        @Published var model: String? = nil
        @Published var port: Int? = nil
        @Published var txtRecords: [String: String]? = nil
        @Published var locationURL: URL? = nil
        /// Host name as received (e.g. "Users-MacBook-Pro.local."), kept for display. Set by a Bonjour resolve, the fallback resolver or an SSDP DNS-named LOCATION.
        var hostName: String? {
            didSet { hostKey = Self.normalizedHostKey(hostName) }
        }
        /// `hostName` lowercased with one trailing dot stripped: the identity shared by every service one host advertises.
        private(set) var hostKey: String?
        /// False until the resolve answered (address, host-only fallback, or failure); sweep and SSDP rows are born settled.
        var resolveSettled = false

        static func normalizedHostKey(_ host: String?) -> String? {
            guard let lowered = host?.lowercased(), !lowered.isEmpty else { return nil }
            let key = lowered.hasSuffix(".") ? String(lowered.dropLast()) : lowered
            return key.isEmpty ? nil : key
        }
        
        var identifier: String { friendlyName ?? serviceName }
        
        init(serviceName: String, serviceDomain: String, serviceType: String) {
            self.serviceName = serviceName
            self.serviceDomain = serviceDomain
            self.serviceType = serviceType
            self.serviceTypeKey = serviceType.hasSuffix(".") ? String(serviceType.dropLast()) : serviceType
        }
    }
    
    // MARK: - Public Scanning Method
    /// Starts a network scan with the given duration.
    func scanNetwork(duration: TimeInterval = 25.0) {
        guard !isScanning else {
            logger.debug("Scan already in progress.")
            return
        }
        // Cancel any existing browsers and clear previous results.
        for browser in bonjourBrowsers { browser.cancel() }
        bonjourBrowsers.removeAll()
        devices.removeAll()
        isScanning = true
        stopActiveResolves()
        logger.info("Starting network scan for service types: \(self.serviceTypes)")
        
        // Start Bonjour scanning.
        for type in self.serviceTypes {
            createAndStartBrowser(for: type)
        }
        
        // Start SSDP scanning with the provided duration.
        scanSSDP(duration: duration)
        
        // Start local TCP subnet scanning.
        localScanner.scanLocalSubnet(port: NWEndpoint.Port(rawValue: 80)!)
        discoveredIPsSubscription = localScanner.$discoveredIPs
            .sink { [weak self] ips in
                guard let self = self else { return }
                for ip in ips {
                    if !self.devices.contains(where: { $0.resolvedIPAddress == ip }) {
                        let device = Device(serviceName: ip, serviceDomain: "local", serviceType: "tcp")
                        device.resolvedIPAddress = ip
                        device.resolveSettled = true
                        self.devices.append(device)
                        self.logger.info("Local scan discovered device at IP: \(ip)")
                    }
                }
            }

        // End the scan after the specified duration.
        let endWorkItem = DispatchWorkItem { [weak self] in
            guard let self = self else { return }
            for browser in self.bonjourBrowsers { browser.cancel() }
            self.bonjourBrowsers.removeAll()
            self.isScanning = false
            self.scanEndWorkItem = nil
            self.logger.info("Scan ended after \(duration) seconds.")
        }
        scanEndWorkItem = endWorkItem
        DispatchQueue.main.asyncAfter(deadline: .now() + duration, execute: endWorkItem)
    }

    /// Stops an in-flight scan immediately so a fresh one can start, and does nothing when no scan is running.
    func cancelScan() {
        guard isScanning else { return }
        scanEndWorkItem?.cancel()
        scanEndWorkItem = nil
        for browser in bonjourBrowsers { browser.cancel() }
        bonjourBrowsers.removeAll()
        ssdpSource?.cancel()
        ssdpSource = nil
        discoveredIPsSubscription?.cancel()
        discoveredIPsSubscription = nil
        stopActiveResolves()
        isScanning = false
        logger.info("Scan cancelled for restart.")
    }

    /// Stops every in-flight resolve and drops its references first, so the callbacks a stop() triggers find no mapping and return.
    private func stopActiveResolves() {
        let inFlight = Array(activeNetServices.values)
        activeNetServices.removeAll()
        serviceToDeviceId.removeAll()
        fallbackStarted.removeAll()
        for service in inFlight { service.stop() }
    }
    
    // MARK: - Bonjour Scanning
    private func createAndStartBrowser(for serviceType: String) {
        let descriptor = NWBrowser.Descriptor.bonjour(type: serviceType, domain: nil)
        let parameters: NWParameters = serviceType.contains("_udp") ? .udp : .tcp
        let browser = NWBrowser(for: descriptor, using: parameters)
        let capturedServiceType: String = serviceType
        
        browser.stateUpdateHandler = { [weak self] (state: NWBrowser.State) -> Void in
            guard let self = self else { return }
            self.logger.info("Bonjour browser for \(capturedServiceType) state: \(String(describing: state))")
            if case .failed(let error) = state {
                self.logger.error("Bonjour browser for \(capturedServiceType) failed: \(error.localizedDescription)")
            }
        }
        
        browser.browseResultsChangedHandler = { [weak self] (results: Set<NWBrowser.Result>, changes: Set<NWBrowser.Result.Change>) -> Void in
            guard let self = self else { return }
            self.processBrowseResults(results)
        }
        
        browser.start(queue: bonjourQueue)
        bonjourBrowsers.append(browser)
    }
    
    private func processBrowseResults(_ results: Set<NWBrowser.Result>) {
        for result in results {
            switch result.endpoint {
            case .service(let name, let type, let domain, _):
                // Never surface this app's own Bonjour preflight probe
                // (LocalNetworkPermissionGate.swift) as a discovered device.
                // The prefix check tolerates the type with or without a trailing dot (devices have reported it undotted).
                guard !type.hasPrefix("_mdnssharklnp._tcp"),
                      !name.hasPrefix("_mdnssharklnp._tcp") else { continue }
                DispatchQueue.main.async {
                    if !self.devices.contains(where: { $0.serviceName == name &&
                        $0.serviceDomain == domain &&
                        $0.serviceType == type }) {
                        let device = Device(serviceName: name, serviceDomain: domain, serviceType: type)
                        self.devices.append(device)
                        self.logger.info("Bonjour discovered: \(name) in domain: \(domain) of type: \(type)")
                        self.resolveService(name: name, type: type, domain: domain)
                    }
                }
            default:
                break
            }
        }
    }
    
    private func resolveService(name: String, type: String, domain: String) {
        let netService = NetService(domain: domain, type: type, name: name)
        netService.delegate = self
        netService.schedule(in: RunLoop.main, forMode: .common)
        // Must outlive this function's scope until a delegate callback
        // fires; see the activeNetServices doc comment above.
        activeNetServices[ObjectIdentifier(netService)] = netService
        if let device = self.devices.first(where: { $0.serviceName == name &&
                                                     $0.serviceDomain == domain &&
                                                     $0.serviceType == type }) {
            serviceToDeviceId[ObjectIdentifier(netService)] = device.id
            // Backstop for a resolve whose fallback never calls back, so the row cannot stay hidden as pending forever.
            DispatchQueue.main.asyncAfter(deadline: .now() + Self.resolveSettleTimeout) { [weak self] in
                guard let self, !device.resolveSettled else { return }
                self.settleResolve(device, reason: "timed out")
            }
        }
        logger.info("Resolving service: \(name) \(type) \(domain)")
        netService.resolve(withTimeout: 10.0)
    }

    /// Longer than the NetService resolve timeout so it only fires when neither delegate path nor the fallback resolver settled the row.
    static let resolveSettleTimeout: TimeInterval = 15.0

    /// Marks a row's resolve as answered and republishes so the view model stops holding it back. Main queue only.
    private func settleResolve(_ device: Device, reason: String) {
        device.resolveSettled = true
        logger.debug("Resolve settled (\(reason)): name=\(device.serviceName) type=\(device.serviceType) hostName=\(device.hostName ?? "nil") ip=\(device.resolvedIPAddress ?? "nil")")
        republishDevices()
    }
    
    // MARK: - SSDP/UPnP Scanning via UDP
    private func scanSSDP(duration: TimeInterval) {
        let ssdpAddress = "239.255.255.250"
        let ssdpPort: UInt16 = 1900
        let ssdpMessage = """
        M-SEARCH * HTTP/1.1\r
        HOST: 239.255.255.250:1900\r
        MAN: "ssdp:discover"\r
        MX: 3\r
        ST: ssdp:all\r
        \r\n
        """
        
        let sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
        if sock < 0 {
            logger.error("SSDP socket creation failed")
            return
        }
        
        var ttl: Int32 = 2
        setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, socklen_t(MemoryLayout<Int32>.size))
        
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = ssdpPort.bigEndian
        inet_pton(AF_INET, ssdpAddress, &addr.sin_addr)
        
        let sendResult = ssdpMessage.withCString { ptr -> ssize_t in
            return withUnsafePointer(to: &addr) { addrPtr in
                addrPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                    sendto(sock, ptr, strlen(ptr), 0, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        
        if sendResult < 0 {
            logger.error("SSDP sendto failed")
            close(sock)
            return
        }
        logger.info("SSDP M-SEARCH message sent.")
        
        let source = DispatchSource.makeReadSource(fileDescriptor: sock, queue: DispatchQueue.global())
        source.setEventHandler { [weak self] in
            var buffer = [UInt8](repeating: 0, count: 1024)
            let count = recv(sock, &buffer, buffer.count, 0)
            if count > 0 {
                let data = Data(buffer[0..<count])
                if let response = String(data: data, encoding: .utf8) {
                    self?.logger.info("Received SSDP response: \(response)")
                    self?.parseSSDPResponse(response)
                } else {
                    self?.logger.debug("Received non-string SSDP data")
                }
            }
        }
        source.setCancelHandler {
            close(sock)
        }
        source.resume()
        ssdpSource = source

        DispatchQueue.global().asyncAfter(deadline: .now() + duration) {
            source.cancel()
        }
    }
    
    private func parseSSDPResponse(_ response: String) {
        let lines = response.components(separatedBy: "\r\n")
        var headers: [String: String] = [:]
        for line in lines {
            if let separatorRange = line.range(of: ":") {
                let key = line[..<separatorRange.lowerBound].trimmingCharacters(in: .whitespaces).lowercased()
                let value = line[separatorRange.upperBound...].trimmingCharacters(in: .whitespaces)
                headers[key] = value
            }
        }
        guard let location = headers["location"] else {
            logger.debug("SSDP response missing LOCATION header: \(response)")
            return
        }
        let usn = headers["usn"] ?? location
        let server = headers["server"] ?? "SSDP Device"
        
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            if !self.devices.contains(where: { $0.serviceName == usn && $0.serviceDomain == "ssdp" }) {
                let device = Device(serviceName: usn, serviceDomain: "ssdp", serviceType: "ssdp")
                device.friendlyName = server
                if let url = URL(string: location), let host = url.host {
                    // A DNS-named LOCATION has no address yet; keep the name so the row can attach by host or show as a service.
                    if Self.isIPAddressLiteral(host) { device.resolvedIPAddress = host } else { device.hostName = host }
                    device.port = url.port ?? 80
                    device.locationURL = url
                }
                device.resolveSettled = true
                self.devices.append(device)
                self.logger.info("SSDP discovered device: \(usn) at \(location)")
            }
        }
    }
    
    // MARK: - NetServiceDelegate
    /// Sent once per address found while the resolve runs to its timeout (see NetService.resolve(withTimeout:)), so the service
    /// stays alive here and the row is recomputed from every address known so far; release happens in didStop or didNotResolve.
    func netServiceDidResolveAddress(_ sender: NetService) {
        let key = ObjectIdentifier(sender)
        guard activeNetServices[key] != nil, let deviceID = serviceToDeviceId[key],
              let device = devices.first(where: { $0.id == deviceID }) else {
            // Expected after cancelScan or a restart released the resolve; the late callback has nothing to update.
            logger.debug("No device mapping for resolved service \(sender.name)")
            return
        }
        let parsed = (sender.addresses ?? []).compactMap { Self.ipAddress(fromSockaddr: $0) }
        logger.debug("Resolved service: name=\(sender.name) type=\(sender.type) hostName=\(sender.hostName ?? "nil") addresses=\(parsed)")
        // A host that also has a self-assigned 169.254 address answers with both IPv4s in no fixed order, so pick by preference rather than arrival.
        guard let foundIP = Self.preferredAddress(from: parsed) else {
            logger.warning("No valid IP parsed yet for \(sender.name)")
            startFallbackResolveIfNeeded(for: sender, device: device)
            return
        }
        let txt = Self.txtRecords(from: sender.txtRecordData())
        let hostName = sender.hostName
        let port = sender.port
        DispatchQueue.main.async {
            device.resolvedIPAddress = foundIP
            if let hostName { device.hostName = hostName }
            if port > 0 { device.port = port }
            if let txt, !txt.isEmpty {
                device.txtRecords = txt
                if let friendly = txt["fn"] ?? txt["n"], !friendly.isEmpty { device.friendlyName = friendly }
                if let model = txt["md"], !model.isEmpty { device.model = model }
            }
            self.logger.info("Resolved \(sender.name) to IP: \(foundIP) on port: \(port) from \(parsed.count) address(es)")
            // Settled on the first address so the row shows promptly; later callbacks only refine and republish it.
            self.settleResolve(device, reason: "address")
        }
    }

    /// Sent when the resolve reached its timeout or was stopped; the one place a service that found addresses is released.
    func netServiceDidStop(_ sender: NetService) {
        guard let device = releaseResolve(for: sender) else { return }
        logger.debug("Resolve stopped: name=\(sender.name) ip=\(device.resolvedIPAddress ?? "nil")")
        DispatchQueue.main.async {
            guard !device.resolveSettled else { return }
            self.settleResolve(device, reason: "stopped without an address")
        }
    }

    func netService(_ sender: NetService, didNotResolve errorDict: [String : NSNumber]) {
        logger.error("Failed to resolve \(sender.name) with error: \(errorDict)")
        // A failed row still counts as answered: it is shown as a service instead of being held back as pending.
        guard let device = releaseResolve(for: sender) else { return }
        DispatchQueue.main.async {
            guard !device.resolveSettled else { return }
            self.settleResolve(device, reason: "did not resolve")
        }
    }

    /// Drops the strong reference and mapping for a finished resolve; nil when already released, so a repeated callback is a no-op.
    private func releaseResolve(for sender: NetService) -> Device? {
        let key = ObjectIdentifier(sender)
        guard activeNetServices.removeValue(forKey: key) != nil else { return nil }
        fallbackStarted.remove(key)
        guard let deviceID = serviceToDeviceId.removeValue(forKey: key) else { return nil }
        return devices.first(where: { $0.id == deviceID })
    }

    /// The DNS-SD fallback, started once per service when a resolve callback carried no usable address.
    private func startFallbackResolveIfNeeded(for sender: NetService, device: Device) {
        let key = ObjectIdentifier(sender)
        guard !fallbackStarted.contains(key) else { return }
        fallbackStarted.insert(key)
        logger.info("Attempting fallback resolution for \(sender.name)")
        DNSServiceResolver.resolve(name: sender.name, type: sender.type, domain: sender.domain) { host, port in
            DispatchQueue.main.async {
                // A real address that arrived meanwhile wins; the fallback only ever names the host.
                guard device.resolvedIPAddress == nil else { return }
                if let host, let port {
                    device.hostName = host
                    device.port = Int(port)
                    self.logger.info("Fallback resolved \(sender.name) to host: \(host) on port: \(port)")
                    self.settleResolve(device, reason: "fallback host")
                } else {
                    self.logger.error("Fallback resolution failed for \(sender.name)")
                    self.settleResolve(device, reason: "fallback failed")
                }
            }
        }
    }

    /// TXT record values as UTF-8 strings, raw; entries that are not UTF-8 are left out.
    private static func txtRecords(from data: Data?) -> [String: String]? {
        guard let data else { return nil }
        var records: [String: String] = [:]
        for (key, value) in NetService.dictionary(fromTXTRecord: data) {
            if let text = String(data: value, encoding: .utf8) { records[key] = text }
        }
        return records
    }

    /// True for an IPv4 or IPv6 literal (an optional "%zone" suffix is ignored), false for a DNS name.
    static func isIPAddressLiteral(_ text: String) -> Bool {
        let bare = text.split(separator: "%", maxSplits: 1).first.map(String.init) ?? text
        var v4 = in_addr(), v6 = in6_addr()
        return inet_pton(AF_INET, bare, &v4) == 1 || inet_pton(AF_INET6, bare, &v6) == 1
    }

    /// Picks the address a host is keyed by: a LAN IPv4 first, then a link-local IPv4, then a routable IPv6, then fe80, then a bare
    /// host name from the fallback resolver. Ties break on the smallest address so the key never depends on which service resolved first.
    static func preferredAddress(from addresses: [String]) -> String? {
        addresses.min(by: isAddressOrdered)
    }

    /// The ordering behind `preferredAddress`, also used to list a device's addresses: IPv4 before IPv6, and within a rank by value.
    static func isAddressOrdered(_ a: String, before b: String) -> Bool {
        func rank(_ ip: String) -> Int {
            if ip.contains(":") { return ip.lowercased().hasPrefix("fe80") ? 3 : 2 }
            guard ip.allSatisfy({ $0.isNumber || $0 == "." }) else { return 4 }
            return ip.hasPrefix("169.254.") ? 1 : 0
        }
        func octets(_ ip: String) -> [Int] { ip.split(separator: ".").map { Int($0) ?? 0 } }
        let (ra, rb) = (rank(a), rank(b))
        if ra != rb { return ra < rb }
        if ra <= 1 { return octets(a).lexicographicallyPrecedes(octets(b)) }
        return a < b
    }

    // Device is a class, so in-place field updates never fire $devices; reassign so the view model re-merges.
    private func republishDevices() {
        let current = devices
        devices = current
    }

    /// The numeric host of a sockaddr as getnameinfo prints it: a plain IPv4, or an IPv6 that keeps its "%scope" when link-local.
    static func ipAddress(fromSockaddr data: Data) -> String? {
        guard data.count >= MemoryLayout<sockaddr>.size, data.count <= MemoryLayout<sockaddr_storage>.size else { return nil }
        var storage = sockaddr_storage()
        withUnsafeMutableBytes(of: &storage) { _ = data.copyBytes(to: $0) }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let result = withUnsafePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getnameinfo($0, socklen_t(data.count), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST)
            }
        }
        guard result == 0 else { return nil }
        return String(cString: host)
    }
}

