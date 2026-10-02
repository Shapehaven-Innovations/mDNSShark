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
    // Diagnostic for a 2026-09-27 on-device report that the header Scan
    // button (disabled while this is true) seemed to re-enable after ~5s
    // instead of the full 25s `scanNetwork` duration. Code trace found no
    // path that flips this early (only set true at scan start, false in
    // the single end-of-duration asyncAfter, guarded against re-entry),
    // and ~5s is exactly when the port-80 sweep / port-scan enrichment
    // stops producing visible activity, so the likely explanation is an
    // eyeball estimate of the wrong sub-phase. Logs every transition with
    // an absolute timestamp and seconds-since-scan-start so a Console
    // capture can settle it without guessing.
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
        "_services._dns-sd._udp",

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
    // NetService.schedule(in:forMode:) does NOT retain the instance the way
    // e.g. Timer does — resolveService()'s local `netService` had no other
    // strong reference anywhere (serviceToDeviceId only stores its
    // ObjectIdentifier, not the object), so ARC deallocated it as soon as
    // resolveService() returned, mid-resolve, every single time. Confirmed
    // as the real cause of a 2026-09-26/27 on-device "scan freezes the app"
    // report: Console showed "cannot add handler to 0 from 0 — dropping"
    // and "invalid mode 'kCFRunLoopCommonModes' provided to
    // CFRunLoopRunSpecific" during a scan, both signatures of a
    // CFNetService/mDNSResponder connection being torn down mid-flight
    // rather than of anything in the packet-tunnel/capture path this was
    // first suspected to be. Every discovered Bonjour service triggers one
    // of these, so a device-rich LAN turns this into a repeated,
    // main-thread-adjacent teardown storm for the whole ~20s Bonjour
    // portion of a scan.
    private var activeNetServices: [ObjectIdentifier: NetService] = [:]
    
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
        
        @Published var resolvedIPAddress: String? = nil
        @Published var friendlyName: String? = nil
        @Published var model: String? = nil
        @Published var port: Int? = nil
        @Published var txtRecords: [String: String]? = nil
        @Published var locationURL: URL? = nil
        
        var identifier: String { friendlyName ?? serviceName }
        
        init(serviceName: String, serviceDomain: String, serviceType: String) {
            self.serviceName = serviceName
            self.serviceDomain = serviceDomain
            self.serviceType = serviceType
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
        serviceToDeviceId.removeAll()
        activeNetServices.values.forEach { $0.stop() }
        activeNetServices.removeAll()
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
        isScanning = false
        logger.info("Scan cancelled for restart.")
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
                // Never surface this app's own internal Bonjour preflight
                // probe (LocalNetworkPermissionGate.swift) as a discovered
                // device: it's a same-device self-advertisement used only
                // to detect Local Network Privacy's decision, not a real
                // host. NWBrowser reports service types with a trailing
                // dot, hence the prefix check. Checked on both `type` AND
                // `name`: a direct browse of this type reports it in
                // `type`, but this app's meta-query browse
                // ("_services._dns-sd._udp", a DNS-SD type-enumeration
                // query) surfaces discovered type strings in `name`
                // instead, with `type` fixed to the meta-service string, so
                // checking only one field lets it slip through the other path.
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
        // fires — see the activeNetServices doc comment above.
        activeNetServices[ObjectIdentifier(netService)] = netService
        if let device = self.devices.first(where: { $0.serviceName == name &&
                                                     $0.serviceDomain == domain &&
                                                     $0.serviceType == type }) {
            serviceToDeviceId[ObjectIdentifier(netService)] = device.id
        }
        logger.info("Resolving service: \(name) \(type) \(domain)")
        netService.resolve(withTimeout: 10.0)
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
                    device.resolvedIPAddress = host
                    device.port = url.port ?? 80
                    device.locationURL = url
                }
                self.devices.append(device)
                self.logger.info("SSDP discovered device: \(usn) at \(location)")
            }
        }
    }
    
    // MARK: - NetServiceDelegate
    func netServiceDidResolveAddress(_ sender: NetService) {
        let key = ObjectIdentifier(sender)
        activeNetServices.removeValue(forKey: key)
        guard let deviceID = serviceToDeviceId[key],
              let device = devices.first(where: { $0.id == deviceID }) else {
            logger.error("No device mapping for resolved service \(sender.name)")
            return
        }
        
        var foundIP: String? = nil
        if let addresses = sender.addresses, !addresses.isEmpty {
            logger.info("\(sender.name) has \(addresses.count) addresses")
            // Every enrichment probe and the port-80 sweep dedup are IPv4-only, so IPv6 only wins when no IPv4 sockaddr exists.
            var firstIPv6: String? = nil
            for addressData in addresses {
                guard let ip = ipAddressFromData(addressData) else { continue }
                if ip.contains(":") {
                    if firstIPv6 == nil { firstIPv6 = ip }
                    continue
                }
                foundIP = ip
                break
            }
            if foundIP == nil { foundIP = firstIPv6 }
            if let ip = foundIP {
                logger.info("Found IP \(ip) for \(sender.name)")
            } else {
                logger.warning("No valid IP parsed for \(sender.name)")
            }
        } else {
            logger.warning("No addresses available for \(sender.name)")
        }
        
        if foundIP == nil {
            logger.info("Attempting fallback resolution for \(sender.name)")
            DNSServiceResolver.resolve(name: sender.name, type: sender.type, domain: sender.domain) { host, port in
                if let host = host, let port = port {
                    DispatchQueue.main.async {
                        device.resolvedIPAddress = host
                        device.port = Int(port)
                        self.logger.info("Fallback resolved \(sender.name) to IP: \(host) on port: \(port)")
                        self.republishDevices()
                    }
                } else {
                    self.logger.error("Fallback resolution failed for \(sender.name)")
                }
            }
            return
        }
        
        DispatchQueue.main.async {
            device.resolvedIPAddress = foundIP
            device.port = sender.port
            self.logger.info("Resolved \(sender.name) to IP: \(foundIP!) on port: \(sender.port)")
        }
        
        if let txtData = sender.txtRecordData() {
            let txtDict = NetService.dictionary(fromTXTRecord: txtData)
            if txtDict.isEmpty {
                logger.debug("TXT record data empty for \(sender.name)")
            } else {
                var allTXTRecords = [String: String]()
                for (key, value) in txtDict {
                    if let stringValue = String(data: value, encoding: .utf8) {
                        allTXTRecords[key] = stringValue
                    }
                }
                DispatchQueue.main.async {
                    device.txtRecords = allTXTRecords
                    self.logger.info("TXT records for \(sender.name): \(allTXTRecords)")
                }
                if let friendlyData = txtDict["fn"] ?? txtDict["n"],
                   let friendly = String(data: friendlyData, encoding: .utf8),
                   !friendly.isEmpty {
                    DispatchQueue.main.async {
                        device.friendlyName = friendly
                        self.logger.info("Resolved friendly name for \(sender.name): \(friendly)")
                    }
                } else {
                    logger.debug("No friendly name found for \(sender.name)")
                }
                if let modelData = txtDict["md"],
                   let model = String(data: modelData, encoding: .utf8),
                   !model.isEmpty {
                    DispatchQueue.main.async {
                        device.model = model
                        self.logger.info("Resolved model for \(sender.name): \(model)")
                    }
                } else {
                    logger.debug("No model info found for \(sender.name)")
                }
            }
        } else {
            logger.debug("No TXT record data available for \(sender.name)")
        }
        // Queued last so it runs after every in-place field update dispatched above.
        DispatchQueue.main.async {
            self.republishDevices()
        }
    }

    // Device is a class, so in-place field updates never fire $devices; reassign so the view model re-merges.
    private func republishDevices() {
        let current = devices
        devices = current
    }

    func netService(_ sender: NetService, didNotResolve errorDict: [String : NSNumber]) {
        activeNetServices.removeValue(forKey: ObjectIdentifier(sender))
        logger.error("Failed to resolve \(sender.name) with error: \(errorDict)")
    }
    
    private func ipAddressFromData(_ data: Data) -> String? {
        var storage = sockaddr_storage()
        (data as NSData).getBytes(&storage, length: MemoryLayout<sockaddr_storage>.size)
        if Int32(storage.ss_family) == AF_INET {
            let addr = withUnsafePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
            }
            if let ipCStr = inet_ntoa(addr) {
                return String(cString: ipCStr)
            }
        } else if Int32(storage.ss_family) == AF_INET6 {
            let addr = withUnsafePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee.sin6_addr }
            }
            var buffer = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            var addr6 = addr
            inet_ntop(AF_INET6, &addr6, &buffer, socklen_t(INET6_ADDRSTRLEN))
            return String(cString: buffer)
        }
        return nil
    }
}

