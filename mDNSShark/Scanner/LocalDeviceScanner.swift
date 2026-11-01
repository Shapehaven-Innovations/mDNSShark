//LocalDeviceScanner.swift

import Foundation
import Network
import os
import Darwin

class LocalDeviceScanner: ObservableObject {
    @Published var discoveredIPs: [String] = []
    private let logger = Logger(subsystem: "com.mDNSShark", category: "LocalDeviceScanner")
    
    /// The interfaces read once at scan time; a seam so tests can supply them.
    var ownAddressesProvider: () -> LocalInterfaces.OwnAddresses = { LocalInterfaces.ownAddresses() }

    /// Addresses to sweep: the phone's /24 (.1 to .254) when the subnet is unknown or /24 or wider, else only the host addresses inside
    /// a narrower subnet (prefix 25 to 30), without its network or broadcast address. A /31 sweeps only its one peer (the address that is not
    /// `ownIPv4`) and a /32 has no peer, so it sweeps nothing.
    static func sweepTargets(ownIPv4: String, subnet: LocalInterfaces.IPv4Subnet?) -> [String] {
        if let subnet, subnet.prefixLength > 24 {
            if subnet.prefixLength == 31 {
                let own = LocalInterfaces.ipv4Value(ownIPv4)
                return [subnet.network, subnet.network + 1].filter { $0 != own }.map(dotted)
            }
            guard subnet.prefixLength <= 30 else { return [] }
            let size = UInt32(1) << UInt32(32 - subnet.prefixLength)
            return (1..<(size - 1)).map { offset in
                dotted(subnet.network + offset)
            }
        }
        let parts = ownIPv4.split(separator: ".")
        guard parts.count == 4 else { return [] }
        return (1...254).map { "\(parts[0]).\(parts[1]).\(parts[2]).\($0)" }
    }

    private static func dotted(_ value: UInt32) -> String {
        (0..<4).map { String(value >> UInt32(24 - 8 * $0) & 0xFF) }.joined(separator: ".")
    }

    /// The default gateway the system reports on this network (by subnet containment when the subnet is known, else by prefix), else the
    /// guess that the router is at x.x.x.1, which is dropped when it falls outside a known subnet.
    static func defaultGateway(prefix: String, subnet: LocalInterfaces.IPv4Subnet?, gateways: [String]) -> String? {
        if let subnet {
            if let reported = gateways.first(where: { LocalInterfaces.ipv4Value($0).map(subnet.contains) == true }) { return reported }
            let guess = "\(prefix)1"
            return LocalInterfaces.ipv4Value(guess).map(subnet.contains) == true ? guess : nil
        }
        return gateways.first { $0.hasPrefix(prefix) } ?? "\(prefix)1"
    }

    /// Scans the local /24 (or a narrower subnet) by iterating over each IP and attempting a TCP connection.
    func scanLocalSubnet(port: NWEndpoint.Port = NWEndpoint.Port(integerLiteral: 80), timeout: TimeInterval = 1.0) {
        // One interface read serves the prefix, the own address, the subnet and the gateway match.
        let own = ownAddressesProvider()
        let subnet = own.primarySubnet
        guard let ownIPv4 = NetworkScanner.preferredAddress(from: own.primary.filter { LocalInterfaces.ipv4Value($0) != nil }),
              let localPrefix = getLocalIPPrefix(for: ownIPv4) else {
            logger.error("Failed to get local IP prefix.")
            return
        }
        let defaultGatewayIP = Self.defaultGateway(prefix: localPrefix, subnet: subnet, gateways: GatewayMonitor.shared.ipv4)
        logger.info("Default gateway detected: \(defaultGatewayIP ?? "unknown")")
        logger.info("Starting local subnet scan on prefix \(localPrefix)")
        
        let group = DispatchGroup()
        // Completions arrive on concurrent queues, so every access to results goes through this lock.
        let resultsLock = NSLock()
        var results = [String]()
        let tcpParameters: NWParameters = .tcp

        // Always include the gateway so it appears as the router node even if port 80 is closed
        if let gw = defaultGatewayIP { results.append(gw) }

        let targets = Self.sweepTargets(ownIPv4: ownIPv4, subnet: subnet)
        for ip in targets {

            group.enter()
            scanSingleIP(ip: ip, port: port, parameters: tcpParameters, timeout: timeout) { success in
                if success {
                    resultsLock.lock()
                    let isNew = !results.contains(ip)
                    if isNew { results.append(ip) }
                    resultsLock.unlock()
                    if isNew { self.logger.info("Local scan discovered device at IP: \(ip)") }
                }
                group.leave()
            }
        }

        group.notify(queue: DispatchQueue.main) { [weak self] in
            guard let self = self else { return }
            resultsLock.lock()
            let found = results
            resultsLock.unlock()
            self.discoveredIPs = found
            self.logger.info("Local subnet scan complete. Discovered IPs: \(found)")
        }
    }
    
    private func scanSingleIP(ip: String,
                              port: NWEndpoint.Port,
                              parameters: NWParameters,
                              timeout: TimeInterval,
                              completion: @escaping (Bool) -> Void) {
        let host = NWEndpoint.Host(ip)
        let connection = NWConnection(host: host, port: port, using: parameters)
        
        let lock = NSLock()
        var didComplete = false
        func safeComplete(_ success: Bool) {
            lock.lock()
            defer { lock.unlock() }
            if !didComplete {
                didComplete = true
                completion(success)
            }
        }
        
        connection.stateUpdateHandler = { [weak self] state in
            guard let self = self else { return }
            self.logger.info("NWConnection for \(ip) state: \(String(describing: state))")
            switch state {
            case .ready:
                self.logger.debug("Connection ready to \(ip)")
                connection.cancel()
                safeComplete(true)
            case .failed(let error):
                self.logger.debug("Connection failed to \(ip): \(error.localizedDescription)")
                connection.cancel()
                safeComplete(false)
            default:
                break
            }
        }
        
        connection.start(queue: DispatchQueue.global())
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
            connection.cancel()
            safeComplete(false)
        }
    }
    
    /// The IPv4 address of this device's Wi-Fi interface, chosen by interface type rather than by name (see LocalInterfaces).
    func getWiFiAddress() -> String? {
        LocalInterfaces.primaryIPv4Address()
    }
    
    func getLocalIPPrefix() -> String? {
        if let wifiAddress = getWiFiAddress() {
            return getLocalIPPrefix(for: wifiAddress)
        }
        return nil
    }
    
    func getLocalIPPrefix(for ip: String) -> String? {
        let parts = ip.split(separator: ".")
        if parts.count == 4 {
            return "\(parts[0]).\(parts[1]).\(parts[2])."
        }
        return nil
    }
}

