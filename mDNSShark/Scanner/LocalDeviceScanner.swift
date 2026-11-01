//LocalDeviceScanner.swift

import Foundation
import Network
import os
import Darwin

class LocalDeviceScanner: ObservableObject {
    @Published var discoveredIPs: [String] = []
    private let logger = Logger(subsystem: "com.mDNSShark", category: "LocalDeviceScanner")
    
    /// Heuristic default gateway: the router is assumed at x.x.x.1 of the device's Wi-Fi prefix.
    private func getDefaultGateway(prefix: String) -> String {
        "\(prefix)1"
    }

    /// Scans the local /24 subnet by iterating over each IP and attempting a TCP connection.
    func scanLocalSubnet(port: NWEndpoint.Port = NWEndpoint.Port(integerLiteral: 80), timeout: TimeInterval = 1.0) {
        // One interface read serves both the prefix and the gateway guess.
        guard let localPrefix = getLocalIPPrefix() else {
            logger.error("Failed to get local IP prefix.")
            return
        }
        let defaultGatewayIP: String? = getDefaultGateway(prefix: localPrefix)
        logger.info("Default gateway (heuristic) detected: \(defaultGatewayIP ?? "unknown")")
        logger.info("Starting local subnet scan on prefix \(localPrefix)")
        
        let group = DispatchGroup()
        // Completions arrive on concurrent queues, so every access to results goes through this lock.
        let resultsLock = NSLock()
        var results = [String]()
        let tcpParameters: NWParameters = .tcp

        // Always include the gateway so it appears as the router node even if port 80 is closed
        if let gw = defaultGatewayIP { results.append(gw) }

        for i in 1...254 {
            let ip = "\(localPrefix)\(i)"

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

