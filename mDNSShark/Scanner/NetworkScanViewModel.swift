// mDNSShark/Scanner/NetworkScanViewModel.swift
import Foundation
import Combine
import os

@MainActor
final class NetworkScanViewModel: ObservableObject {
    @Published var devices: [DiscoveredDevice] = []
    @Published var isScanning: Bool = false

    private let scanner     = NetworkScanner()
    private let localUtil   = LocalDeviceScanner()
    private let ouiDB       = OUIDatabase.shared
    private var cancellables = Set<AnyCancellable>()
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
    }

    func startScan(duration: Double = 25.0) {
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
            } else {
                let mac = device.txtRecords?["mac"]
                let mfr = mac.flatMap { ouiDB.manufacturer(for: String($0.prefix(8))) }
                let svc = BonjourService(
                    serviceType: device.serviceType,
                    serviceName: device.serviceName,
                    port: device.port ?? 0,
                    txtRecords: device.txtRecords ?? [:]
                )
                let os = inferOS(serviceType: device.serviceType, manufacturer: mfr)
                byIP[ip] = DiscoveredDevice(
                    hostname:        device.identifier,
                    ipAddress:       ip,
                    macAddress:      mac,
                    manufacturer:    mfr,
                    inferredOS:      os,
                    openPorts:       device.port.map { [$0] } ?? [],
                    bonjourServices: [svc]
                )
            }
        }
        return Array(byIP.values).sorted { $0.ipAddress < $1.ipAddress }
    }

    private func inferOS(serviceType: String, manufacturer: String?) -> String? {
        let appleServices: Set<String> = [
            "_apple-mobdev2._tcp", "_airdrop._tcp", "_airplay._tcp",
            "_raop._tcp", "_device-info._tcp", "_daap._tcp"
        ]
        if appleServices.contains(serviceType) { return "Apple" }
        if let mfr = manufacturer {
            if mfr.contains("Apple")     { return "Apple" }
            if mfr.contains("Microsoft") { return "Windows" }
            if mfr.contains("Raspberry") { return "Linux" }
        }
        return nil
    }
}
