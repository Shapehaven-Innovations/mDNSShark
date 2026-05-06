// mDNSShark/Models/DiscoveredDevice.swift
import Foundation

enum DeviceType: Hashable {
    case router, apple, computer, printer, tv, unknown
}

struct DiscoveredDevice: Identifiable, Equatable {
    let id: UUID
    var hostname: String
    var ipAddress: String
    var macAddress: String?
    var manufacturer: String?
    var inferredOS: String?
    var openPorts: [Int]
    var bonjourServices: [BonjourService]
    var securityFindings: [SecurityFinding]

    init(id: UUID = UUID(), hostname: String, ipAddress: String,
         macAddress: String? = nil, manufacturer: String? = nil,
         inferredOS: String? = nil, openPorts: [Int] = [],
         bonjourServices: [BonjourService] = [], securityFindings: [SecurityFinding] = []) {
        self.id = id; self.hostname = hostname; self.ipAddress = ipAddress
        self.macAddress = macAddress; self.manufacturer = manufacturer
        self.inferredOS = inferredOS; self.openPorts = openPorts
        self.bonjourServices = bonjourServices; self.securityFindings = securityFindings
    }

    static func == (l: DiscoveredDevice, r: DiscoveredDevice) -> Bool { l.id == r.id }

    var isGateway: Bool { ipAddress.hasSuffix(".1") }

    var deviceType: DeviceType {
        if isGateway { return .router }
        let types = bonjourServices.map { $0.serviceType }
        if types.contains("_airplay._tcp") || types.contains("_raop._tcp") { return .tv }
        if types.contains("_ipp._tcp") || types.contains("_printer._tcp") { return .printer }
        if types.contains("_apple-mobdev2._tcp") || types.contains("_airdrop._tcp") { return .apple }
        if types.contains("_afpovertcp._tcp") || types.contains("_smb._tcp") { return .computer }
        if manufacturer?.contains("Apple") == true { return .apple }
        return .unknown
    }

    var deviceIcon: String {
        switch deviceType {
        case .router:   return "wifi.router"
        case .tv:       return "tv"
        case .printer:  return "printer"
        case .apple:    return "iphone"
        case .computer: return "laptopcomputer"
        case .unknown:  return "questionmark.circle"
        }
    }
}
