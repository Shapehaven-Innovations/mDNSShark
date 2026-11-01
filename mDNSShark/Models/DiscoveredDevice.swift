// mDNSShark/Models/DiscoveredDevice.swift
import Foundation
import DeviceFingerprint

enum DeviceType: Hashable, CaseIterable {
    case router, apple, computer, printer, tv, unknown

    /// The one label every surface shows (Topology chips, pin picker, Devices card).
    var label: String {
        switch self {
        case .router:   return "Router"
        case .apple:    return "Other Apple"
        case .computer: return "Computer"
        case .printer:  return "Printer"
        case .tv:       return "TV"
        case .unknown:  return "Unknown"
        }
    }
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
    /// True once this device's enrichment probe set has answered (or was refused), so `openPorts` is a known fact rather than pending.
    var probesSettled: Bool = false
    /// Every address seen for this device, raw as received: IPv4 first, then IPv6 (with its scope, if any).
    var addresses: [String] = []

    init(id: UUID = UUID(), hostname: String, ipAddress: String,
         macAddress: String? = nil, manufacturer: String? = nil,
         inferredOS: String? = nil, openPorts: [Int] = [],
         bonjourServices: [BonjourService] = [], securityFindings: [SecurityFinding] = [],
         probesSettled: Bool = false, addresses: [String] = []) {
        self.id = id; self.hostname = hostname; self.ipAddress = ipAddress
        self.macAddress = macAddress; self.manufacturer = manufacturer
        self.inferredOS = inferredOS; self.openPorts = openPorts
        self.bonjourServices = bonjourServices; self.securityFindings = securityFindings
        self.probesSettled = probesSettled; self.addresses = addresses
    }

    // Compares the late-enriched fields too, so SwiftUI redraws a row when enrichment lands; securityFindings is left out.
    static func == (l: DiscoveredDevice, r: DiscoveredDevice) -> Bool {
        l.id == r.id && l.hostname == r.hostname && l.ipAddress == r.ipAddress
            && l.macAddress == r.macAddress && l.manufacturer == r.manufacturer
            && l.inferredOS == r.inferredOS && l.openPorts == r.openPorts
            && l.bonjourServices == r.bonjourServices
            && l.probesSettled == r.probesSettled && l.addresses == r.addresses
    }

    var isGateway: Bool { ipAddress.hasSuffix(".1") }

    /// `inferredOS` if any real source (banner text, ground-truth
    /// discovery reply, etc) ever supplied one; otherwise a generic
    /// manufacturer-based guess computed fresh here, never persisted.
    /// Deliberately NOT folded into `inferredOS`/`merge()`'s stored state:
    /// writing a guess into that field would permanently block a later,
    /// more specific non-ground-truth OS answer from a slower probe batch
    /// from ever landing, since the field would no longer look empty. See
    /// `DeviceEnrichment.merge()`'s doc comment for the full reasoning.
    var displayInferredOS: String? {
        inferredOS ?? manufacturer.flatMap { inferredOSFamily(forManufacturer: $0) }
    }

    /// Every model string the services advertise, so the type is a function of all the evidence and not of which service arrived first.
    private var advertisedModels: [String] { bonjourServices.compactMap { $0.txtRecords["model"] ?? $0.txtRecords["am"] } }

    var deviceType: DeviceType {
        if isGateway { return .router }
        let types = bonjourServices.map { $0.serviceType }
        let models = advertisedModels
        if types.contains("_airplay._tcp") || types.contains("_raop._tcp") {
            guard manufacturer?.contains("Apple") == true else { return .tv }
            if models.contains(where: { $0.hasPrefix("Mac") || $0.hasPrefix("iMac") }) { return .computer }
            // An AirPlay row with no usable model must not hide a file-sharing service that marks a Mac.
            if models.isEmpty, types.contains("_smb._tcp") || types.contains("_afpovertcp._tcp") { return .computer }
            return .apple
        }
        if types.contains("_ipp._tcp") || types.contains("_printer._tcp") { return .printer }
        // _rdlink._tcp is advertised only by iPhone and iPad, so it marks an Apple device without saying which.
        if types.contains("_apple-mobdev2._tcp") || types.contains("_airdrop._tcp") || types.contains("_rdlink._tcp") { return .apple }
        if types.contains("_afpovertcp._tcp") || types.contains("_smb._tcp") { return .computer }
        if manufacturer?.contains("Apple") == true { return .apple }
        return .unknown
    }

    var deviceIcon: String {
        switch deviceType {
        case .router:   return "wifi.router"
        case .tv:       return "tv"
        case .printer:  return "printer"
        case .apple:    return appleModelIcon ?? "laptopcomputer.and.iphone"
        case .computer: return "laptopcomputer"
        case .unknown:  return "questionmark.circle"
        }
    }

    /// Phone or tablet glyph only when a service's model string names one; otherwise nil so the generic Apple icon shows.
    private var appleModelIcon: String? {
        let models = advertisedModels
        if models.contains(where: { $0.hasPrefix("iPhone") }) { return "iphone" }
        if models.contains(where: { $0.hasPrefix("iPad") }) { return "ipad" }
        return nil
    }
}
