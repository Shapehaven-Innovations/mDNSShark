// mDNSShark/Models/DiscoveredDevice.swift
import Foundation
import DeviceFingerprint

enum DeviceType: Hashable, CaseIterable {
    case router, apple, computer, printer, tv, camera, unknown

    /// The one label every surface shows (Topology chips, pin picker, Devices card).
    var label: String {
        switch self {
        case .router:   return "Router"
        case .apple:    return "Other Apple"
        case .computer: return "Computer"
        case .printer:  return "Printer"
        case .tv:       return "TV"
        case .camera:   return "Camera"
        case .unknown:  return "Unknown"
        }
    }
}

/// Facts readable from a MAC address string alone, with no lookup.
enum MACAddressFacts {
    /// IEEE 802: bit 0x02 of the first octet marks a locally administered (private, randomized or derived) address, which no vendor owns.
    static func isLocallyAdministered(_ mac: String) -> Bool {
        guard let first = firstOctet(mac) else { return false }
        return first & 0x02 != 0
    }

    /// The same address with the locally administered bit cleared, in the same text format, nil when it is not set or the text is not a MAC.
    static func clearingLocalBit(_ mac: String) -> String? {
        guard let first = firstOctet(mac), first & 0x02 != 0 else { return nil }
        return String(format: "%02x", first & ~0x02) + mac.dropFirst(2)
    }

    private static func firstOctet(_ mac: String) -> UInt8? {
        guard mac.count >= 2 else { return nil }
        return UInt8(mac.prefix(2), radix: 16)
    }
}

/// Why a host got no active probes: the vendor of its MAC makes payment, point-of-sale or traffic and roadside equipment.
struct PaymentVendorSkip: Equatable {
    enum Category: Equatable { case payment, infrastructure }
    var category: Category = .payment
    /// The vendor exactly as the OUI table names it.
    var vendor: String
    /// True when the vendor comes from the MAC with its locally administered bit cleared, not from the MAC itself.
    var inferred: Bool
    /// True when one NBSTAT datagram went out to fill the ARP table before the vendor was known.
    var sentARPTrigger: Bool

    static let label = "Payment terminal"
    static let infrastructureLabel = "Roadside equipment"
    static let detail = "identified from MAC vendor only, not probed"

    /// The badge text for this host's category.
    var badgeText: String { (category == .payment ? Self.label : Self.infrastructureLabel) + (inferred ? "?" : "") }

    /// The detail view's note: what was skipped, and what still reached the device before its vendor was known.
    var note: String {
        var text: String
        switch category {
        case .payment:
            text = "\(vendor) makes payment or point-of-sale equipment, so mDNSShark skipped its device probes for this address."
        case .infrastructure:
            text = "Vendor makes traffic-control, roadside or licence plate equipment, so mDNSShark skipped its device probes for this address."
        }
        text += " The subnet sweep's single connection attempt to port 80 runs before any vendor is known, so it is not skipped."
        if sentARPTrigger { text += " One NetBIOS name query was sent before the vendor was known, so the address would appear in the ARP table." }
        if inferred { text += " The vendor is inferred from a private MAC address with its locally administered bit cleared, not confirmed." }
        return text
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
    /// The SSDP `SERVER` header as received (OS and product tokens), shown as its own field and never as a name.
    var ssdpServer: String?
    /// False when every IPv4 address is outside the networks this phone or Mac is connected to (a reflected advertisement from another VLAN), nil when unknown.
    var isOnLocalSubnet: Bool?
    /// For a web port that answered with a redirect, the `Location` it sent, as received. Ports with no entry were not seen redirecting.
    var httpRedirectByPort: [Int: String] = [:]
    /// Set when the payment-vendor gate kept this host passive, so its open ports are unknown rather than none.
    var paymentVendorSkip: PaymentVendorSkip?
    /// False for a host that got no active probes (vendor gate or off-subnet), so an empty findings list means unchecked, not clean.
    var wasProbed: Bool { paymentVendorSkip == nil && isOnLocalSubnet != false }

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
            && l.probesSettled == r.probesSettled && l.addresses == r.addresses && l.ssdpServer == r.ssdpServer
            && l.isOnLocalSubnet == r.isOnLocalSubnet && l.isDefaultGateway == r.isDefaultGateway && l.httpRedirectByPort == r.httpRedirectByPort
            && l.paymentVendorSkip == r.paymentVendorSkip
    }

    /// Whether the system's default gateway is one of this device's addresses; nil when the gateway is unknown.
    var isDefaultGateway: Bool?

    /// The system's answer when there is one, otherwise the guess that the router is at x.x.x.1.
    var isGateway: Bool { isDefaultGateway ?? ipAddress.hasSuffix(".1") }

    /// What to show when no open port is known: "Not probed" for a host the payment gate kept passive, since "None" would claim a fact.
    var noOpenPortsText: String { paymentVendorSkip == nil ? "None" : "Not probed" }

    /// True when the MAC is private or derived, so the vendor cannot be read from it.
    var hasLocallyAdministeredMAC: Bool { macAddress.map(MACAddressFacts.isLocallyAdministered) ?? false }

    /// A plain-text note about a locally administered MAC, nil otherwise. When the address with that bit cleared belongs to a known vendor
    /// (a guest network's address is often derived from the device's own that way) it says so and marks that as inferred.
    func macNote(vendorLookup: (String) -> String?) -> String? {
        guard let mac = macAddress, MACAddressFacts.isLocallyAdministered(mac) else { return nil }
        var note = "Private or locally administered MAC address, so the vendor cannot be read from it."
        if let cleared = MACAddressFacts.clearingLocalBit(mac), let vendor = vendorLookup(cleared) {
            note += " With that bit cleared the address is \(cleared), which belongs to \(vendor). This is inferred, not confirmed."
        }
        return note
    }

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

    /// Any one camera signal counts: a camera-only vendor, a camera service type or instance name, a HomeKit camera category, or a Matter camera device type.
    private var hasCameraEvidence: Bool {
        if let manufacturer, CameraHint.isCameraVendor(manufacturer) { return true }
        return bonjourServices.contains { service in
            CameraHint.isCameraServiceType(service.serviceType)
                || CameraHint.isCameraInstanceName(service.serviceName)
                || (service.serviceType == "_hap._tcp" && service.txtRecords["ci"].map(CameraHint.isCameraHAPCategory) == true)
                || (service.serviceType == "_matterc._udp" && service.txtRecords["DT"].map(CameraHint.isCameraMatterDeviceType) == true)
        }
    }

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
        if hasCameraEvidence { return .camera }
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
        case .camera:   return "video"
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
