// mDNSShark/Models/DiscoveredDevice.swift
import Foundation
import DeviceFingerprint

enum DeviceType: Hashable, CaseIterable {
    case router, apple, computer, printer, tv, camera, audio, smartHome, nas, unknown

    /// The chip for a catalog kind; `network` has no chip yet, so it returns nil.
    init?(kind: DeviceKind) {
        switch kind {
        case .camera:    self = .camera
        case .audio:     self = .audio
        case .tv:        self = .tv
        case .smartHome: self = .smartHome
        case .nas:       self = .nas
        case .printer:   self = .printer
        case .computer:  self = .computer
        case .network:   return nil
        }
    }

    /// The one label every surface shows (Topology chips, pin picker, Devices card).
    var label: String {
        switch self {
        case .router:   return "Router"
        case .apple:    return "Other Apple"
        case .computer: return "Computer"
        case .printer:  return "Printer"
        case .tv:       return "TV"
        case .camera:   return "Camera"
        case .audio:    return "Audio"
        case .smartHome: return "Smart Home"
        case .nas:      return "NAS"
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
    func note(offNetwork: Bool = false) -> String {
        var text: String
        switch category {
        case .payment:
            text = "\(vendor) makes payment or point-of-sale equipment, so mDNSShark skipped its device probes for this address."
        case .infrastructure:
            text = "Vendor makes traffic-control, roadside or licence plate equipment, so mDNSShark skipped its device probes for this address."
        }
        if !offNetwork { text += " The subnet sweep's single connection attempt to port 80 runs before any vendor is known, so it is not skipped." }
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
    /// True when probing was refused for this host's addresses (no IPv4 address, or none the coordinator accepts), so its open ports are unknown.
    var probeRefused: Bool = false
    /// True when the user asked for probes on this off-network host in the current scan only.
    var probeRequested = false
    /// False for a host that got no active probes (vendor gate, off-subnet or refused), so an empty findings list means unchecked, not clean.
    /// An off-network host counts as probed only after an explicit request, and a payment or roadside skip always wins.
    var wasProbed: Bool { paymentVendorSkip == nil && (isOnLocalSubnet != false || probeRequested) && !probeRefused }

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
            && l.paymentVendorSkip == r.paymentVendorSkip && l.probeRefused == r.probeRefused && l.probeRequested == r.probeRequested
    }

    /// Whether the system's default gateway is one of this device's addresses; nil when the gateway is unknown.
    var isDefaultGateway: Bool?

    /// The system's answer when there is one, otherwise the guess that the router is at x.x.x.1.
    var isGateway: Bool { isDefaultGateway ?? ipAddress.hasSuffix(".1") }

    /// What to show when no open port is known: "Not probed" for a host that was never probed (payment skip, off-subnet or refused), since "None" would claim a fact.
    var noOpenPortsText: String { wasProbed ? "None" : "Not probed" }

    /// Literal lines about where this device sits and how it was learned. The remote network's prefix length is unknowable, so none is claimed.
    func networkNote(ownCIDRs: [String]) -> [String] {
        var lines: [String] = []
        let phone = ownCIDRs.joined(separator: ", ")
        switch isOnLocalSubnet {
        case true:  lines.append("Same network as this phone (\(phone))")
        case false: lines.append("Outside this phone's network (device \(ipAddress), outside: \(phone))")
        case nil:   lines.append("Network not known")
        }
        let types = bonjourServices.map(\.serviceType)
        let viaBonjour = !types.isEmpty
        if viaBonjour { lines.append("Bonjour advertisement (\(Array(Set(types)).sorted().joined(separator: ", ")))") }
        if ssdpServer != nil { lines.append("SSDP reply") }
        if isOnLocalSubnet == false, viaBonjour, ssdpServer == nil {
            lines.append("Your router may be repeating this advertisement from another network (not confirmed).")
        }
        if paymentVendorSkip != nil { lines.append("Not probed: payment or roadside vendor") }
        else if probeRefused { lines.append("Not probed: IPv6 only or non-local address") }
        else if isOnLocalSubnet == false {
            lines.append(!probeRequested ? "Not probed: on another network" : (probesSettled ? "Probed on request" : "Probes pending"))
        }
        else { lines.append("Probed") }
        return lines
    }

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

    /// Types that mark a speaker, so a non-Apple AirPlay receiver carrying one is audio and not a TV.
    private static let speakerTypes: Set<String> = [
        "_sonos._tcp", "_heos-audio._tcp", "_soundtouch._tcp", "_bangolufsen._tcp",
        "_musc._tcp", "_linkplay._tcp", "_netaudio-arc._udp", "_netaudio-cmc._udp",
    ]

    /// The first catalog kind over the services, ordered by type then name so the answer does not depend on arrival order.
    private var catalogKind: DeviceKind? {
        let ordered = bonjourServices.sorted { ($0.serviceType, $0.serviceName) < ($1.serviceType, $1.serviceName) }
        for service in ordered {
            if let kind = BonjourTypeCatalog.kind(serviceType: service.serviceType, instanceName: service.serviceName, txt: service.txtRecords),
               DeviceType(kind: kind) != nil { return kind }
        }
        return nil
    }

    var deviceType: DeviceType {
        if isGateway { return .router }
        let types = bonjourServices.map { $0.serviceType }
        let models = advertisedModels
        if types.contains("_airplay._tcp") || types.contains("_raop._tcp") {
            var airplayTXT = bonjourServices.first { $0.serviceType == "_airplay._tcp" }?.txtRecords ?? [:]
            // A RAOP-only receiver carries the same feature bitmap under `ft`.
            if airplayTXT["features"] == nil, let ft = bonjourServices.first(where: { $0.serviceType == "_raop._tcp" })?.txtRecords["ft"] { airplayTXT["features"] = ft }
            guard manufacturer?.contains("Apple") == true else {
                if types.contains(where: Self.speakerTypes.contains) || BonjourTypeCatalog.isAudioOnlyAirPlay(txt: airplayTXT) { return .audio }
                return .tv
            }
            if models.contains(where: { $0.hasPrefix("AudioAccessory") || $0.hasPrefix("AirPort") }) { return .audio }
            if models.contains(where: { $0.hasPrefix("Mac") || $0.hasPrefix("iMac") }) { return .computer }
            // An AirPlay row with no usable model must not hide a file-sharing service that marks a Mac.
            if models.isEmpty, types.contains("_smb._tcp") || types.contains("_afpovertcp._tcp") { return .computer }
            return .apple
        }
        if hasCameraEvidence { return .camera }
        if let kind = catalogKind, let type = DeviceType(kind: kind) { return type }
        if types.contains("_ipp._tcp") || types.contains("_printer._tcp") { return .printer }
        // _rdlink._tcp is advertised only by iPhone and iPad, so it marks an Apple device without saying which.
        if types.contains("_apple-mobdev2._tcp") || types.contains("_airdrop._tcp") || types.contains("_rdlink._tcp") { return .apple }
        if types.contains("_afpovertcp._tcp") || types.contains("_smb._tcp") { return .computer }
        if manufacturer?.contains("Apple") == true { return .apple }
        if isApplianceMaker { return .smartHome }
        return .unknown
    }

    /// True only when the MAC vendor is exactly on the appliance list; a vendor fact, not proof of the device type.
    var isApplianceMaker: Bool { manufacturer.map(ApplianceVendorHint.isApplianceVendor) ?? false }

    var deviceIcon: String {
        deviceType == .apple ? (appleModelIcon ?? DeviceType.apple.symbol) : deviceType.symbol
    }

    /// Phone or tablet glyph only when a service's model string names one; otherwise nil so the generic Apple icon shows.
    private var appleModelIcon: String? {
        let models = advertisedModels
        if models.contains(where: { $0.hasPrefix("iPhone") }) { return "iphone" }
        if models.contains(where: { $0.hasPrefix("iPad") }) { return "ipad" }
        return nil
    }
}

extension DeviceType {
    /// The SF Symbol for this type; Apple rows may refine it with a model glyph in `deviceIcon`.
    var symbol: String {
        switch self {
        case .router:   return "wifi.router"
        case .tv:       return "tv"
        case .camera:   return "video"
        case .audio:    return "hifispeaker"
        case .smartHome: return "lightbulb"
        case .nas:      return "externaldrive.connected.to.line.below"
        case .printer:  return "printer"
        case .apple:    return "laptopcomputer.and.iphone"
        case .computer: return "laptopcomputer"
        case .unknown:  return "questionmark.circle"
        }
    }
}
