import Foundation

/// Bonjour types to browse beyond the common ones, with the kind and TXT facts each implies. None of this sends traffic beyond the browses.
public enum BonjourTypeCatalog {
    /// Extra types to browse, each as `_name._tcp` or `_name._udp`. Long and underscore names are deliberate: the daemon accepts them on `local.`.
    public static let browseTypes: [String] = [
        "_axis-video._tcp", "_axis-nvr._tcp", "_axis-nvr._udp", "_acsp-server._tcp", "_rtsp._tcp", "_psia._tcp",
        "_cctv._tcp", "_amba-cam._udp", "_matter._tcp", "_matterc._udp", "_matterd._udp", "_hap._udp",
        "_meshcop._udp", "_hue._tcp", "_sonos._tcp", "_esphomelib._tcp", "_shelly._tcp", "_wled._tcp",
        "_lutron._tcp", "_ecobee._tcp", "_homekit._tcp", "_miio._udp", "_lifx._udp", "_nanoleafapi._tcp",
        "_elg._tcp", "_home-assistant._tcp", "_homeconnect._tcp", "_amzn-alexa._tcp", "_bond._tcp",
        "_powerview._tcp", "_enphase-envoy._tcp", "_arduino._tcp", "_dyson_mqtt._tcp", "_androidtvremote2._tcp",
        "_viziocast._tcp", "_philipstv_rpc._tcp", "_mediaremotetv._tcp", "_appletv-v2._tcp", "_hscp._tcp",
        "_home-sharing._tcp", "_heos-audio._tcp", "_soundtouch._tcp", "_amzn-wplay._tcp", "_linkplay._tcp",
        "_musc._tcp", "_bangolufsen._tcp", "_uscan._tcp", "_uscans._tcp", "_qdiscover._tcp", "_wd-2go._tcp",
        "_nut._tcp", "_net-assistant._udp", "_FC9F5ED42C8A._tcp", "_adb-tls-connect._tcp", "_remotepairing._tcp",
        "_netaudio-arc._udp", "_netaudio-cmc._udp", "_ndi._tcp", "_qlab._tcp", "_apple-midi._udp",
        "_mieleathome._tcp", "_dkapi._tcp", "_openevse._tcp", "_rabbitair._udp", "_hwenergy._tcp", "_homewizard._tcp",
        "_sideplay._tcp", "_360eye_mqtt._tcp", "_aicu-http._tcp", "_moonraker._tcp", "_prusalink._tcp",
    ]

    /// Kind implied by a type alone, keyed by the type without a trailing dot.
    public static let kinds: [String: DeviceKind] = {
        var table: [String: DeviceKind] = [:]
        func add(_ kind: DeviceKind, _ types: [String]) { for type in types { table[type] = kind } }
        add(.camera, browseTypes.filter { CameraHint.isCameraServiceType($0) })
        add(.audio, ["_sonos._tcp", "_heos-audio._tcp", "_soundtouch._tcp", "_linkplay._tcp", "_musc._tcp", "_bangolufsen._tcp",
                     "_netaudio-arc._udp", "_netaudio-cmc._udp"])
        add(.smartHome, ["_hue._tcp", "_esphomelib._tcp", "_shelly._tcp", "_wled._tcp", "_lutron._tcp", "_ecobee._tcp",
                         "_miio._udp", "_lifx._udp", "_nanoleafapi._tcp", "_elg._tcp", "_home-assistant._tcp", "_homeconnect._tcp",
                         "_bond._tcp", "_powerview._tcp", "_enphase-envoy._tcp", "_arduino._tcp", "_dyson_mqtt._tcp", "_hap._udp", "_matterd._udp",
                         "_mieleathome._tcp", "_dkapi._tcp", "_openevse._tcp", "_rabbitair._udp", "_hwenergy._tcp", "_homewizard._tcp",
                         "_360eye_mqtt._tcp", "_aicu-http._tcp"])
        add(.tv, ["_androidtvremote2._tcp", "_viziocast._tcp", "_philipstv_rpc._tcp", "_hscp._tcp"])
        add(.nas, ["_qdiscover._tcp", "_wd-2go._tcp"])
        add(.printer, ["_uscan._tcp", "_uscans._tcp", "_octoprint._tcp", "_moonraker._tcp", "_prusalink._tcp"])
        add(.computer, ["_net-assistant._udp", "_home-sharing._tcp", "_qlab._tcp"])
        return table
    }()

    /// TXT key per type whose non-empty value is a literal vendor claim by the device.
    public static let vendorTXTKeys: [String: String] = [
        "_airplay._tcp": "manufacturer", "_netaudio-arc._udp": "mf", "_netaudio-cmc._udp": "mf", "_elg._tcp": "mf", "_meshcop._udp": "vn",
        "_homeconnect._tcp": "brand", "_octoprint._tcp": "vendor",
    ]

    /// Kind implied by a HomeKit accessory category identifier, nil for categories that say nothing.
    public static func hapCategoryKind(_ ci: Int) -> DeviceKind? {
        switch ci {
        case 17, 18: return .camera
        case 26, 34: return .audio
        case 31, 35, 36: return .tv
        case 33: return .network
        case 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 19, 20, 21, 22, 23, 28, 29, 30: return .smartHome
        default: return nil
        }
    }

    /// Kind for one service, nil when the type says nothing. `_hap._tcp` uses `ci`, `_matterc._udp` uses `DT`, `_amzn-alexa._tcp` only marks iRobot vacuums by name, and `_sideplay._tcp` only ecobee models by `mdl`.
    public static func kind(serviceType: String, instanceName: String, txt: [String: String]) -> DeviceKind? {
        let type = serviceType.hasSuffix(".") ? String(serviceType.dropLast()) : serviceType
        switch type {
        case "_hap._tcp":
            return txt["ci"].flatMap { Int($0) }.flatMap { hapCategoryKind($0) }
        case "_matterc._udp":
            guard let dt = txt["DT"], Int(dt) != nil else { return nil }
            return CameraHint.isCameraMatterDeviceType(dt) ? .camera : .smartHome
        case "_amzn-alexa._tcp":
            let lower = instanceName.lowercased()
            return lower.hasPrefix("irobot-") || lower.hasPrefix("roomba-") ? .smartHome : nil
        case "_sideplay._tcp":
            let model = txt["mdl"]?.lowercased() ?? ""
            return model.hasPrefix("eb-") || model.hasPrefix("ecobee") ? .smartHome : nil
        default:
            return kinds[type]
        }
    }

    private static let matterDeviceTypeNames: [Int: String] = [
        10: "Door Lock", 23: "Solar Power", 24: "Battery Storage", 45: "Air Purifier", 64: "Irrigation System", 66: "Water Valve",
        112: "Refrigerator", 113: "Temperature Controlled Cabinet", 114: "Room Air Conditioner", 115: "Laundry Washer",
        116: "Robotic Vacuum Cleaner", 117: "Dishwasher", 120: "Cooktop", 121: "Microwave Oven", 122: "Extractor Hood", 123: "Oven",
        124: "Laundry Dryer", 125: "Humidity Conditioner", 769: "Thermostat", 777: "Heat Pump", 1292: "EVSE", 1295: "Water Heater",
    ]

    /// Name of a Matter device type from its decimal `DT` TXT value, per the connectedhomeip device type list; nil for an unlisted or non-numeric value.
    public static func matterDeviceTypeName(_ dt: String) -> String? {
        Int(dt).flatMap { matterDeviceTypeNames[$0] }
    }

    private static let tvManufacturerPrefixes = ["samsung", "roku", "lg", "sony", "vizio", "appletv"]
    private static let tvModelPrefixes = ["kd-", "xr-", "bravia"]
    /// AirPlay feature bits that only a screen or video receiver sets: 0 video v1, 1 photo, 7 screen, 33 video play queue, 42 screen multi codec, 49 video v2.
    private static let screenBits = [0, 1, 7, 33, 42, 49]

    /// True only when the AirPlay `features` value proves a receiver with audio and no screen or video bits, and nothing names a TV. It may leave a speaker as TV but never turns a TV into audio.
    public static func isAudioOnlyAirPlay(txt: [String: String]) -> Bool {
        let model = txt["model"]?.lowercased() ?? ""
        if model.hasPrefix("audioaccessory") || model.hasPrefix("airport") { return true }
        let maker = txt["manufacturer"]?.lowercased() ?? ""
        if tvManufacturerPrefixes.contains(where: { maker.hasPrefix($0) || model.hasPrefix($0) }) { return false }
        if tvModelPrefixes.contains(where: { model.hasPrefix($0) }) { return false }
        guard let bits = featureBits(txt["features"]) else { return false }
        return bits & (1 << 9) != 0 && screenBits.allSatisfy { bits & (UInt64(1) << UInt64($0)) == 0 }
    }

    /// One or two comma-separated hex words, low 32 bits first, with or without `0x`; nil when anything fails to parse.
    private static func featureBits(_ value: String?) -> UInt64? {
        guard let value else { return nil }
        let words = value.split(separator: ",", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
        guard (1...2).contains(words.count) else { return nil }
        var result: UInt64 = 0
        for (index, word) in words.enumerated() {
            let digits = word.lowercased().hasPrefix("0x") ? String(word.dropFirst(2)) : word
            guard !digits.isEmpty, let part = UInt32(digits, radix: 16) else { return nil }
            result |= UInt64(part) << UInt64(32 * index)
        }
        return result
    }

    /// Shape of a browsable type: a 63-byte label with interior underscores allowed, then `_tcp` or `_udp`.
    public static var legacyTypeShape: Regex<(Substring, Substring)> { /^_[A-Za-z0-9][A-Za-z0-9_-]{0,62}\._(tcp|udp)$/ }
}
