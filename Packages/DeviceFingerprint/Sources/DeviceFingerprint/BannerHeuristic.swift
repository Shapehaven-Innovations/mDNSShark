import Foundation

public struct BannerGuess {
    public let manufacturer: String?
    public let os: String?
}

/// Cheap substring matching over a raw TCP banner (SSH version string, HTTP
/// Server header, etc). Weak evidence, same tier as the TTL guess — never
/// treat this as certain.
public func guessFromBanner(_ banner: String) -> BannerGuess {
    let lower = banner.lowercased()
    var manufacturer: String?
    var os: String?

    if lower.contains("dropbear") {
        os = "Linux (embedded, likely)"
    } else if lower.contains("openssh") && (lower.contains("debian") || lower.contains("ubuntu")) {
        os = "Linux (likely)"
    } else if lower.contains("openssh") {
        os = "Linux/Unix-like (likely)"
    }

    if lower.contains("synology") {
        manufacturer = "Synology"
    } else if lower.contains("ubiquiti") || lower.contains("unifi") {
        manufacturer = "Ubiquiti"
    } else if lower.contains("mikrotik") || lower.contains("routeros") {
        manufacturer = "MikroTik"
    }

    return BannerGuess(manufacturer: manufacturer, os: os)
}
