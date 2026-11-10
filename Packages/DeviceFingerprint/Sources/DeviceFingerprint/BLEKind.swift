import Foundation

public enum BLEKind: String, CaseIterable, Codable, Sendable {
    case phone, computer, wearable, earbuds, audio, tv, tracker, findMy, health, inputDevice, beacon, smartHome, camera, printer, unknown

    public var label: String {
        switch self {
        case .phone: return "Phone"
        case .computer: return "Computer"
        case .wearable: return "Wearable"
        case .earbuds: return "Earbuds"
        case .audio: return "Audio"
        case .tv: return "TV"
        case .tracker: return "Tracker"
        case .findMy: return "Find My"
        case .health: return "Health"
        case .inputDevice: return "Input device"
        case .beacon: return "Beacon"
        case .smartHome: return "Smart Home"
        case .camera: return "Camera"
        case .printer: return "Printer"
        case .unknown: return "Unknown"
        }
    }

    /// Trackers and Find My beacons are not connectable and stay out of the opt-in device info read.
    public var offersDeviceInfoRead: Bool { self != .tracker && self != .findMy }

    public var symbol: String {
        switch self {
        case .phone: return "smartphone"
        case .computer: return "laptopcomputer"
        case .wearable: return "applewatch"
        case .earbuds: return "earbuds"
        case .audio: return "hifispeaker"
        case .tv: return "tv"
        case .tracker: return "tag"
        case .findMy: return "tag"
        case .health: return "heart"
        case .inputDevice: return "keyboard"
        case .beacon: return "dot.radiowaves.left.and.right"
        case .smartHome: return "lightbulb"
        case .camera: return "video"
        case .printer: return "printer"
        case .unknown: return "questionmark.circle"
        }
    }
}
