// mDNSShark/Models/BonjourService.swift
import Foundation

/// An advertisement that has not resolved to a device (no IP, or only a host name no device matches). Shown as a service, never as a device.
struct DiscoveredService: Identifiable, Equatable {
    /// Stable across re-merges: "type|name|domain" is unique per advertisement.
    let id: String
    let name: String
    /// Bonjour type ("_http._tcp") or "ssdp" for a UPnP advertisement.
    let serviceType: String
    let port: Int?
    /// Host name as advertised, when known.
    let hostName: String?

    var isSSDP: Bool { serviceType == "ssdp" }
    var typeLabel: String { isSSDP ? "SSDP / UPnP" : serviceType }
}

struct BonjourService: Identifiable, Equatable {
    /// "type|name", deterministic so two merges of the same rows compare equal and SwiftUI does not redraw every publish.
    let id: String
    let serviceType: String
    let serviceName: String
    let port: Int
    let txtRecords: [String: String]

    init(serviceType: String, serviceName: String, port: Int, txtRecords: [String: String] = [:]) {
        self.id = "\(serviceType)|\(serviceName)"
        self.serviceType = serviceType; self.serviceName = serviceName
        self.port = port; self.txtRecords = txtRecords
    }
}
