// mDNSShark/Devices/ServiceCardView.swift
import SwiftUI

/// One advertisement that resolved to no device, plus the section that lists them under the device cards.
struct ServiceCardView: View {
    let service: DiscoveredService

    var body: some View {
        CardView {
            HStack {
                Image(systemName: service.isSSDP ? "dot.radiowaves.left.and.right" : "network")
                    .font(.title2).foregroundColor(.secondary).frame(width: 32)
                VStack(alignment: .leading, spacing: 2) {
                    Text(service.name).font(.headline).lineLimit(1)
                    Text(detail).font(.subheadline).foregroundColor(.secondary).lineLimit(1)
                }
                Spacer()
                AppBadge(text: "No device", color: Color(.systemGray))
            }
        }
    }

    private var detail: String {
        var parts = [service.typeLabel]
        if let port = service.port { parts.append("port \(port)") }
        if let host = service.hostName { parts.append(host) }
        return parts.joined(separator: " · ")
    }
}

struct UnattachedServicesSection: View {
    let services: [DiscoveredService]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Services without a resolved device").font(.headline)
            Text("These are running on the network, but no address was found for them, so they are not counted as devices.")
                .font(.caption).foregroundColor(.secondary)
            ForEach(services) { ServiceCardView(service: $0) }
        }
    }
}
