// mDNSShark/Packets/PacketDetailView.swift
import SwiftUI

struct PacketDetailView: View {
    let packet: PacketModel

    var body: some View {
        ScrollView {
            VStack(spacing: 16) {
                CardView {
                    VStack(alignment: .leading, spacing: 10) {
                        HStack {
                            Text("Packet Summary").font(.headline)
                            Spacer()
                            AppBadge(text: packet.protocolName,
                                     color: AppColors.PacketProtocol.color(for: packet.protocolName))
                        }
                        Divider()
                        row("Frame",       "#\(packet.frameNumber)")
                        row("Timestamp",   packet.formattedTimestamp)
                        row("Source",      packet.sourceIP + (packet.sourcePort.map { ":\($0)" } ?? ""))
                        row("Destination", packet.destinationIP + (packet.destinationPort.map { ":\($0)" } ?? ""))
                        row("Protocol",    packet.protocolName)
                        row("Length",      "\(packet.length) bytes")
                        if !packet.info.isEmpty { row("Info", packet.info) }
                    }
                }
                CardView {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Hex Dump").font(.headline)
                        Divider()
                        ScrollView(.horizontal, showsIndicators: true) {
                            Text(packet.hexDump)
                                .font(.system(.caption, design: .monospaced))
                                .padding(.vertical, 4)
                        }
                    }
                }
            }
            .padding(.horizontal).padding(.top, 8)
        }
        .navigationTitle("Frame \(packet.frameNumber)")
        .navigationBarTitleDisplayMode(.inline)
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundColor(.secondary).font(.subheadline)
            Spacer()
            Text(value).font(.subheadline.weight(.medium)).multilineTextAlignment(.trailing)
        }
    }
}
