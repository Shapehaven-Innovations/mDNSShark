// mDNSShark/Packets/PacketRowView.swift
import SwiftUI

struct PacketRowView: View {
    let packet: PacketModel

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Text("#\(packet.frameNumber)")
                .font(.caption.monospacedDigit()).foregroundColor(.secondary)
                .frame(width: 40, alignment: .trailing)
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("\(packet.sourceIP) → \(packet.destinationIP)")
                        .font(.subheadline.weight(.semibold)).lineLimit(1)
                    Spacer()
                    HStack(spacing: 4) {
                        AppBadge(text: packet.protocolName,
                                 color: AppColors.PacketProtocol.color(for: packet.protocolName))
                        if packet.isReconstructed {
                            Text("reconstructed")
                                .font(.caption2)
                                .padding(.horizontal, 4).padding(.vertical, 2)
                                .background(Color.orange.opacity(0.12))
                                .foregroundColor(.orange)
                                .cornerRadius(4)
                        }
                    }
                }
                HStack {
                    Text(packet.formattedTimestamp)
                        .font(.caption.monospacedDigit()).foregroundColor(.secondary)
                    Spacer()
                    Text("\(packet.length) bytes").font(.caption).foregroundColor(.secondary)
                }
                if !packet.info.isEmpty {
                    Text(packet.info).font(.caption).foregroundColor(.secondary).lineLimit(1)
                }
            }
        }
        .padding(.horizontal, 16).padding(.vertical, 10)
    }
}
