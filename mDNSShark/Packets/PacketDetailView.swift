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
                        if packet.isReconstructed {
                            VStack(alignment: .leading, spacing: 4) {
                                Label("Reconstructed Inbound", systemImage: "info.circle")
                                    .font(.caption.weight(.semibold))
                                    .foregroundColor(.orange)
                                Text("Inbound TCP payload is accurate. Sequence numbers and window size are approximate (stream-proxied, not wire-captured).")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            .padding(10)
                            .background(Color.orange.opacity(0.08))
                            .cornerRadius(8)
                        }
                    }
                }
                if let text = packet.payloadText, !text.isEmpty {
                    CardView {
                        VStack(alignment: .leading, spacing: 10) {
                            Text("Payload (Plaintext)").font(.headline)
                            Divider()
                            ScrollView(.horizontal, showsIndicators: true) {
                                Text(text)
                                    .font(.system(.caption, design: .monospaced))
                                    .padding(.vertical, 4)
                            }
                        }
                    }
                }

                CardView {
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Hex Dump").font(.headline)
                        Divider()
                        if packet.protocolName == "HTTPS" {
                            VStack(alignment: .leading, spacing: 4) {
                                Label("TLS payload is encrypted - hex shows ciphertext.", systemImage: "lock.fill")
                                    .font(.caption.weight(.semibold))
                                    .foregroundColor(.secondary)
                                Text("Full plaintext capture requires a custom CA certificate. This can be configured in a future Settings option.")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                            .padding(8)
                            .background(Color(.secondarySystemBackground))
                            .cornerRadius(8)
                            .padding(.bottom, 2)
                        }
                        ScrollView(.horizontal, showsIndicators: true) {
                            Text(formattedHexDump(packet.hexDump))
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

    private func formattedHexDump(_ raw: String) -> String {
        let tokens = raw.split(separator: " ").map { String($0) }
        guard !tokens.isEmpty else { return raw }
        var lines: [String] = []
        var i = 0
        while i < tokens.count {
            let chunk = Array(tokens[i..<min(i + 16, tokens.count)])
            let offset = String(format: "%04x", i)
            let hex = chunk.joined(separator: " ")
            let padded = hex.padding(toLength: 16 * 3 - 1, withPad: " ", startingAt: 0)
            let ascii = chunk
                .compactMap { UInt8($0, radix: 16) }
                .map { ($0 >= 32 && $0 < 127) ? String(UnicodeScalar($0)) : "." }
                .joined()
            lines.append("\(offset)  \(padded)  \(ascii)")
            i += 16
        }
        return lines.joined(separator: "\n")
    }

    private func row(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label).foregroundColor(.secondary).font(.subheadline)
            Spacer()
            Text(value).font(.subheadline.weight(.medium)).multilineTextAlignment(.trailing)
        }
    }
}
