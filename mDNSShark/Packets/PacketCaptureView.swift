// mDNSShark/Packets/PacketCaptureView.swift
import SwiftUI

struct PacketCaptureView: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @State private var selectedProtocol = "All"
    private let protocols = ["All", "TCP", "UDP", "DNS", "mDNS", "Other"]

    private var filtered: [PacketModel] {
        let all = coordinator.packetCaptureManager.packets
        switch selectedProtocol {
        case "All":   return all
        case "TCP":   return all.filter { ["TCP","HTTP","HTTPS"].contains($0.protocolName) }
        case "UDP":   return all.filter { ["UDP","DNS","mDNS"].contains($0.protocolName) }
        case "Other":
            let known: Set<String> = ["TCP","UDP","DNS","mDNS","HTTPS","HTTP","ICMP"]
            return all.filter { !known.contains($0.protocolName) }
        default:      return all.filter { $0.protocolName == selectedProtocol }
        }
    }

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(protocols, id: \.self) { p in
                            Button(p) { selectedProtocol = p }
                                .buttonStyle(.bordered)
                                .tint(selectedProtocol == p ? AppColors.info : .secondary)
                                .font(.caption.weight(selectedProtocol == p ? .semibold : .regular))
                        }
                    }
                    .padding(.horizontal, 16).padding(.vertical, 8)
                }
                Divider()
                if filtered.isEmpty {
                    Spacer()
                    VStack(spacing: 12) {
                        Image(systemName: "waveform").font(.system(size: 48)).foregroundColor(.secondary)
                        Text(coordinator.packetCaptureManager.isCapturing
                             ? "Waiting for packets…"
                             : "Tap Start to begin capturing.")
                        .foregroundColor(.secondary)
                    }
                    Spacer()
                } else {
                    ScrollView {
                        LazyVStack(spacing: 0) {
                            ForEach(filtered) { packet in
                                NavigationLink(destination: PacketDetailView(packet: packet)) {
                                    PacketRowView(packet: packet)
                                }
                                .buttonStyle(.plain)
                                Divider().padding(.leading, 56)
                            }
                        }
                    }
                }
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .principal) {
                    Text("Packet Capture").font(.headline)
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(coordinator.packetCaptureManager.isCapturing ? "Stop" : "Start") {
                        if coordinator.packetCaptureManager.isCapturing {
                            coordinator.packetCaptureManager.stopCapture()
                        } else {
                            coordinator.packetCaptureManager.startCapture()
                        }
                    }
                    .foregroundColor(coordinator.packetCaptureManager.isCapturing ? AppColors.critical : AppColors.info)
                    .font(.subheadline.weight(.semibold))
                }
            }
        }
    }
}
