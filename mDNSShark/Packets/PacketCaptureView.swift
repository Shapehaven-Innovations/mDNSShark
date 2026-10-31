// mDNSShark/Packets/PacketCaptureView.swift
import SwiftUI

struct PacketCaptureView: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @State private var selectedProtocol = "All"
    @State private var decryptedOnly = false
    @State private var showWarning = false
    @State private var showExportError = false
    @State private var showDeleteConfirm = false
    private let protocols = PacketCaptureChip.all

    private var filtered: [PacketModel] {
        coordinator.packetCaptureManager.packets.filtered(byChip: selectedProtocol, decryptedOnly: decryptedOnly)
    }

    var body: some View {
        NavigationView {
            VStack(spacing: 0) {
                ScrollView(.horizontal, showsIndicators: false) {
                    HStack(spacing: 8) {
                        ForEach(protocols, id: \.self) { p in
                            Button(p) {
                                selectedProtocol = p
                                if p != "TCP" { decryptedOnly = false }
                            }
                                .buttonStyle(.bordered)
                                .tint(selectedProtocol == p ? AppColors.info : .secondary)
                                .font(.caption.weight(selectedProtocol == p ? .semibold : .regular))
                        }
                    }
                    .padding(.horizontal, 16).padding(.vertical, 8)
                }
                if selectedProtocol == "TCP" {
                    Picker("TCP entries", selection: $decryptedOnly) {
                        Text("All TCP").tag(false)
                        Text("Decrypted").tag(true)
                    }
                    .pickerStyle(.segmented)
                    .font(.caption)
                    .padding(.horizontal, 16).padding(.bottom, 8)
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
                        if selectedProtocol == "mDNS" {
                            Text(MDNSEmptyState.text(isCapturing: coordinator.packetCaptureManager.isCapturing,
                                                     filterOn: SharedSettings.captureFilterProtocols.contains("mDNS"),
                                                     listenerStatus: SharedSettings.mdnsListenerStatus))
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 32)
                        } else if decryptedOnly {
                            Text("Decrypted HTTPS requests appear here only while TLS Inspection is enabled in Settings and the mDNSShark CA certificate is installed and trusted on this device. Domains on the Bypass List are relayed without decryption.")
                                .font(.caption)
                                .foregroundColor(.secondary)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 32)
                        }
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
                ToolbarItem(placement: .navigationBarLeading) {
                    if coordinator.packetCaptureManager.hasCapture &&
                       !coordinator.packetCaptureManager.isCapturing {
                        HStack(spacing: 12) {
                            Button { exportPCAP() } label: {
                                Label("Export", systemImage: "square.and.arrow.up")
                            }
                            Button(role: .destructive) { showDeleteConfirm = true } label: {
                                Label("Delete Capture", systemImage: "trash")
                            }
                            .foregroundColor(AppColors.critical)
                            // Wait for .disconnected so the extension can't rewrite capture-meta.json after deletion.
                            .disabled(!coordinator.packetCaptureManager.isTunnelDisconnected)
                        }
                    }
                }
                ToolbarItem(placement: .principal) {
                    Text("Packet Capture").font(.headline)
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button(coordinator.packetCaptureManager.isCapturing ? "Stop" : "Start") {
                        if coordinator.packetCaptureManager.isCapturing {
                            coordinator.packetCaptureManager.stopCapture()
                        } else {
                            showWarning = true
                        }
                    }
                    .foregroundColor(coordinator.packetCaptureManager.isCapturing
                                     ? AppColors.critical : AppColors.info)
                    .font(.subheadline.weight(.semibold))
                }
            }
            .sheet(isPresented: $showWarning) {
                CaptureWarningSheet(
                    onConfirm: { coordinator.packetCaptureManager.startCapture() },
                    isPresented: $showWarning
                )
                .presentationDetents([PresentationDetent.medium])
            }
            .alert("Export Failed", isPresented: $showExportError) {
                Button("OK", role: .cancel) {}
            } message: {
                Text("No capture file found. Run a capture session first.")
            }
            .confirmationDialog("Delete Capture?", isPresented: $showDeleteConfirm, titleVisibility: .visible) {
                Button("Delete Capture", role: .destructive) {
                    coordinator.packetCaptureManager.deleteCapture()
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This permanently removes the captured packets, pcap file, and capture metadata from this device.")
            }
        }
    }

    private func exportPCAP() {
        guard let urls = coordinator.packetCaptureManager.exportURLs() else {
            showExportError = true
            return
        }
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd-HHmmss"
        let stem = "mDNSShark-\(formatter.string(from: captureStartDate(metaURL: urls.meta)))"
        let fm = FileManager.default

        let tmp = fm.temporaryDirectory.appendingPathComponent("\(stem).pcap")
        try? fm.removeItem(at: tmp)
        try? fm.copyItem(at: urls.pcap, to: tmp)

        var items: [Any] = [tmp]
        if fm.fileExists(atPath: urls.meta.path) {
            let metaTmp = fm.temporaryDirectory.appendingPathComponent("\(stem)-meta.json")
            try? fm.removeItem(at: metaTmp)
            if (try? fm.copyItem(at: urls.meta, to: metaTmp)) != nil {
                items.append(metaTmp)
            }
        }

        let ac = UIActivityViewController(activityItems: items, applicationActivities: nil)
        if let scene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let root = scene.windows.first?.rootViewController {
            root.present(ac, animated: true)
        }
    }

    // Names exports by capture start (meta captureStart, else first packet) so pcap and meta pair up.
    private func captureStartDate(metaURL: URL) -> Date {
        if let data = try? Data(contentsOf: metaURL),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
           let str = obj["captureStart"] as? String {
            let frac = ISO8601DateFormatter()
            frac.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            if let d = ISO8601DateFormatter().date(from: str) ?? frac.date(from: str) { return d }
        }
        return coordinator.packetCaptureManager.packets.first?.timestamp ?? Date()
    }
}

/// Quick-filter chips on the Packet Capture tab, in display order.
enum PacketCaptureChip {
    static let all = ["All", "TCP", "UDP", "DNS", "mDNS", "Other"]
    static let tcpProtocols: Set<String> = ["TCP", "HTTP", "HTTPS"]
    static let knownProtocols: Set<String> = ["TCP", "UDP", "DNS", "mDNS", "HTTPS", "HTTP", "ICMP"]
}

extension Array where Element == PacketModel {
    /// Applies a chip from `PacketCaptureChip.all`; `decryptedOnly` then narrows the result to decrypted HTTPS requests, which only the TCP chip offers.
    func filtered(byChip chip: String, decryptedOnly: Bool = false) -> [PacketModel] {
        let byChip: [PacketModel]
        switch chip {
        case "All":   byChip = self
        case "TCP":   byChip = filter { PacketCaptureChip.tcpProtocols.contains($0.protocolName) }
        case "UDP":   byChip = filter { $0.protocolName == "UDP" }
        case "Other": byChip = filter { !PacketCaptureChip.knownProtocols.contains($0.protocolName) }
        default:      byChip = filter { $0.protocolName == chip }
        }
        return decryptedOnly ? byChip.filter { $0.isDecryptedRequest } : byChip
    }
}
