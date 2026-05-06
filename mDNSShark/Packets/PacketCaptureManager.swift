// mDNSShark/Packets/PacketCaptureManager.swift
import Foundation
import NetworkExtension
import Combine

@MainActor
final class PacketCaptureManager: ObservableObject {
    @Published var packets: [PacketModel] = []
    @Published var isCapturing: Bool = false

    private let vpnManager = NEVPNManager.shared()
    private var fileReadTimer: Timer?

    private let sharedFileURL: URL = {
        let appGroup = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.com.yourcompany.mDNSShark")
        let base = appGroup ?? FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("packets.log")
    }()

    func startCapture() {
        configureVPN { [weak self] error in
            guard let self else { return }
            if let error { print("VPN config error: \(error)"); return }
            do {
                try self.vpnManager.connection.startVPNTunnel()
                Task { @MainActor in
                    self.isCapturing = true
                    self.startPolling()
                }
            } catch { print("VPN start error: \(error)") }
        }
    }

    func stopCapture() {
        vpnManager.connection.stopVPNTunnel()
        isCapturing = false
        stopPolling()
    }

    private func configureVPN(completion: @escaping (Error?) -> Void) {
        vpnManager.loadFromPreferences { [weak self] error in
            if let error { completion(error); return }
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "com.yourcompany.PacketTunnel"
            proto.serverAddress = "127.0.0.1"
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.vpnManager.protocolConfiguration = proto
                self.vpnManager.localizedDescription = "Packet Capture Tunnel"
                self.vpnManager.isEnabled = true
                self.vpnManager.saveToPreferences { completion($0) }
            }
        }
    }

    private func startPolling() {
        fileReadTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    private func stopPolling() {
        fileReadTimer?.invalidate(); fileReadTimer = nil
    }

    private func poll() {
        guard FileManager.default.fileExists(atPath: sharedFileURL.path),
              let content = try? String(contentsOf: sharedFileURL, encoding: .utf8) else { return }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        let newPackets = content.split(separator: "\n").compactMap { line -> PacketModel? in
            guard let data = line.data(using: .utf8) else { return nil }
            return try? dec.decode(PacketModel.self, from: data)
        }
        packets.append(contentsOf: newPackets)
        try? "".write(to: sharedFileURL, atomically: true, encoding: .utf8)
    }
}
