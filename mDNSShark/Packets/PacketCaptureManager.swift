// mDNSShark/Packets/PacketCaptureManager.swift
import Foundation
import NetworkExtension
import Combine

@MainActor
final class PacketCaptureManager: ObservableObject {
    @Published var packets: [PacketModel] = []
    @Published var isCapturing: Bool = false
    @Published var hasCapture: Bool = false

    private var tunnelManager: NETunnelProviderManager?
    private var fileReadTimer: Timer?
    private var statusObserver: NSObjectProtocol?
    private var logOffset: UInt64 = 0

    private let sharedFileURL: URL = {
        let base = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.org.shapehaveninnovations.mDNSShark")
            ?? FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("packets.log")
    }()

    private let pcapFileURL: URL = {
        let base = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.org.shapehaveninnovations.mDNSShark")
            ?? FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("capture.pcap")
    }()

    private let metaFileURL: URL = {
        let base = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: "group.org.shapehaveninnovations.mDNSShark")
            ?? FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        return base.appendingPathComponent("capture-meta.json")
    }()

    func startCapture() {
        configureVPN { [weak self] error in
            guard let self else { return }
            if let error { print("VPN config error: \(error)"); return }
            self.observeVPNStatus()
            do {
                try self.tunnelManager?.connection.startVPNTunnel()
            } catch { print("VPN start error: \(error)") }
        }
    }

    func stopCapture() {
        tunnelManager?.connection.stopVPNTunnel()
        isCapturing = false
        hasCapture = !packets.isEmpty
        stopPolling()
        removeStatusObserver()
    }

    func exportURLs() -> (pcap: URL, meta: URL)? {
        guard FileManager.default.fileExists(atPath: pcapFileURL.path) else { return nil }
        return (pcapFileURL, metaFileURL)
    }

    // MARK: - VPN status observation

    private func observeVPNStatus() {
        removeStatusObserver()
        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: tunnelManager?.connection,
            queue: .main
        ) { [weak self] _ in
            // Task { @MainActor } required: this closure is @Sendable but accesses @MainActor state.
            Task { @MainActor [weak self] in
                guard let self else { return }
                switch self.tunnelManager?.connection.status {
                case .connected:
                    self.isCapturing = true
                    self.logOffset = 0
                    self.packets.removeAll()
                    self.startPolling()
                case .disconnected, .invalid:
                    self.isCapturing = false
                    self.hasCapture = !self.packets.isEmpty
                    self.stopPolling()
                default: break
                }
            }
        }
    }

    private func removeStatusObserver() {
        if let obs = statusObserver { NotificationCenter.default.removeObserver(obs) }
        statusObserver = nil
    }

    // MARK: - VPN configuration

    private func configureVPN(completion: @escaping (Error?) -> Void) {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            if let error { completion(error); return }
            let manager = managers?.first ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = "org.ShapehavenInnovations.mDNSShark.PacketTunnel"
            proto.serverAddress = "127.0.0.1"
            manager.protocolConfiguration = proto
            manager.localizedDescription = "Packet Capture Tunnel"
            manager.isEnabled = true
            manager.saveToPreferences { error in
                if let error { completion(error); return }
                manager.loadFromPreferences { error in
                    Task { @MainActor [weak self] in
                        self?.tunnelManager = manager
                        completion(error)
                    }
                }
            }
        }
    }

    // MARK: - Polling

    private func startPolling() {
        fileReadTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.poll() }
        }
    }

    private func stopPolling() {
        fileReadTimer?.invalidate()
        fileReadTimer = nil
    }

    // Reads only bytes past logOffset so the tunnel's open FileHandle is never disturbed.
    // Advances logOffset by the count of complete lines consumed (up to and including the
    // last newline). A partial final line (no trailing newline) stays for the next poll.
    private func poll() {
        guard let fh = try? FileHandle(forReadingFrom: sharedFileURL) else { return }
        defer { try? fh.close() }
        try? fh.seek(toOffset: logOffset)
        let newData = fh.readDataToEndOfFile()
        guard !newData.isEmpty else { return }

        let newline = UInt8(ascii: "\n")
        guard let lastNewlineIdx = newData.lastIndex(of: newline) else { return }
        let completeBytes = newData[newData.startIndex...lastNewlineIdx]
        logOffset += UInt64(completeBytes.count)

        let dec = JSONDecoder()
        dec.dateDecodingStrategy = .iso8601
        let newPackets = completeBytes
            .split(separator: newline)
            .compactMap { slice -> PacketModel? in
                let data = Data(slice)
                guard !data.isEmpty else { return nil }
                return try? dec.decode(PacketModel.self, from: data)
            }
        if !newPackets.isEmpty {
            packets.append(contentsOf: newPackets)
            hasCapture = true
        }
    }
}
