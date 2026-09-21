// mDNSShark/App/AppCoordinator.swift
import Foundation
import Combine

enum AppTab: String, CaseIterable {
    case topology = "Topology"
    case devices  = "Devices"
    case security = "Security"
    case packets  = "Packets"
    case analysis = "Analysis"
    case settings = "Settings"

    var icon: String {
        switch self {
        case .topology: return "point.3.connected.trianglepath.dotted"
        case .devices:  return "magnifyingglass"
        case .security: return "shield"
        case .packets:  return "waveform"
        case .analysis: return "chart.bar"
        case .settings: return "gearshape.fill"
        }
    }
}

@MainActor
final class AppCoordinator: ObservableObject {
    @Published var selectedTab: AppTab = .topology

    let networkScanViewModel: NetworkScanViewModel
    let securityViewModel: SecurityViewModel
    let packetCaptureManager: PacketCaptureManager
    let analysisViewModel: AnalysisViewModel

    private var cancellables = Set<AnyCancellable>()

    init() {
        let threatDB = ThreatDatabase()
        networkScanViewModel  = NetworkScanViewModel()
        securityViewModel     = SecurityViewModel(threatDatabase: threatDB)
        packetCaptureManager  = PacketCaptureManager()
        analysisViewModel     = AnalysisViewModel()
        wire()
        // Waits out iOS's Local Network Privacy decision before the very
        // first scan fires — starting immediately here raced the system
        // permission alert on every fresh install (confirmed via a live
        // device log: `errno=65 EHOSTUNREACH` / `Local network prohibited`
        // on probes that fired before the user could possibly have
        // answered it, since the alert itself only renders in response to
        // this same traffic). See LocalNetworkPermissionGate.swift.
        Task {
            await LocalNetworkPermissionGate.waitForDecision()
            // If the user already ran a manual scan (the header Scan
            // button isn't disabled during the gate wait) while this was
            // still resolving, don't silently replace it with a second,
            // unrequested scan.
            guard !networkScanViewModel.hasScannedAtLeastOnce else { return }
            networkScanViewModel.startScan()
        }
        packetCaptureManager.healStaleVPNConfigIfNeeded()
    }

    private func wire() {
        networkScanViewModel.objectWillChange
            .sink { [weak self] in self?.objectWillChange.send() }
            .store(in: &cancellables)

        securityViewModel.objectWillChange
            .sink { [weak self] in self?.objectWillChange.send() }
            .store(in: &cancellables)

        networkScanViewModel.$devices
            .filter { !$0.isEmpty }
            .sink { [weak self] devices in
                guard let self else { return }
                Task { await self.securityViewModel.assess(devices: devices) }
            }
            .store(in: &cancellables)

        packetCaptureManager.objectWillChange
            .sink { [weak self] in self?.objectWillChange.send() }
            .store(in: &cancellables)

        analysisViewModel.objectWillChange
            .sink { [weak self] in self?.objectWillChange.send() }
            .store(in: &cancellables)

        packetCaptureManager.$packets
            .sink { [weak self] packets in
                self?.analysisViewModel.ingest(packets: packets)
            }
            .store(in: &cancellables)

        securityViewModel.$findings
            .sink { [weak self] findings in
                self?.analysisViewModel.update(findings: findings)
            }
            .store(in: &cancellables)
    }
}
