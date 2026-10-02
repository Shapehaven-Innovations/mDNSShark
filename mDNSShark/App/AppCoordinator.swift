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
        let threatDB = ThreatDatabase.live()
        let pcm = PacketCaptureManager()
        networkScanViewModel  = NetworkScanViewModel()
        securityViewModel     = SecurityViewModel(threatDatabase: threatDB, isTunnelActive: { [weak pcm] in
            await pcm?.isTunnelActive() ?? false
        })
        packetCaptureManager  = pcm
        analysisViewModel     = AnalysisViewModel()
        wire()
        Task { await securityViewModel.loadThreatDataStatus() }
        // Waits out iOS's Local Network Privacy decision before the very
        // first scan fires. Starting immediately here raced the system
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

        // With "Include LAN traffic in capture" on, the only LAN traffic
        // worth capturing is the app's own scan, and nothing in the UI
        // used to say the separate header Scan button had to be tapped
        // after Start Capture (todo.md item 1: every early verification
        // capture was empty for exactly that reason). So the moment the
        // tunnel actually reaches .connected (not the Start tap, since
        // connecting takes a beat), kick off a scan automatically.
        // `removeDuplicates` + `dropFirst` turns this into a strict
        // false -> true edge: the initial `false` seed on subscription is
        // dropped, and repeated `true`s can't re-fire. A scan already in
        // flight sent its sweep over Wi-Fi before the route existed, so
        // restart it rather than skip it. Left off when the
        // LAN toggle is off: a plain internet-traffic capture shouldn't
        // start a device sweep the user never asked for.
        packetCaptureManager.$isCapturing
            .removeDuplicates()
            .dropFirst()
            .filter { $0 }
            .sink { [weak self] _ in
                guard let self, SharedSettings.includeAllNetworksInCapture else { return }
                self.networkScanViewModel.restartScan()
            }
            .store(in: &cancellables)

        // A threat-data refresh's request to cisa.gov would otherwise get
        // routed into the capture tunnel it just started (and potentially
        // MITM'd by the app's own TLSInterceptor) — cancel it best-effort
        // the moment capture connects. `performThreatDataRefresh`'s own
        // `isTunnelActive()` pre-flight check is the authoritative guard;
        // this just cuts short a refresh already in flight when capture
        // starts mid-fetch.
        packetCaptureManager.$isCapturing
            .removeDuplicates()
            .dropFirst()
            .filter { $0 }
            .sink { [weak self] _ in
                self?.securityViewModel.cancelThreatDataRefresh()
            }
            .store(in: &cancellables)
    }
}
