// mDNSShark/App/AppCoordinator.swift
import Foundation
import Combine
import UIKit
import WidgetSnapshot

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
    /// Set by `showDevices(filter:)`; the Devices tab consumes it.
    @Published var devicesFilterRequest: DevicesFilter?

    let networkScanViewModel: NetworkScanViewModel
    let securityViewModel: SecurityViewModel
    let packetCaptureManager: PacketCaptureManager
    let analysisViewModel: AnalysisViewModel
    let bluetoothViewModel: BluetoothViewModel

    let deepLinkRouter = DeepLinkRouter()
    let widgetWriter = WidgetSnapshotWriter(store: SnapshotStore.appGroup())

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
        bluetoothViewModel    = BluetoothViewModel(store: BLEDeviceStore.appSupport())
        wire()
        UserDefaults.standard.removeObject(forKey: "preferredColorScheme") // retired theme override
        Task { await securityViewModel.loadThreatDataStatus() }
        // The Local Network check and first scan start from ContentView once the splash is gone: `NetworkScanViewModel.startLaunchGateIfNeeded`.
        packetCaptureManager.healStaleVPNConfigIfNeeded()
    }

    func widgetInput() -> WidgetSnapshotWriter.Input {
        let cidr = networkScanViewModel.networkCIDR
        return WidgetSnapshotWriter.Input(
            devices: networkScanViewModel.devices,
            status: { [securityViewModel] in securityViewModel.status(of: $0) },
            ownAddressKeys: networkScanViewModel.ownAddressMatchKeys,
            subnet: cidr == "Unknown" ? nil : cidr,
            localNetwork: networkScanViewModel.scanPermissionDecision,
            localNetworkDeniedBanner: networkScanViewModel.isLocalNetworkDenied,
            // A scan ending with the app not active (a widget run) may replace the snapshot only after a confirmed grant.
            requiresConfirmedGrant: UIApplication.shared.applicationState != .active,
            bluetooth: bluetoothViewModel.widgetUpdate())
    }

    func showDevices(filter: DevicesFilter) {
        devicesFilterRequest = filter
        selectedTab = .devices
    }

    /// The header Scan: always the LAN scan, plus Bluetooth when it is already allowed and the setting is on. Never prompts.
    func startHeaderScan() {
        networkScanViewModel.startScan()
        if BluetoothScanPolicy.headerScanStartsBluetooth(authorization: bluetoothViewModel.authorization,
                                                         includeSetting: SharedSettings.includeBluetoothInScan) {
            bluetoothViewModel.startScanIfAuthorized()
        }
    }

    var isAnyScanRunning: Bool { networkScanViewModel.isScanning || bluetoothViewModel.isScanning }

    func open(_ url: URL) {
        if let tab = deepLinkRouter.open(url, devices: networkScanViewModel.devices, isScanning: networkScanViewModel.isScanning) {
            selectedTab = tab
        }
    }

    /// A request older than 120 s is dropped so a stale flag never starts a surprise scan.
    func consumeWidgetScanRequest() {
        Self.consumeScanRequest(from: SharedSettings.suite, now: Date(), gateSettled: networkScanViewModel.launchGateSettled) {
            networkScanViewModel.restartScan()
        }
    }

    /// Always clears the flag; an unsettled launch gate runs the first scan itself, so restarting then would skip its permission redo.
    static func consumeScanRequest(from defaults: UserDefaults, now: Date, gateSettled: Bool, restart: () -> Void) {
        if ScanRequestFlag.consume(from: defaults, now: now), gateSettled { restart() }
    }

    private func wire() {
        networkScanViewModel.scanFinished
            .sink { [weak self] in
                guard let self else { return }
                self.widgetWriter.scanDidFinish(self.widgetInput())
                self.deepLinkRouter.scanFinished()
            }
            .store(in: &cancellables)

        // The closure runs after the debounce, so it reads settled rows and findings, not the willSet value.
        // A threat-data refresh changes findings without changing devices, so both sources schedule the debounced rewrite.
        // Bluetooth changes are throttled to one a minute as a backstop on top of the debounce and the writer's equality check.
        WidgetSnapshotWriter.rewriteTriggers(
            devices: networkScanViewModel.$devices, findings: securityViewModel.$findings,
            bluetooth: bluetoothViewModel.widgetUpdates.throttle(for: .seconds(60), scheduler: DispatchQueue.main, latest: true))
            .sink { [weak self] _ in
                self?.widgetWriter.scheduleRewrite { [weak self] in
                    guard let self, !self.networkScanViewModel.isScanning else { return nil }
                    return self.widgetInput()
                }
            }
            .store(in: &cancellables)

        // Runs inside `devices`' willSet, so the sink parameter is the new list and `networkScanViewModel.devices` is still the old one.
        networkScanViewModel.$devices
            .sink { [weak self] in
                self?.securityViewModel.assess(devices: $0)
                self?.deepLinkRouter.devicesChanged($0)
            }
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
