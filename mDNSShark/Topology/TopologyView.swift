// mDNSShark/Topology/TopologyView.swift
import SwiftUI

struct TopologyView: View {
    @EnvironmentObject var coordinator: AppCoordinator
    // Only the id, not a DiscoveredDevice snapshot: `DiscoveredDevice` is a
    // struct, so a stored value here would freeze mac/manufacturer/
    // inferredOS at whatever they were at tap time. Re-deriving the live
    // device by id in `navigationDestination`'s closure below means an
    // already-open detail view keeps reflecting enrichment as it streams
    // in, instead of getting stuck on "Unknown" if tapped before it lands.
    @State private var selectedDeviceID: UUID? = nil
    @State private var navigateToDetail = false
    @State private var securityFilters: Set<SecurityStatus> = []
    @State private var typeFilters: Set<DeviceType> = []
    @State private var showingPicker = false
    @State private var showingServices = false
    @AppStorage("pinnedDeviceIPs") private var pinnedIPsRaw: String = ""

    private var pinnedIPs: Set<String> {
        Set(pinnedIPsRaw.split(separator: ",").map(String.init).filter { !$0.isEmpty })
    }

    // Unit-circle positions: gateway at .zero, others at (cos θ, sin θ).
    // Actual pixel radius is applied at render time inside GeometryReader.
    private var visibleNodes: [TopologyNode] {
        let allDevices = coordinator.networkScanViewModel.devices
        let findings   = coordinator.securityViewModel.findings
        guard !allDevices.isEmpty else { return [] }

        let ips       = pinnedIPs
        let pinned    = allDevices.filter {  ips.contains($0.ipAddress) }
        let nonPinned = allDevices.filter { !ips.contains($0.ipAddress) }
        let auto      = Array(prioritySorted(nonPinned, findings: findings).prefix(10))
        let toShow    = pinned + auto

        let filtered = toShow.filter { device in
            let secStatus = TopologyNode.status(findings: findings.filter { $0.deviceID == device.id },
                                                settled: device.probesSettled)
            let secOK  = TopologyNode.matchesFilters(secStatus, securityFilters)
            let typeOK = typeFilters.isEmpty || typeFilters.contains(device.deviceType)
            return secOK && typeOK
        }

        guard !filtered.isEmpty else { return [] }

        let gateway   = filtered.first { $0.isGateway } ?? filtered[0]
        let others    = filtered.filter { $0.id != gateway.id }
        var result    = [TopologyNode(device: enriched(gateway, findings), position: .zero)]
        guard !others.isEmpty else { return result }

        // One slot is held back for the services node so it never overlaps a device.
        let slots = others.count + (coordinator.networkScanViewModel.unattachedServices.isEmpty ? 0 : 1)
        for (i, d) in others.enumerated() {
            result.append(TopologyNode(device: enriched(d, findings), position: unitPosition(index: i, of: slots)))
        }
        return result
    }

    private func unitPosition(index: Int, of total: Int) -> CGPoint {
        let a = 2 * Double.pi / Double(total) * Double(index) - Double.pi / 2
        return CGPoint(x: cos(a), y: sin(a))
    }

    /// Where the services node sits: the last ring slot, the centre when no device exists, or nil when filters hide every device.
    private func servicesPosition(nodes: [TopologyNode]) -> CGPoint? {
        guard !coordinator.networkScanViewModel.unattachedServices.isEmpty else { return nil }
        if nodes.isEmpty { return coordinator.networkScanViewModel.devices.isEmpty ? .zero : nil }
        return unitPosition(index: nodes.count - 1, of: nodes.count)
    }

    var body: some View {
        // Evaluate once per render pass - avoids triple-computation and cross-call drift
        let nodes = visibleNodes
        let servicesPos = servicesPosition(nodes: nodes)
        let services = coordinator.networkScanViewModel.unattachedServices
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    if coordinator.networkScanViewModel.devices.isEmpty && services.isEmpty {
                        emptyState
                    } else {
                        CardView {
                            VStack(alignment: .leading, spacing: 0) {
                                // Title - never covered by nodes
                                HStack {
                                    Label("Network Topology", systemImage: "wifi")
                                        .font(.headline)
                                    Spacer()
                                    Button { showingPicker = true } label: {
                                        Image(systemName: "pin.circle")
                                            .font(.title3)
                                            .foregroundColor(AppColors.info)
                                    }
                                    .buttonStyle(.plain)
                                    .accessibilityLabel("Pin Devices")
                                }
                                .padding(.bottom, 10)

                                // Filters - never covered by nodes
                                filterChipBar
                                    .padding(.bottom, 10)

                                // Canvas - nodes are strictly within this frame
                                GeometryReader { geo in
                                    let count     = max(1, nodes.count - 1 + (services.isEmpty || nodes.isEmpty ? 0 : 1))
                                    let radius    = CGFloat(max(110, min(180, count * 14)))
                                    let available = min(geo.size.width, geo.size.height) / 2 - 24
                                    let scale     = min(1.0, max(0.4, available / (radius + 40)))
                                    let center    = CGPoint(x: geo.size.width / 2, y: geo.size.height / 2)
                                    let pixelPos: (CGPoint) -> CGPoint = { unit in
                                        CGPoint(x: center.x + unit.x * radius * scale,
                                                y: center.y + unit.y * radius * scale)
                                    }

                                    ZStack {
                                        Canvas { ctx, _ in
                                            var targets: [CGPoint] = nodes.dropFirst().map { $0.position }
                                            if let servicesPos, !nodes.isEmpty { targets.append(servicesPos) }
                                            for target in targets {
                                                let nPos = pixelPos(target)
                                                var path = Path()
                                                path.move(to: center)
                                                path.addLine(to: nPos)
                                                ctx.stroke(path, with: .color(.secondary.opacity(0.4)),
                                                           style: StrokeStyle(lineWidth: 1.5, dash: [6, 4]))
                                            }
                                        }

                                        ForEach(nodes) { node in
                                            TopologyNodeView(node: node)
                                                .scaleEffect(scale)
                                                .position(pixelPos(node.position))
                                                .onTapGesture {
                                                    selectedDeviceID = node.device.id
                                                    navigateToDetail = true
                                                }
                                                .accessibilityAddTraits(.isButton)
                                        }

                                        if let servicesPos {
                                            ServicesGroupNodeView(count: services.count)
                                                .scaleEffect(scale)
                                                .position(pixelPos(servicesPos))
                                                .onTapGesture { showingServices = true }
                                                .accessibilityAddTraits(.isButton)
                                        }

                                        if nodes.isEmpty && servicesPos == nil {
                                            Text("No devices match the current filter.")
                                                .font(.caption)
                                                .foregroundColor(.secondary)
                                                .frame(maxWidth: .infinity, maxHeight: .infinity)
                                        }
                                    }
                                }
                                .frame(height: 280)

                                // Legend - never covered by nodes
                                HStack(spacing: 14) {
                                    legendDot(Color(.systemGray), "Pending")
                                    legendDot(AppColors.secure,   "Secure")
                                    legendDot(AppColors.info,     "Info")
                                    legendDot(AppColors.warning,  "Warning")
                                    legendDot(AppColors.critical, "Critical")
                                }
                                .font(.caption)
                                .padding(.top, 10)
                            }
                        }
                        .sheet(isPresented: $showingPicker) {
                            DevicePickerSheet(
                                pinnedIPsRaw: $pinnedIPsRaw,
                                allDevices: coordinator.networkScanViewModel.devices,
                                findings: coordinator.securityViewModel.findings
                            )
                        }
                        .padding(.horizontal)
                    }
                }
                .padding(.top, 8)
            }
            .navigationBarHidden(true)
            .sheet(isPresented: $showingServices) {
                ScrollView {
                    UnattachedServicesSection(services: coordinator.networkScanViewModel.unattachedServices)
                        .padding()
                }
            }
            .navigationDestination(isPresented: $navigateToDetail) {
                // Looked up from the raw (unfiltered, uncapped) devices
                // array, not `nodes`: `nodes` drops out-of-filter/beyond
                // top-10 devices, and a filter change or new device joining
                // while this detail view is open must not blank it out.
                // No findings overlay here: DeviceDetailView re-reads the
                // live row and findings from the coordinator itself.
                if let id = selectedDeviceID,
                   let device = coordinator.networkScanViewModel.devices.first(where: { $0.id == id }) {
                    DeviceDetailView(device: device)
                }
            }
        }
    }

    // MARK: - Filter chips

    private var filterChipBar: some View {
        VStack(alignment: .leading, spacing: 6) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    secChip(nil,             "All")
                    secChip(.pending,        "Pending")
                    secChip(.secure,         "Secure")
                    secChip(.informational,  "Info")
                    secChip(.warning,        "Warning")
                    secChip(.critical,       "Critical")
                }
                .padding(.horizontal, 2)
            }
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    typeChip(nil,       "All")
                    typeChip(.router,   "Router")
                    typeChip(.apple,    "Apple (other)")
                    typeChip(.computer, "Computer")
                    typeChip(.printer,  "Printer")
                    typeChip(.tv,       "TV")
                    typeChip(.unknown,  "Unknown")
                }
                .padding(.horizontal, 2)
            }
        }
    }

    private func secChip(_ status: SecurityStatus?, _ label: String) -> some View {
        let active: Bool = status == nil ? securityFilters.isEmpty : securityFilters.contains(status!)
        let color: Color = {
            switch status {
            case .none:             return AppColors.info
            case .pending:          return Color(.systemGray)
            case .secure:           return AppColors.secure
            case .informational:    return AppColors.info
            case .warning:          return AppColors.warning
            case .critical:         return AppColors.critical
            }
        }()
        return Button {
            if let s = status {
                if securityFilters.contains(s) { securityFilters.remove(s) }
                else { securityFilters.insert(s) }
            } else {
                securityFilters.removeAll()
            }
        } label: {
            Text(label)
                .font(.caption.weight(.medium))
                .padding(.horizontal, 10).padding(.vertical, 4)
                .background(active ? color : Color(.secondarySystemBackground))
                .foregroundColor(active ? .white : .secondary)
                .clipShape(Capsule())
        }
        .buttonStyle(.plain)
    }

    private func typeChip(_ type: DeviceType?, _ label: String) -> some View {
        let active: Bool = type == nil ? typeFilters.isEmpty : typeFilters.contains(type!)
        return Button {
            if let t = type {
                if typeFilters.contains(t) { typeFilters.remove(t) }
                else { typeFilters.insert(t) }
            } else {
                typeFilters.removeAll()
            }
        } label: {
            Text(label)
                .font(.caption.weight(.medium))
                .padding(.horizontal, 10).padding(.vertical, 4)
                .background(active ? AppColors.info : Color(.secondarySystemBackground))
                .foregroundColor(active ? .white : .secondary)
                .clipShape(Capsule())
        }
        .buttonStyle(.plain)
    }

    // MARK: - Helpers

    private func prioritySorted(_ devices: [DiscoveredDevice], findings: [SecurityFinding]) -> [DiscoveredDevice] {
        func rank(_ d: DiscoveredDevice) -> Int {
            if d.isGateway { return 0 }
            let worst = findings.filter { $0.deviceID == d.id }.worstDeviceSeverity
            if worst == .critical { return 1 }
            if worst == .warning  { return 2 }
            switch d.deviceType {
            case .apple:    return 3
            case .tv:       return 4
            case .printer:  return 5
            case .computer: return 6
            default:        return 7
            }
        }
        return devices.sorted { a, b in
            let ra = rank(a), rb = rank(b)
            return ra != rb ? ra < rb : a.ipAddress < b.ipAddress
        }
    }

    private func enriched(_ d: DiscoveredDevice, _ findings: [SecurityFinding]) -> DiscoveredDevice {
        var copy = d
        copy.securityFindings = findings.filter { $0.deviceID == d.id }
        return copy
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "point.3.connected.trianglepath.dotted")
                .font(.system(size: 48)).foregroundColor(.secondary)
            Text("No devices yet. Tap Scan to discover your network.")
                .foregroundColor(.secondary).multilineTextAlignment(.center)
        }.padding(40)
    }

    private func legendDot(_ color: Color, _ label: String) -> some View {
        HStack(spacing: 4) {
            Circle().fill(color).frame(width: 8, height: 8)
            Text(label).foregroundColor(.secondary)
        }
    }
}
