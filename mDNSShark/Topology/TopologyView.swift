// mDNSShark/Topology/TopologyView.swift
import SwiftUI

struct TopologyView: View {
    @EnvironmentObject var scanVM: NetworkScanViewModel
    @EnvironmentObject var securityVM: SecurityViewModel
    // Only the id, not a DiscoveredDevice snapshot: `DiscoveredDevice` is a
    // struct, so a stored value here would freeze mac/manufacturer/
    // inferredOS at whatever they were at tap time. Re-deriving the live
    // device by id in `navigationDestination`'s closure below means an
    // already-open detail view keeps reflecting enrichment as it streams
    // in, instead of getting stuck on "Unknown" if tapped before it lands.
    @State private var selectedDeviceID: UUID? = nil
    @State private var navigateToDetail = false
    // Fallback while a rescan has not re-found the tapped device, so the pushed screen never goes blank.
    @State private var selectedDevice: DiscoveredDevice? = nil
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
        let allDevices = scanVM.devices
        let findings   = securityVM.findings
        guard !allDevices.isEmpty else { return [] }

        let ips       = pinnedIPs
        let pinned    = allDevices.filter {  ips.contains($0.ipAddress) }
        let nonPinned = allDevices.filter { !ips.contains($0.ipAddress) }
        let auto      = Array(prioritySorted(nonPinned, findings: findings).prefix(10))
        let toShow    = pinned + auto

        // The layout comes from every shown device, so toggling a chip never moves a node; chips only hide nodes (see `matchingIDs`).
        let filtered = toShow

        let gateway   = filtered.first { $0.isGateway } ?? filtered[0]
        let others    = filtered.filter { $0.id != gateway.id }
        var result    = [TopologyNode(device: enriched(gateway, findings), position: .zero)]
        guard !others.isEmpty else { return result }

        // One slot is held back for the services node so it never overlaps a device.
        let slots = others.count + (scanVM.unattachedServices.isEmpty ? 0 : 1)
        for (i, d) in others.enumerated() {
            result.append(TopologyNode(device: enriched(d, findings), position: unitPosition(index: i, of: slots)))
        }
        return result
    }

    /// The nodes the active chips let through; the rest keep their slot but are not drawn.
    private func matchingIDs(_ nodes: [TopologyNode]) -> Set<UUID> {
        Set(nodes.filter { node in
            TopologyNode.matchesFilters(node.securityStatus, securityFilters)
                && (typeFilters.isEmpty || typeFilters.contains(node.device.deviceType))
        }.map(\.id))
    }

    private func unitPosition(index: Int, of total: Int) -> CGPoint {
        let a = 2 * Double.pi / Double(total) * Double(index) - Double.pi / 2
        return CGPoint(x: cos(a), y: sin(a))
    }

    /// Where the services node sits: the last ring slot, the centre when no device exists, or nil when filters hide every device.
    private func servicesPosition(nodes: [TopologyNode]) -> CGPoint? {
        guard !scanVM.unattachedServices.isEmpty else { return nil }
        if nodes.isEmpty { return scanVM.devices.isEmpty ? .zero : nil }
        return unitPosition(index: nodes.count - 1, of: nodes.count)
    }

    var body: some View {
        // Evaluate once per render pass - avoids triple-computation and cross-call drift
        let nodes = visibleNodes
        let shown = matchingIDs(nodes)
        let servicesPos = servicesPosition(nodes: nodes)
        let services = scanVM.unattachedServices
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    if scanVM.devices.isEmpty && services.isEmpty {
                        emptyState
                    } else {
                        CardView {
                            VStack(alignment: .leading, spacing: 0) {
                                // Title - never covered by nodes
                                HStack {
                                    Label { Text("Network Topology") } icon: { WifiGlyph().frame(width: 20, height: 20) }
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
                                            var targets: [CGPoint] = nodes.dropFirst().filter { shown.contains($0.id) }.map { $0.position }
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
                                                .transition(.opacity)
                                                .scaleEffect(scale)
                                                .position(pixelPos(node.position))
                                                .opacity(shown.contains(node.id) ? 1 : 0)
                                                .allowsHitTesting(shown.contains(node.id))
                                                .accessibilityHidden(!shown.contains(node.id))
                                                .onTapGesture {
                                                    selectedDeviceID = node.device.id
                                                    selectedDevice = node.device
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

                                        if shown.isEmpty && servicesPos == nil {
                                            Text("No devices match the current filter.")
                                                .font(.caption)
                                                .foregroundColor(.secondary)
                                                .frame(maxWidth: .infinity, maxHeight: .infinity)
                                        }
                                    }
                                    // Nodes glide to their new slots when devices join or leave, instead of jumping.
                                    .animation(.snappy(duration: 0.3), value: nodes.map(\.id))
                                }
                                .frame(height: 280)

                                // Legend - never covered by nodes
                                HStack(spacing: 14) {
                                    ForEach(SecurityStatus.allCases, id: \.self) { legendDot($0.color, $0.label) }
                                }
                                .font(.caption)
                                .padding(.top, 10)
                            }
                        }
                        .sheet(isPresented: $showingPicker) {
                            DevicePickerSheet(
                                pinnedIPsRaw: $pinnedIPsRaw,
                                allDevices: scanVM.devices,
                                findings: securityVM.findings
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
                    UnattachedServicesSection(services: scanVM.unattachedServices)
                        .padding()
                }
            }
            // Keeps the pushed screen's fallback at the last live row, not the tap-time one, if a rescan has not re-found the device.
            .onChange(of: scanVM.devices) { _, devices in
                if let id = selectedDeviceID, let live = devices.first(where: { $0.id == id }) { selectedDevice = live }
            }
            .navigationDestination(isPresented: $navigateToDetail) {
                // The device is held in state, not looked up from `nodes`, so a filter change or a rescan cannot blank the pushed screen;
                // DeviceDetailView re-reads its live row and findings itself.
                if let selectedDevice { DeviceDetailView(device: selectedDevice) }
            }
        }
    }

    // MARK: - Filter chips

    private var filterChipBar: some View {
        VStack(alignment: .leading, spacing: 6) {
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    secChip(nil,             "All")
                    ForEach(SecurityStatus.allCases, id: \.self) { secChip($0, $0.label) }
                }
                .padding(.horizontal, 2)
            }
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: 8) {
                    typeChip(nil,       "All")
                    ForEach(DeviceType.allCases, id: \.self) { typeChip($0, $0.label) }
                }
                .padding(.horizontal, 2)
            }
        }
    }

    private func secChip(_ status: SecurityStatus?, _ label: String) -> some View {
        let active: Bool = status == nil ? securityFilters.isEmpty : securityFilters.contains(status!)
        let color: Color = status?.color ?? AppColors.info
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
            case .camera:   return 6
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
