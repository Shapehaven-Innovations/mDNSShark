// mDNSShark/Security/SecurityView.swift
import SwiftUI

struct SecurityView: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @State private var criticalExpanded = true
    @State private var warningExpanded  = true
    @State private var infoExpanded     = false
    @State private var sharePresented   = false

    private var vm: SecurityViewModel { coordinator.securityViewModel }

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 16) {
                    overviewCard
                    if vm.isAssessing { ProgressView("Assessing…") }
                    if !vm.findings.isEmpty {
                        groupPicker
                        findingsContent
                    } else if !vm.isAssessing {
                        emptyState
                    }
                    footerButtons
                }
                .padding(.horizontal)
                .padding(.top, 8)
            }
            .navigationBarHidden(false)
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                if !vm.findings.isEmpty {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button {
                            sharePresented = true
                        } label: {
                            Image(systemName: "square.and.arrow.up")
                        }
                    }
                }
            }
            .sheet(isPresented: $sharePresented) {
                ShareSheet(items: [vm.exportText])
            }
        }
    }

    // MARK: - Subviews

    private var overviewCard: some View {
        CardView {
            VStack(spacing: 16) {
                Text("Security Overview")
                    .font(.headline)
                    .frame(maxWidth: .infinity, alignment: .leading)
                HStack {
                    stat(vm.findings.count,        "Total Vulnerabilities", AppColors.critical)
                    Divider().frame(height: 40)
                    stat(vm.vulnerableDeviceCount, "Vulnerable Devices",    AppColors.warning)
                }
            }
        }
    }

    private var groupPicker: some View {
        Picker("Group by", selection: Binding(
            get: { vm.groupMode },
            set: { vm.groupMode = $0 }
        )) {
            ForEach(GroupMode.allCases, id: \.self) { mode in
                Text(mode.rawValue).tag(mode)
            }
        }
        .pickerStyle(.segmented)
    }

    @ViewBuilder
    private var findingsContent: some View {
        switch vm.groupMode {
        case .severity: severityContent
        case .device:   deviceContent
        case .all:      allContent
        }
    }

    private var severityContent: some View {
        VStack(spacing: 16) {
            if !vm.criticalFindings.isEmpty {
                findingSection(title: "Critical Security Issues",
                               icon: "exclamationmark.triangle.fill",
                               color: AppColors.critical,
                               findings: vm.criticalFindings,
                               expanded: $criticalExpanded,
                               showDeviceName: true)
            }
            if !vm.warningFindings.isEmpty {
                findingSection(title: "Security Warnings",
                               icon: "shield.fill",
                               color: AppColors.warning,
                               findings: vm.warningFindings,
                               expanded: $warningExpanded,
                               showDeviceName: true)
            }
            if !vm.informationalFindings.isEmpty {
                findingSection(title: "Informational Notices",
                               icon: "info.circle.fill",
                               color: AppColors.info,
                               findings: vm.informationalFindings,
                               expanded: $infoExpanded,
                               showDeviceName: true)
            }
        }
    }

    private var deviceContent: some View {
        VStack(spacing: 16) {
            ForEach(vm.findingsByDevice, id: \.deviceName) { group in
                DeviceFindingsSectionView(
                    deviceName: group.deviceName,
                    deviceIcon: group.deviceIcon,
                    findings: group.findings
                )
            }
        }
    }

    private var allContent: some View {
        CardView {
            VStack(alignment: .leading, spacing: 0) {
                ForEach(vm.allFindingsSorted) { f in
                    FindingRowView(finding: f, showDeviceName: true)
                    if f.id != vm.allFindingsSorted.last?.id { Divider() }
                }
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 48))
                .foregroundColor(AppColors.secure)
            Text("No vulnerabilities found. Run a scan to assess your network.")
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }.padding(40)
    }

    private var isCapturing: Bool { coordinator.packetCaptureManager.isCapturing }

    private var footerButtons: some View {
        VStack(spacing: 8) {
            Text("Security checks run entirely on this device. Refreshing downloads CISA's public catalog; your devices and scan results are never uploaded.")
                .font(.caption).foregroundColor(.secondary).multilineTextAlignment(.center)

            Button {
                vm.startThreatDataRefresh()
            } label: {
                if vm.isRefreshing {
                    HStack(spacing: 6) {
                        ProgressView().progressViewStyle(.circular)
                        Text("Refreshing…")
                    }
                    .font(.subheadline)
                } else {
                    Label("Refresh CISA Data", systemImage: "arrow.clockwise")
                        .font(.subheadline)
                }
            }
            .buttonStyle(.bordered)
            .disabled(vm.isRefreshing || isCapturing)

            if let status = vm.threatDataStatus {
                let summary = status.summary()
                Text(summary.text)
                    .font(.caption2)
                    .foregroundColor(summary.isStale ? AppColors.warning : .secondary)
                Text("Findings flag exposed services and manufacturers with published advisories. mDNSShark does not confirm that a specific vulnerability is present on a device.")
                    .font(.caption2).foregroundColor(.secondary).multilineTextAlignment(.center)
                Text("This product uses the NVD API but is not endorsed or certified by the NVD.")
                    .font(.caption2).foregroundColor(.secondary).multilineTextAlignment(.center)
            }

            if isCapturing {
                Text("Stop packet capture to refresh. Otherwise the download would pass through the capture tunnel.")
                    .font(.caption2).foregroundColor(AppColors.warning).multilineTextAlignment(.center)
            } else if let reason = vm.refreshError {
                Text(refreshErrorText(reason))
                    .font(.caption2).foregroundColor(AppColors.warning).multilineTextAlignment(.center)
            }
        }
        .padding(.top, 8)
    }

    private func refreshErrorText(_ reason: ThreatRefreshFailure) -> String {
        switch reason {
        case .captureActive:
            return "Stop packet capture to refresh. Otherwise the download would pass through the capture tunnel."
        case .cancelledByCapture:
            return "Refresh stopped because packet capture started."
        case .network:
            return "Couldn't reach CISA. Check your connection and try again."
        case .unusableData:
            return "CISA returned data mDNSShark couldn't use. Your existing threat data was kept."
        case .saveFailed:
            return "Couldn't save the update. Your existing threat data was kept."
        }
    }

    // MARK: - Helpers

    private func stat(_ value: Int, _ label: String, _ color: Color) -> some View {
        VStack(spacing: 4) {
            Text("\(value)").font(.system(size: 36, weight: .bold)).foregroundColor(color)
            Text(label).font(.caption).foregroundColor(.secondary).multilineTextAlignment(.center)
        }.frame(maxWidth: .infinity)
    }

    private func findingSection(title: String, icon: String, color: Color,
                                 findings: [SecurityFinding], expanded: Binding<Bool>,
                                 showDeviceName: Bool) -> some View {
        CardView {
            VStack(alignment: .leading, spacing: 0) {
                Button { expanded.wrappedValue.toggle() } label: {
                    HStack {
                        Image(systemName: icon).foregroundColor(color)
                        Text(title).font(.headline).foregroundColor(color)
                        Spacer()
                        Image(systemName: expanded.wrappedValue ? "chevron.up" : "chevron.down")
                            .foregroundColor(.secondary)
                    }
                }
                .buttonStyle(.plain)
                if expanded.wrappedValue {
                    Divider().padding(.top, 8)
                    ForEach(findings) { f in
                        FindingRowView(finding: f, showDeviceName: showDeviceName)
                        if f.id != findings.last?.id { Divider() }
                    }
                }
            }
        }
    }
}

// MARK: - Device section card

private struct DeviceFindingsSectionView: View {
    let deviceName: String
    let deviceIcon: String
    let findings: [SecurityFinding]
    @State private var expanded = true

    private var worstColor: Color {
        if findings.contains(where: { $0.severity == .critical }) { return AppColors.critical }
        if findings.contains(where: { $0.severity == .warning   }) { return AppColors.warning  }
        return AppColors.info
    }

    var body: some View {
        CardView {
            VStack(alignment: .leading, spacing: 0) {
                Button { expanded.toggle() } label: {
                    HStack {
                        Image(systemName: deviceIcon).foregroundColor(worstColor)
                        Text(deviceName).font(.headline).foregroundColor(.primary)
                        Spacer()
                        AppBadge(text: "\(findings.count)", color: worstColor)
                        Image(systemName: expanded ? "chevron.up" : "chevron.down")
                            .foregroundColor(.secondary)
                    }
                }
                .buttonStyle(.plain)
                if expanded {
                    Divider().padding(.top, 8)
                    ForEach(findings) { f in
                        FindingRowView(finding: f, showDeviceName: false)
                        if f.id != findings.last?.id { Divider() }
                    }
                }
            }
        }
    }
}
