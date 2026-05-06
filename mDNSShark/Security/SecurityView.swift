// mDNSShark/Security/SecurityView.swift
import SwiftUI

struct SecurityView: View {
    @EnvironmentObject var coordinator: AppCoordinator
    @State private var criticalExpanded = true
    @State private var warningExpanded  = true

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 16) {
                    CardView {
                        VStack(spacing: 16) {
                            Text("Security Overview").font(.headline).frame(maxWidth: .infinity, alignment: .leading)
                            HStack {
                                stat(coordinator.securityViewModel.findings.count,        "Total Vulnerabilities", AppColors.critical)
                                Divider().frame(height: 40)
                                stat(coordinator.securityViewModel.vulnerableDeviceCount, "Vulnerable Devices",    AppColors.warning)
                            }
                        }
                    }

                    if coordinator.securityViewModel.isAssessing { ProgressView("Assessing…") }

                    if !coordinator.securityViewModel.criticalFindings.isEmpty {
                        section(title: "Critical Security Issues", icon: "exclamationmark.triangle.fill",
                                color: AppColors.critical, findings: coordinator.securityViewModel.criticalFindings,
                                expanded: $criticalExpanded)
                    }
                    if !coordinator.securityViewModel.warningFindings.isEmpty {
                        section(title: "Security Warnings", icon: "shield.fill",
                                color: AppColors.warning, findings: coordinator.securityViewModel.warningFindings,
                                expanded: $warningExpanded)
                    }
                    if coordinator.securityViewModel.findings.isEmpty && !coordinator.securityViewModel.isAssessing {
                        VStack(spacing: 12) {
                            Image(systemName: "checkmark.shield.fill").font(.system(size: 48)).foregroundColor(AppColors.secure)
                            Text("No vulnerabilities found. Run a scan to assess your network.").foregroundColor(.secondary).multilineTextAlignment(.center)
                        }.padding(40)
                    }

                    VStack(spacing: 8) {
                        Text("All assessments run entirely on-device. No data leaves your phone.")
                            .font(.caption).foregroundColor(.secondary).multilineTextAlignment(.center)
                        Button {
                            Task { await coordinator.securityViewModel.refreshThreatData() }
                        } label: {
                            if coordinator.securityViewModel.isRefreshing {
                                ProgressView().progressViewStyle(.circular)
                            } else {
                                Label("Refresh Threat Data", systemImage: "arrow.clockwise").font(.subheadline)
                            }
                        }
                        .buttonStyle(.bordered)
                        if let d = coordinator.securityViewModel.lastRefreshDate {
                            Text("Updated: \(d.formatted(.dateTime))").font(.caption2).foregroundColor(.secondary)
                        }
                    }
                    .padding(.top, 8)
                }
                .padding(.horizontal).padding(.top, 8)
            }
            .navigationBarHidden(true)
        }
    }

    private func stat(_ value: Int, _ label: String, _ color: Color) -> some View {
        VStack(spacing: 4) {
            Text("\(value)").font(.system(size: 36, weight: .bold)).foregroundColor(color)
            Text(label).font(.caption).foregroundColor(.secondary).multilineTextAlignment(.center)
        }.frame(maxWidth: .infinity)
    }

    private func section(title: String, icon: String, color: Color,
                         findings: [SecurityFinding], expanded: Binding<Bool>) -> some View {
        CardView {
            VStack(alignment: .leading, spacing: 0) {
                Button { expanded.wrappedValue.toggle() } label: {
                    HStack {
                        Image(systemName: icon).foregroundColor(color)
                        Text(title).font(.headline).foregroundColor(color)
                        Spacer()
                        Image(systemName: expanded.wrappedValue ? "chevron.up" : "chevron.down").foregroundColor(.secondary)
                    }
                }
                .buttonStyle(.plain)
                if expanded.wrappedValue {
                    Divider().padding(.top, 8)
                    ForEach(findings) { f in
                        FindingRowView(finding: f)
                        if f.id != findings.last?.id { Divider() }
                    }
                }
            }
        }
    }
}
