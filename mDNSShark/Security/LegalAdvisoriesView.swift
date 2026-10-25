// mDNSShark/Security/LegalAdvisoriesView.swift
import SwiftUI

/// Privacy, interpretation and attribution notes for the Security tab, pushed from Settings > About.
struct LegalAdvisoriesView: View {
    @ObservedObject var viewModel: SecurityViewModel

    var body: some View {
        List {
            Section("Your data stays on this device") {
                Label {
                    Text("Security checks run entirely on this device. Refreshing downloads CISA's public catalog; your devices and scan results are never uploaded.")
                } icon: {
                    Image(systemName: "lock.shield.fill").foregroundColor(AppColors.secure)
                }
            }

            Section("What findings mean") {
                Label {
                    Text("Findings flag exposed services and manufacturers with published advisories. mDNSShark does not confirm that a specific vulnerability is present on a device.")
                } icon: {
                    Image(systemName: "exclamationmark.shield.fill").foregroundColor(AppColors.warning)
                }
            }

            Section("Data sources") {
                Link(destination: URL(string: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")!) {
                    Label("CISA Known Exploited Vulnerabilities (KEV) catalog", systemImage: "arrow.up.right.square")
                }
                Link(destination: URL(string: "https://nvd.nist.gov")!) {
                    Label("NIST National Vulnerability Database (NVD)", systemImage: "arrow.up.right.square")
                }
                Text("This product uses the NVD API but is not endorsed or certified by the NVD.")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Section("Last refresh") {
                if let status = viewModel.threatDataStatus {
                    let summary = status.summary()
                    Text(summary.text)
                        .font(.subheadline)
                        .foregroundColor(summary.isStale ? AppColors.warning : .primary)
                } else {
                    Text("CISA exploit data: not yet loaded.")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Legal and Advisories")
        .navigationBarTitleDisplayMode(.inline)
    }
}
