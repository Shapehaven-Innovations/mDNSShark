// mDNSShark/Security/FindingRowView.swift
import SwiftUI

struct FindingRowView: View {
    let finding: SecurityFinding
    var showDeviceName: Bool = true
    @State private var expanded = false

    private var color: Color {
        switch finding.severity {
        case .critical:      return AppColors.critical
        case .warning:       return AppColors.warning
        case .informational: return AppColors.info
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button { expanded.toggle() } label: {
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(finding.title)
                            .font(.subheadline.weight(.semibold))
                            .foregroundColor(color)
                        if showDeviceName {
                            Label(finding.deviceName, systemImage: finding.deviceIcon)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                        Text(finding.description)
                            .font(.caption)
                            .foregroundColor(.secondary)
                            .lineLimit(expanded ? nil : 2)
                    }
                    Spacer()
                    AppBadge(text: finding.source.rawValue, color: Color(.systemGray))
                }
            }
            .buttonStyle(.plain)

            if expanded {
                VStack(alignment: .leading, spacing: 6) {
                    Text("Recommendation")
                        .font(.caption.weight(.semibold))
                        .foregroundColor(.secondary)
                    Text(finding.recommendation)
                        .font(.caption)
                    if let url = finding.referenceURL {
                        Link(
                            "View \(finding.cveID ?? "reference") →",
                            destination: url
                        )
                        .font(.caption.weight(.medium))
                        .foregroundColor(color)
                    }
                }
                .padding(8)
                .background(color.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
        }
        .padding(.vertical, 4)
    }
}
