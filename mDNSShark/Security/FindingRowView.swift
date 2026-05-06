// mDNSShark/Security/FindingRowView.swift
import SwiftUI

struct FindingRowView: View {
    let finding: SecurityFinding
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
                    VStack(alignment: .leading, spacing: 4) {
                        Text(finding.title).font(.subheadline.weight(.semibold)).foregroundColor(color)
                        Text(finding.description).font(.caption).foregroundColor(.secondary).lineLimit(expanded ? nil : 2)
                    }
                    Spacer()
                    AppBadge(text: finding.source.rawValue, color: Color(.systemGray))
                }
            }
            .buttonStyle(.plain)
            if expanded {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Recommendation").font(.caption.weight(.semibold)).foregroundColor(.secondary)
                    Text(finding.recommendation).font(.caption)
                }
                .padding(8)
                .background(color.opacity(0.08))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }
        }
        .padding(.vertical, 4)
    }
}
