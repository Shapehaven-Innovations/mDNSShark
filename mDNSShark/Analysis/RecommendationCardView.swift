// mDNSShark/Analysis/RecommendationCardView.swift
import SwiftUI

struct RecommendationCardView: View {
    let rec: SecurityRecommendation
    @EnvironmentObject var coordinator: AppCoordinator

    private var color: Color {
        switch rec.severity {
        case .critical:      return AppColors.critical
        case .warning:       return AppColors.warning
        case .informational: return AppColors.info
        }
    }
    private var icon: String {
        switch rec.severity {
        case .critical:      return "exclamationmark.triangle.fill"
        case .warning:       return "shield.fill"
        case .informational: return "point.3.connected.trianglepath.dotted"
        }
    }

    var body: some View {
        CardView {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: icon).foregroundColor(color).font(.title3)
                VStack(alignment: .leading, spacing: 4) {
                    Text(rec.title).font(.subheadline.weight(.semibold)).foregroundColor(color)
                    Text(rec.description).font(.caption).foregroundColor(.secondary)
                }
                Spacer()
                if let title = rec.actionTitle {
                    Button(title) {
                        switch rec.action {
                        case .navigateToSecurity: coordinator.selectedTab = .security
                        case .navigateToTopology: coordinator.selectedTab = .topology
                        case .none: break
                        }
                    }
                    .font(.caption.weight(.semibold))
                    .buttonStyle(.bordered).tint(color)
                }
            }
        }
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(color.opacity(0.3), lineWidth: 1))
    }
}
