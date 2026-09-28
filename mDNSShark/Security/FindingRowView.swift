// mDNSShark/Security/FindingRowView.swift
import SwiftUI

struct FindingRowView: View {
    let finding: SecurityFinding
    var showDeviceName: Bool = true
    @State private var expanded = false
    @State private var expandedTierID: String?
    @State private var showAllInExpandedTier = false

    private var color: Color { Self.severityColor(for: finding.severity) }

    private static func severityColor(for severity: Severity) -> Color {
        switch severity {
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
                    if !finding.cveTiers.isEmpty {
                        tierCapsules
                    }
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

    /// Tappable, light-tinted severity capsules (never the raw CVE ID list
    /// inline - a vendor advisory can carry dozens of IDs) that expand to a
    /// per-CVE list, each row linking to its NVD detail page for the full
    /// description/CVSS/references, with a "show more" for tiers over 8.
    private var tierCapsules: some View {
        VStack(alignment: .leading, spacing: 6) {
            FlowLayout(spacing: 6) {
                ForEach(finding.cveTiers) { tier in
                    let tierColor = Self.severityColor(for: tier.severity)
                    Button {
                        withAnimation(.easeInOut(duration: 0.15)) {
                            expandedTierID = (expandedTierID == tier.id) ? nil : tier.id
                            showAllInExpandedTier = false
                        }
                    } label: {
                        Text(tier.label)
                            .font(.caption2.weight(.semibold))
                            .foregroundColor(tierColor)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(tierColor.opacity(0.15))
                            .overlay(
                                Capsule().strokeBorder(tierColor.opacity(expandedTierID == tier.id ? 0.6 : 0), lineWidth: 1)
                            )
                            .clipShape(Capsule())
                    }
                    .buttonStyle(.plain)
                }
            }

            if let tierID = expandedTierID, let tier = finding.cveTiers.first(where: { $0.id == tierID }) {
                let cap = 8
                let shown = showAllInExpandedTier ? tier.entries : Array(tier.entries.prefix(cap))
                let remaining = tier.entries.count - shown.count

                VStack(alignment: .leading, spacing: 4) {
                    ForEach(shown) { entry in
                        let nvdURL = URL(string: "https://nvd.nist.gov/vuln/detail/\(entry.cveID)")
                        if let nvdURL {
                            Link(destination: nvdURL) {
                                HStack(alignment: .top, spacing: 6) {
                                    Text(entry.cveID)
                                        .font(.caption2.monospaced().weight(.semibold))
                                    Text(entry.title)
                                        .font(.caption2)
                                        .foregroundColor(.secondary)
                                        .lineLimit(1)
                                }
                            }
                        }
                    }
                    if remaining > 0 {
                        Button("Show \(remaining) more →") {
                            withAnimation(.easeInOut(duration: 0.15)) { showAllInExpandedTier = true }
                        }
                        .font(.caption2.weight(.medium))
                    }
                }
            }
        }
    }
}

/// Minimal left-to-right wrapping row - SwiftUI has no built-in flow
/// layout usable pre-iOS 16's `Layout` protocol version this app targets
/// elsewhere, so this wraps capsules onto new lines instead of clipping
/// or forcing horizontal scroll.
struct FlowLayout: Layout {
    var spacing: CGFloat = 6

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var rowWidth: CGFloat = 0, totalHeight: CGFloat = 0, rowHeight: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if rowWidth + size.width > maxWidth, rowWidth > 0 {
                totalHeight += rowHeight + spacing
                rowWidth = 0
                rowHeight = 0
            }
            rowWidth += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
        totalHeight += rowHeight
        return CGSize(width: maxWidth, height: totalHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        var x = bounds.minX, y = bounds.minY, rowHeight: CGFloat = 0
        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x + size.width > bounds.maxX, x > bounds.minX {
                x = bounds.minX
                y += rowHeight + spacing
                rowHeight = 0
            }
            subview.place(at: CGPoint(x: x, y: y), proposal: .unspecified)
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}
