// mDNSShark/Analysis/AnalysisView.swift
import SwiftUI

struct AnalysisView: View {
    @EnvironmentObject var coordinator: AppCoordinator

    var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 16) {
                    HStack(alignment: .top, spacing: 12) {
                        CardView {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Network Traffic").font(.headline)
                                Divider()
                                trafficRow("Inbound",  coordinator.analysisViewModel.inboundBytes,  AppColors.secure)
                                trafficRow("Outbound", coordinator.analysisViewModel.outboundBytes, AppColors.info)
                                HStack {
                                    Text("Total Packets").font(.subheadline).foregroundColor(.secondary)
                                    Spacer()
                                    Text("\(coordinator.analysisViewModel.totalPackets)").font(.subheadline.weight(.semibold))
                                }
                            }
                        }
                        .frame(maxWidth: .infinity)

                        CardView {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Protocol Distribution").font(.headline)
                                Divider()
                                if coordinator.analysisViewModel.protocolDistribution.isEmpty {
                                    Text("No data yet").font(.caption).foregroundColor(.secondary)
                                } else {
                                    ForEach(coordinator.analysisViewModel.protocolDistribution
                                        .sorted { $0.value > $1.value }, id: \.key) { k, v in
                                        HStack {
                                            Text(k).font(.subheadline).foregroundColor(.secondary)
                                            Spacer()
                                            Text(String(format: "%.0f%%", v)).font(.subheadline.weight(.semibold))
                                        }
                                    }
                                }
                            }
                        }
                        .frame(maxWidth: .infinity)
                    }

                    if !coordinator.analysisViewModel.recommendations.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Security Recommendations").font(.headline).padding(.horizontal, 4)
                            ForEach(coordinator.analysisViewModel.recommendations) { rec in
                                RecommendationCardView(rec: rec)
                            }
                        }
                    }
                }
                .padding(.horizontal).padding(.top, 8)
            }
            .navigationBarHidden(true)
        }
    }

    private func trafficRow(_ label: String, _ bytes: Int64, _ color: Color) -> some View {
        let text = ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
        return HStack {
            Text(label).font(.subheadline).foregroundColor(.secondary)
            Spacer()
            Text(text).font(.subheadline.weight(.semibold)).foregroundColor(color)
        }
    }
}
