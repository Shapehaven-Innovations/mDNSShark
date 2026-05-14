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
                                trafficRow("Inbound",  coordinator.analysisViewModel.inboundMBps,  AppColors.secure, "MB")
                                trafficRow("Outbound", coordinator.analysisViewModel.outboundMBps, AppColors.info,   "MB")
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

    private func trafficRow(_ label: String, _ value: Double, _ color: Color, _ unit: String) -> some View {
        HStack {
            Text(label).font(.subheadline).foregroundColor(.secondary)
            Spacer()
            Text(String(format: "%.1f %@", value, unit)).font(.subheadline.weight(.semibold)).foregroundColor(color)
        }
    }
}
