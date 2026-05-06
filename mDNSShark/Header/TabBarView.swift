// mDNSShark/Header/TabBarView.swift
import SwiftUI

struct TabBarView: View {
    @Binding var selectedTab: AppTab

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 4) {
                ForEach(AppTab.allCases, id: \.self) { tab in
                    tabItem(tab)
                }
            }
            .padding(.horizontal, 16).padding(.vertical, 8)
        }
        .background(Color(.systemBackground))
        .overlay(alignment: .bottom) { Divider() }
    }

    private func tabItem(_ tab: AppTab) -> some View {
        HStack(spacing: 6) {
            Image(systemName: tab.icon).font(.subheadline)
            Text(tab.rawValue)
                .font(.subheadline.weight(selectedTab == tab ? .semibold : .regular))
        }
        .foregroundColor(selectedTab == tab ? AppColors.info : .secondary)
        .padding(.horizontal, 14).padding(.vertical, 8)
        .background(selectedTab == tab ? AppColors.info.opacity(0.12) : .clear)
        .clipShape(Capsule())
        .animation(.easeInOut(duration: 0.2), value: selectedTab)
        .onTapGesture { selectedTab = tab }
    }
}
