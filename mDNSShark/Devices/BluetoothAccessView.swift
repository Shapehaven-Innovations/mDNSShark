// mDNSShark/Devices/BluetoothAccessView.swift
import SwiftUI

/// The Bluetooth part of Devices when it cannot list anything yet: not asked, denied, restricted, off or unsupported.
struct BluetoothAccessView: View {
    let state: BluetoothAccessState
    let onAllow: () -> Void

    static let undeterminedTitle = "Nearby Bluetooth is not set up"
    static let undeterminedBody = "Allow Bluetooth to list nearby devices and spot which ones might also be on your Wi-Fi."
    static let undeterminedNote = "Nothing connects to your devices. Your phone only listens."
    static let allowButton = "Allow Bluetooth"
    static let deniedText = "Bluetooth access is off for mDNSShark."
    static let restrictedText = "Bluetooth is restricted on this phone."
    static let poweredOffText = "Turn on Bluetooth in Control Center."
    static let unsupportedText = "Bluetooth is not available on this device."
    static let footer = "Scanned on this phone only. Nothing is sent anywhere."

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            content
            Text(Self.footer).font(.caption).foregroundColor(.secondary)
                .frame(maxWidth: .infinity, alignment: .center)
                .multilineTextAlignment(.center)
        }
    }

    @ViewBuilder private var content: some View {
        switch state {
        case .ready:
            EmptyView()
        case .undetermined:
            CardView {
                VStack(spacing: 12) {
                    Image(systemName: BluetoothSymbol.name).font(.system(size: 40)).foregroundColor(AppColors.info)
                        .accessibilityHidden(true)
                    Text(Self.undeterminedTitle).font(.headline).accessibilityAddTraits(.isHeader)
                    Text(Self.undeterminedBody).font(.subheadline).foregroundColor(.secondary).multilineTextAlignment(.center)
                    Text(Self.undeterminedNote).font(.caption).foregroundColor(.secondary).multilineTextAlignment(.center)
                    // Large control size keeps the button at least 44 pt tall.
                    Button(Self.allowButton, action: onAllow).buttonStyle(.borderedProminent).controlSize(.large)
                        .accessibilityHint("Shows the system Bluetooth permission prompt, then scans nearby")
                }
                .frame(maxWidth: .infinity)
            }
        case .denied:
            banner(Self.deniedText, symbol: "exclamationmark.triangle", settings: Self.showsOpenSettings(.denied))
        case .restricted:
            banner(Self.restrictedText, symbol: "lock", settings: Self.showsOpenSettings(.restricted))
        case .poweredOff:
            banner(Self.poweredOffText, symbol: "power", settings: Self.showsOpenSettings(.poweredOff))
        case .unsupported:
            banner(Self.unsupportedText, symbol: "nosign", settings: Self.showsOpenSettings(.unsupported))
        }
    }

    /// Only a denial is fixed in this app's Settings page; the radio is turned on from Control Center.
    static func showsOpenSettings(_ state: BluetoothAccessState) -> Bool { state == .denied }

    /// Same layout as `LocalNetworkDeniedBanner` in ContentView.
    private func banner(_ text: String, symbol: String, settings: Bool) -> some View {
        HStack {
            Image(systemName: symbol).foregroundColor(AppColors.warning).accessibilityHidden(true)
            Text(text).font(.caption).foregroundColor(.primary)
            Spacer()
            if settings {
                // The 44 pt frame sits inside the label so the whole area takes the tap.
                Button {
                    if let url = URL(string: UIApplication.openSettingsURLString) { UIApplication.shared.open(url) }
                } label: {
                    Text("Open Settings").frame(minWidth: 44, minHeight: 44).contentShape(Rectangle())
                }
                .font(.caption)
            }
        }
        .padding(10)
        .background(AppColors.warning.opacity(0.15))
        .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}
