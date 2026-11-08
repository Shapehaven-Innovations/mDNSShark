import SwiftUI
import DeviceFingerprint

/// Licenses and third-party notices. Lives under Settings > About, next to Legal and Advisories.
struct AcknowledgementsView: View {
    var body: some View {
        List {
            Section("mDNSShark") {
                Link(destination: URL(string: "https://github.com/Shapehaven-Innovations/mDNSShark/blob/main/LICENSE")!) {
                    Label("Licensed under the Apache License 2.0", systemImage: "arrow.up.right.square")
                }
            }
            Section("Bluetooth names") {
                VStack(alignment: .leading, spacing: 6) {
                    Text(BluetoothDataNotice.title).font(.headline)
                    Text("Bluetooth company and service names. Copyright \(BluetoothDataNotice.source). \(BluetoothDataNotice.licenseName) License.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                .accessibilityElement(children: .combine)
                Link(destination: BluetoothDataNotice.sourceURL) {
                    Label("Source on GitHub", systemImage: "arrow.up.right.square")
                }
            }
            Section("License text") {
                Text(BluetoothDataNotice.licenseText)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Acknowledgements")
        .navigationBarTitleDisplayMode(.inline)
    }
}
