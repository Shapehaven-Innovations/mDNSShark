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
            ForEach(DataNotice.all) { notice in
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        Text(notice.title).font(.headline)
                        Text("\(notice.summary) \(notice.licenseName).")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                    Link(destination: notice.sourceURL) {
                        Label("Source on GitHub", systemImage: "arrow.up.right.square")
                    }
                    DisclosureGroup("License text") {
                        Text(notice.licenseText)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }
                }
            }
        }
        .listStyle(.insetGrouped)
        .navigationTitle("Acknowledgements")
        .navigationBarTitleDisplayMode(.inline)
    }
}
