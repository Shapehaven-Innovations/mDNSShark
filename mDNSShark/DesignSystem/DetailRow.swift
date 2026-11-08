// mDNSShark/DesignSystem/DetailRow.swift
import SwiftUI

/// A label and value row for detail cards.
struct DetailRow: View {
    let label: String
    let value: String
    var selectable: Bool = false

    var body: some View {
        // .firstTextBaseline, not .center: a wrapped two-line value would otherwise pull the label to its midpoint.
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundColor(.secondary).font(.subheadline)
            Spacer()
            if selectable {
                Text(value).font(.subheadline.weight(.medium)).multilineTextAlignment(.trailing)
                    .textSelection(.enabled)
            } else {
                Text(value).font(.subheadline.weight(.medium)).multilineTextAlignment(.trailing)
            }
        }
        .accessibilityElement(children: .combine)
    }
}
