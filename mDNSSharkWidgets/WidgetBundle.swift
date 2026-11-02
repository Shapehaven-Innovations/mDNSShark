import WidgetKit
import SwiftUI

// Later phases append the other widget kinds here.
@main
struct MDNSSharkWidgets: WidgetBundle {
    var body: some Widget {
        DevicesWidget()
        ScanNowWidget()
    }
}
