import WidgetKit
import SwiftUI

// Lists every widget this extension ships.
@main
struct MDNSSharkWidgets: WidgetBundle {
    var body: some Widget {
        DevicesWidget()
        ScanNowWidget()
        SecurityWidget()
    }
}
