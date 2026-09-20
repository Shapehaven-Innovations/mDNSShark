import Foundation

public struct SSDPDescriptionInfo {
    public let manufacturer: String?
    public let modelName: String?
    public let serialNumber: String?
}

/// Parses the UPnP device-description XML document an SSDP `LOCATION`
/// header points to. Uses `XMLParser` (Foundation, available without any
/// extra dependency) rather than hand-rolled string scanning.
public enum SSDPDeviceDescription {
    public static func parse(_ xml: Data) -> SSDPDescriptionInfo? {
        let delegate = Delegate()
        let parser = XMLParser(data: xml)
        parser.delegate = delegate
        guard parser.parse() else { return nil }
        guard delegate.manufacturer != nil || delegate.modelName != nil || delegate.serialNumber != nil else {
            return nil
        }
        return SSDPDescriptionInfo(manufacturer: delegate.manufacturer, modelName: delegate.modelName, serialNumber: delegate.serialNumber)
    }

    private final class Delegate: NSObject, XMLParserDelegate {
        var manufacturer: String?, modelName: String?, serialNumber: String?
        private var currentText = ""

        func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
            currentText = ""
        }

        func parser(_ parser: XMLParser, foundCharacters string: String) {
            currentText += string
        }

        func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
            let trimmed = currentText.trimmingCharacters(in: .whitespacesAndNewlines)
            // First-wins: the root <device> is always the first one encountered
            // in document order, so once a field is captured we must not let a
            // later embedded sub-device (deviceList > device, e.g. WANDevice on
            // a router) overwrite it.
            switch elementName {
            case "manufacturer": if manufacturer == nil, !trimmed.isEmpty { manufacturer = trimmed }
            case "modelName": if modelName == nil, !trimmed.isEmpty { modelName = trimmed }
            case "serialNumber": if serialNumber == nil, !trimmed.isEmpty { serialNumber = trimmed }
            default: break
            }
        }
    }
}
