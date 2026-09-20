import Foundation

/// Parsed identity fields from either a Linksys JNAP (`POST /JNAP/`, JSON) or
/// an HNAP (`POST /HNAP1/`, SOAP/XML) device-info response. Same wire-level
/// idea as `SSDPDescriptionInfo` — the device answering its own vendor API
/// directly, so this is ground-truth tier, not a guess.
public struct JNAPHNAPInfo {
    public let vendorName: String?
    public let modelName: String?
    public let modelDescription: String?
    public let firmwareVersion: String?
}

public enum JNAPHNAPParser {
    /// Parses a JNAP `core/GetDeviceInfo` JSON response body:
    /// `{"result":"OK","output":{"manufacturer":"Linksys","modelNumber":"MX5500","description":"...","firmwareVersion":"..."}}`.
    /// Requires `result == "OK"` — this result is merged as ground truth
    /// (unconditionally overrides weaker sources), so it's worth rejecting
    /// anything the device itself didn't report success on, rather than
    /// accepting any 200 response that happens to contain JSON shaped like
    /// this envelope.
    public static func parseJNAP(_ json: Data) -> JNAPHNAPInfo? {
        guard let root = try? JSONSerialization.jsonObject(with: json) as? [String: Any],
              root["result"] as? String == "OK",
              let output = root["output"] as? [String: Any] else {
            return nil
        }
        let vendorName = output["manufacturer"] as? String
        let modelName = output["modelNumber"] as? String
        let modelDescription = output["description"] as? String
        let firmwareVersion = output["firmwareVersion"] as? String
        guard vendorName != nil || modelName != nil || modelDescription != nil || firmwareVersion != nil else {
            return nil
        }
        return JNAPHNAPInfo(vendorName: vendorName, modelName: modelName, modelDescription: modelDescription, firmwareVersion: firmwareVersion)
    }

    /// Parses an HNAP `GetDeviceSettings` SOAP/XML response body. Field names
    /// vary a little across vendors, so this looks for the common ones seen
    /// in the wild (`VendorName`/`ModelName`/`ModelDescription`/
    /// `FirmwareVersion`). Deliberately does NOT fall back to `DeviceName` —
    /// that field is the user-editable host name ("Living Room"), not a
    /// model, and this result is merged as ground truth so a wrong value
    /// there would silently override real data. Requires
    /// `GetDeviceSettingsResult == "OK"`, same reasoning as JNAP's `result`
    /// check.
    public static func parseHNAP(_ xml: Data) -> JNAPHNAPInfo? {
        let delegate = Delegate()
        let parser = XMLParser(data: xml)
        parser.delegate = delegate
        guard parser.parse(), delegate.result == "OK" else { return nil }
        guard delegate.vendorName != nil || delegate.modelName != nil || delegate.modelDescription != nil
                || delegate.firmwareVersion != nil else {
            return nil
        }
        return JNAPHNAPInfo(vendorName: delegate.vendorName, modelName: delegate.modelName,
                             modelDescription: delegate.modelDescription, firmwareVersion: delegate.firmwareVersion)
    }

    private final class Delegate: NSObject, XMLParserDelegate {
        var vendorName: String?, modelName: String?, modelDescription: String?, firmwareVersion: String?, result: String?
        private var currentText = ""

        func parser(_ parser: XMLParser, didStartElement elementName: String, namespaceURI: String?, qualifiedName qName: String?, attributes attributeDict: [String: String] = [:]) {
            currentText = ""
        }

        func parser(_ parser: XMLParser, foundCharacters string: String) {
            currentText += string
        }

        func parser(_ parser: XMLParser, didEndElement elementName: String, namespaceURI: String?, qualifiedName qName: String?) {
            let trimmed = currentText.trimmingCharacters(in: .whitespacesAndNewlines)
            // First-wins, same reasoning as SSDPDeviceDescription: don't let a
            // later, unrelated element with the same local name overwrite an
            // already-captured field.
            switch elementName {
            case "VendorName": if vendorName == nil, !trimmed.isEmpty { vendorName = trimmed }
            case "ModelName": if modelName == nil, !trimmed.isEmpty { modelName = trimmed }
            case "ModelDescription": if modelDescription == nil, !trimmed.isEmpty { modelDescription = trimmed }
            case "FirmwareVersion": if firmwareVersion == nil, !trimmed.isEmpty { firmwareVersion = trimmed }
            case "GetDeviceSettingsResult": if result == nil, !trimmed.isEmpty { result = trimmed }
            default: break
            }
        }
    }
}
