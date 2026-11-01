import Testing
import DeviceFingerprint
@testable import mDNSShark

struct DeviceKindClassificationTests {
    private func device(manufacturer: String? = nil, gateway: Bool = false, services: [BonjourService]) -> DiscoveredDevice {
        var d = DiscoveredDevice(hostname: "x", ipAddress: "203.0.113.70", manufacturer: manufacturer, bonjourServices: services)
        d.isDefaultGateway = gateway
        return d
    }

    private func service(_ type: String, _ name: String = "svc", _ txt: [String: String] = [:]) -> BonjourService {
        BonjourService(serviceType: type, serviceName: name, port: 1, txtRecords: txt)
    }

    private let sonosFeatures = "0x445F8A00,0x1C340"
    private let samsungFeatures = "0x7F8AD0,0x38BCB46"

    @Test("a Sonos speaker with AirPlay is audio, not a TV")
    func sonosIsAudio() {
        let d = device(manufacturer: "Sonos", services: [service("_sonos._tcp"), service("_airplay._tcp", "Sonos", ["manufacturer": "Sonos", "features": sonosFeatures])])
        #expect(d.deviceType == .audio)
        #expect(d.deviceIcon == "hifispeaker")
    }

    @Test("an AirPlay receiver with audio-only features is audio even without a speaker type")
    func featuresAlone() {
        #expect(device(services: [service("_airplay._tcp", "Amp", ["features": sonosFeatures])]).deviceType == .audio)
    }

    @Test("non-Apple AirPlay with the Samsung TV features stays a TV")
    func samsungStaysTV() {
        let d = device(manufacturer: "Samsung", services: [service("_airplay._tcp", "TV", ["manufacturer": "Samsung", "features": samsungFeatures])])
        #expect(d.deviceType == .tv)
        #expect(device(services: [service("_airplay._tcp", "TV")]).deviceType == .tv)
    }

    @Test("an Apple HomePod is audio and an Apple TV with Matter and Thread types is Apple")
    func appleRules() {
        let pod = device(manufacturer: "Apple", services: [service("_airplay._tcp", "Pod", ["model": "AudioAccessory1,1"])])
        #expect(pod.deviceType == .audio)
        let tv = device(manufacturer: "Apple", services: [service("_airplay._tcp", "TV", ["model": "AppleTV11,1"]), service("_meshcop._udp"), service("_matter._tcp")])
        #expect(tv.deviceType == .apple)
    }

    @Test("catalog types give smart home and NAS")
    func catalogKinds() {
        #expect(device(services: [service("_hue._tcp")]).deviceType == .smartHome)
        #expect(device(services: [service("_hue._tcp")]).deviceIcon == "lightbulb")
        #expect(device(services: [service("_qdiscover._tcp")]).deviceType == .nas)
        #expect(device(services: [service("_qdiscover._tcp")]).deviceIcon == "externaldrive.connected.to.line.below")
    }

    @Test("camera evidence beats the catalog and a camera type alone is a camera")
    func cameraRules() {
        #expect(device(services: [service("_http._tcp", "AMC060E7AF0A5BCE81")]).deviceType == .camera)
        #expect(device(services: [service("_axis-video._tcp")]).deviceType == .camera)
        #expect(device(services: [service("_hue._tcp"), service("_axis-video._tcp")]).deviceType == .camera)
    }

    @Test("the gateway stays a router whatever it advertises")
    func gatewayWins() {
        #expect(device(gateway: true, services: [service("_hue._tcp")]).deviceType == .router)
    }

    @Test("the Alexa type marks only roomba and irobot names")
    func alexaName() {
        #expect(device(services: [service("_amzn-alexa._tcp", "roomba-123")]).deviceType == .smartHome)
        #expect(device(services: [service("_amzn-alexa._tcp", "Echo")]).deviceType == .unknown)
    }

    @Test("a HomeKit speaker category is audio and a network category has no chip")
    func hapCategories() {
        #expect(device(services: [service("_hap._tcp", "Spk", ["ci": "26"])]).deviceType == .audio)
        #expect(device(services: [service("_hap._tcp", "Rtr", ["ci": "33"])]).deviceType == .unknown)
    }

    @Test("labels are unique and the network kind maps to no type")
    func labelsAndNetwork() {
        let labels = DeviceType.allCases.map(\.label)
        #expect(Set(labels).count == labels.count)
        #expect(DeviceType(kind: .network) == nil)
        #expect(DeviceType(kind: .nas) == .nas)
    }

    @Test("the chip row shows only present or actively filtered types")
    func chipFilter() {
        let devices = [device(services: [service("_hue._tcp")]), device(services: [])]
        #expect(TopologyView.visibleTypeChips(devices: devices, active: []) == [.smartHome, .unknown])
        #expect(TopologyView.visibleTypeChips(devices: devices, active: [.nas]) == [.smartHome, .nas, .unknown])
    }

    @Test("the vendor is only the device's own non-empty TXT claim, never a guess from the type name")
    func catalogVendor() {
        #expect(NetworkScanViewModel.catalogVendor(serviceType: "_elg._tcp", txtRecords: ["mf": "Corsair"]) == "Corsair")
        #expect(NetworkScanViewModel.catalogVendor(serviceType: "_elg._tcp", txtRecords: ["mf": ""]) == nil)
        #expect(NetworkScanViewModel.catalogVendor(serviceType: "_airplay._tcp", txtRecords: ["manufacturer": "Denon"]) == "Denon")
        #expect(NetworkScanViewModel.catalogVendor(serviceType: "_hue._tcp", txtRecords: [:]) == nil)
        #expect(NetworkScanViewModel.catalogVendor(serviceType: "_sonos._tcp", txtRecords: [:]) == nil)
        #expect(NetworkScanViewModel.catalogVendor(serviceType: "_http._tcp", txtRecords: [:]) == nil)
    }

    @Test("Network MIDI does not make a Mac or an iPad audio")
    func midiIsNotAudio() {
        #expect(device(services: [service("_apple-midi._udp"), service("_smb._tcp")]).deviceType == .computer)
        #expect(device(manufacturer: "Apple", services: [service("_apple-midi._udp")]).deviceType != .audio)
        #expect(device(services: [service("_apple-midi._udp")]).deviceType != .audio)
    }

    @Test("an Apple AirPort model is audio like AudioAccessory")
    func airPortIsAudio() {
        let d = device(manufacturer: "Apple", services: [service("_airplay._tcp", "AirPort", ["model": "AirPort10,115"])])
        #expect(d.deviceType == .audio)
    }

    @Test("without _airplay the _raop ft bitmap decides audio versus TV")
    func raopFeatureFallback() {
        #expect(device(services: [service("_raop._tcp", "Amp", ["ft": sonosFeatures])]).deviceType == .audio)
        #expect(device(services: [service("_raop._tcp", "TV", ["ft": samsungFeatures])]).deviceType == .tv)
        #expect(device(services: [service("_raop._tcp", "Unknown")]).deviceType == .tv)
    }

    @Test("Whisperplay alone gives no TV chip")
    func whisperplayNotTV() {
        #expect(device(services: [service("_amzn-wplay._tcp")]).deviceType == .unknown)
    }

    @Test("new HomeKit categories map to their chips")
    func moreHAPCategories() {
        #expect(device(services: [service("_hap._tcp", "Gar", ["ci": "4"])]).deviceType == .smartHome)
        #expect(device(services: [service("_hap._tcp", "Rcv", ["ci": "34"])]).deviceType == .audio)
        #expect(device(services: [service("_hap._tcp", "Stick", ["ci": "36"])]).deviceType == .tv)
    }

    @Test("an OUI-only BSH row is Smart Home with the appliance maker tag")
    func applianceMakerOnly() {
        let d = device(manufacturer: "BSH Hausgeräte GmbH", services: [])
        #expect(d.deviceType == .smartHome)
        #expect(d.isApplianceMaker)
    }

    @Test("stronger evidence beats the appliance list and unlisted vendors stay unknown")
    func applianceMakerPrecedence() {
        let mac = device(manufacturer: "Whirlpool Corporation", services: [service("_smb._tcp")])
        #expect(mac.deviceType == .computer)
        let airplay = device(manufacturer: "Electrolux", services: [service("_airplay._tcp", "TV")])
        #expect(airplay.deviceType == .tv)
        let camera = device(manufacturer: "Hikvision", services: [service("_rtsp._tcp")])
        #expect(camera.deviceType == .camera)
        #expect(!camera.isApplianceMaker)
        #expect(device(manufacturer: "Acme Widgets", services: []).deviceType == .unknown)
        #expect(!device(manufacturer: "Genie Industries, Inc.", services: []).isApplianceMaker)
        #expect(!device(manufacturer: nil, services: []).isApplianceMaker)
    }

    @Test("an appliance vendor MAC never overrides the gateway or printer evidence")
    func applianceMakerBelowGatewayAndPrinter() {
        #expect(device(manufacturer: "GE Appliances", gateway: true, services: []).deviceType == .router)
        #expect(device(manufacturer: "GE Appliances", services: [service("_ipp._tcp")]).deviceType == .printer)
    }

    @Test("new appliance and printer Bonjour types map to their chips")
    func applianceTypes() {
        #expect(device(services: [service("_mieleathome._tcp")]).deviceType == .smartHome)
        #expect(device(services: [service("_homewizard._tcp")]).deviceType == .smartHome)
        #expect(device(services: [service("_octoprint._tcp")]).deviceType == .printer)
        #expect(device(services: [service("_prusalink._tcp")]).deviceType == .printer)
    }

    @Test("the HomeKit hub type alone never makes a smart home row")
    func homekitHubIsNotSmartHome() {
        let ipad = device(manufacturer: "Apple", services: [service("_homekit._tcp"), service("_rdlink._tcp")])
        #expect(ipad.deviceType == .apple)
        let tv = device(services: [service("_homekit._tcp"), service("_mediaremotetv._tcp")])
        #expect(tv.deviceType != .smartHome)
    }

    @Test("the sideplay type is smart home only for an ecobee model")
    func sideplayGated() {
        #expect(device(services: [service("_sideplay._tcp", "t", ["mdl": "eb-STATe5-01"])]).deviceType == .smartHome)
        #expect(device(services: [service("_sideplay._tcp", "t", ["mdl": "Ecobee3"])]).deviceType == .smartHome)
        #expect(device(services: [service("_sideplay._tcp", "t", ["mdl": "Other"])]).deviceType != .smartHome)
    }
}
