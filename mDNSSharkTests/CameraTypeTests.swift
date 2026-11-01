import Testing
@testable import mDNSShark

struct CameraTypeTests {
    private func device(manufacturer: String? = nil, services: [BonjourService] = []) -> DiscoveredDevice {
        var d = DiscoveredDevice(hostname: "x", ipAddress: "203.0.113.60", manufacturer: manufacturer, bonjourServices: services)
        d.isDefaultGateway = false
        return d
    }

    @Test("the field-test Amcrest, advertising only _http._tcp with an AMC instance name and an Amcrest MAC vendor, is a camera")
    func amcrestIsCamera() {
        let http = BonjourService(serviceType: "_http._tcp", serviceName: "AMC060E7AF0A5BCE81", port: 80)
        #expect(device(services: [http]).deviceType == .camera)
        #expect(device(manufacturer: "Amcrest Technologies", services: [BonjourService(serviceType: "_http._tcp", serviceName: "Cam", port: 80)]).deviceType == .camera)
    }

    @Test("a HomeKit IP camera or video doorbell is a camera, an alarm panel is not")
    func hapCategory() {
        func hap(_ ci: String) -> DiscoveredDevice {
            device(services: [BonjourService(serviceType: "_hap._tcp", serviceName: "Acc", port: 1, txtRecords: ["ci": ci])])
        }
        #expect(hap("17").deviceType == .camera)
        #expect(hap("18").deviceType == .camera)
        #expect(hap("11").deviceType == .unknown)
    }

    @Test("a camera service type or a Matter camera device type makes a camera")
    func serviceAndMatter() {
        #expect(device(services: [BonjourService(serviceType: "_axis-video._tcp", serviceName: "AXIS", port: 554)]).deviceType == .camera)
        #expect(device(services: [BonjourService(serviceType: "_matterc._udp", serviceName: "m", port: 5540, txtRecords: ["DT": "323"])]).deviceType == .camera)
    }

    @Test("a mixed-product vendor alone is not promoted to a camera")
    func mixedVendorsStayUnknown() {
        #expect(device(manufacturer: "TP-Link Technologies Co.,Ltd.").deviceType == .unknown)
        #expect(device(manufacturer: "Ubiquiti Inc").deviceType == .unknown)
    }

    @Test("an AirPlay Apple device is not turned into a camera, and the gateway stays a router")
    func existingTypesWin() {
        let air = BonjourService(serviceType: "_airplay._tcp", serviceName: "TV", port: 7000)
        #expect(device(manufacturer: "Apple", services: [air]).deviceType == .apple)
        var gw = device(manufacturer: "Hangzhou Hikvision Digital Technology Co.,Ltd.")
        gw.isDefaultGateway = true
        #expect(gw.deviceType == .router)
    }

    @Test("the camera type has its own label and icon")
    func labelAndIcon() {
        #expect(DeviceType.camera.label == "Camera")
        #expect(device(manufacturer: "Amcrest Technologies").deviceIcon == "video")
    }
}
