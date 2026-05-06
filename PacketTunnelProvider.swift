//
//  PacketTunnelProvider.swift
//  PacketTunnel (Network Extension Target)
//  
//  Created by user on 4/10/25.
//

import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {
    private var packetFrameCounter: UInt = 1
    private let sharedFileURL: URL = {
        let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.com.yourcompany.mDNSShark")!
        return container.appendingPathComponent("packets.log")
    }()
    
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        // Configure a virtual network interface.
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        networkSettings.ipv4Settings = NEIPv4Settings(addresses: ["192.168.1.100"], subnetMasks: ["255.255.255.0"])
        networkSettings.mtu = 1500 as NSNumber
        
        setTunnelNetworkSettings(networkSettings) { [weak self] error in
            if let error = error {
                completionHandler(error)
                return
            }
            // Begin capturing real packets.
            self?.startPacketCapture()
            completionHandler(nil)
        }
    }
    
    /// Continuously reads real packets from the packetFlow.
    private func startPacketCapture() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }
            for (index, packetData) in packets.enumerated() {
                let proto = protocols[index]
                let packet = self.processPacket(packetData, protocolNumber: proto)
                self.writePacketToSharedFile(packet)
            }
            // Continue capturing packets recursively.
            self.startPacketCapture()
        }
    }
    
    /// Converts raw packet data into a PacketModel.
    /// In production you should parse headers (IP, TCP/UDP, etc.) to get real source/destination.
    private func processPacket(_ data: Data, protocolNumber: NSNumber) -> PacketModel {
        let hexDump = data.map { String(format: "%02x", $0) }.joined(separator: " ")
        let packet = PacketModel(
            frameNumber: Int(packetFrameCounter),
            time: String(format: "%.6f", Date().timeIntervalSince1970),
            source: "0.0.0.0",         // TODO: Parse actual source IP from packet data
            destination: "0.0.0.0",    // TODO: Parse actual destination IP
            protocolName: protocolNumber.stringValue,
            length: data.count,
            info: "Real packet captured", // Enhance with parsed info as needed
            hexDump: hexDump
        )
        packetFrameCounter += 1
        return packet
    }
    
    /// Writes JSON‑encoded packet data (as one JSON object per line) to a shared file.
    private func writePacketToSharedFile(_ packet: PacketModel) {
        do {
            let encoder = JSONEncoder()
            let jsonData = try encoder.encode(packet)
            if let jsonString = String(data: jsonData, encoding: .utf8) {
                let line = jsonString + "\n"
                if FileManager.default.fileExists(atPath: sharedFileURL.path) {
                    let fileHandle = try FileHandle(forWritingTo: sharedFileURL)
                    fileHandle.seekToEndOfFile()
                    if let data = line.data(using: .utf8) {
                        fileHandle.write(data)
                    }
                    fileHandle.closeFile()
                } else {
                    try line.write(to: sharedFileURL, atomically: true, encoding: .utf8)
                }
            }
        } catch {
            NSLog("Error writing packet to shared file: \(error.localizedDescription)")
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        // Clean up any resources if necessary.
        completionHandler()
    }
}
