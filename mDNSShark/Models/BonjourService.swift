// mDNSShark/Models/BonjourService.swift
import Foundation

struct BonjourService: Identifiable, Equatable {
    let id: UUID
    let serviceType: String
    let serviceName: String
    let port: Int
    let txtRecords: [String: String]

    init(id: UUID = UUID(), serviceType: String, serviceName: String,
         port: Int, txtRecords: [String: String] = [:]) {
        self.id = id; self.serviceType = serviceType; self.serviceName = serviceName
        self.port = port; self.txtRecords = txtRecords
    }
}
