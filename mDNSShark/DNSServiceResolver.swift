//DNSServiceResolver.swift

import Foundation
import os

public typealias DNSResolveCompletion = (String?, UInt16?) -> Void

private let dnsLogger = Logger(subsystem: "com.mDNSShark", category: "DNSServiceResolver")

public typealias MyDNSServiceResolveReply = @convention(c) (
    DNSServiceRef?,
    DNSServiceFlags,
    UInt32,
    DNSServiceErrorType,
    UnsafePointer<CChar>?,
    UnsafePointer<CChar>?,
    UInt16,
    UInt16,
    UnsafePointer<UInt8>?,
    UnsafeMutableRawPointer?
) -> Void

private class DNSResolveContext {
    let completion: DNSResolveCompletion
    var hasCompleted = false
    let lock = NSLock()
    
    init(_ completion: @escaping DNSResolveCompletion) {
        self.completion = completion
    }
}

private let dnsServiceResolveCallback: MyDNSServiceResolveReply = {
    sdRef, flags, interfaceIndex, errorCode, fullname, hosttarget, port, txtLen, txtRecord, context in
    
    guard let context = context else { return }
    let dnsContext = Unmanaged<DNSResolveContext>.fromOpaque(context).takeUnretainedValue()
    
    dnsContext.lock.lock()
    if dnsContext.hasCompleted {
        dnsContext.lock.unlock()
        return
    }
    dnsContext.hasCompleted = true
    dnsContext.lock.unlock()
    
    if errorCode == kDNSServiceErr_NoError, let hosttarget = hosttarget {
        let portValue = UInt16(port.bigEndian)
        let host = String(cString: hosttarget)
        dnsContext.completion(host, portValue)
    } else {
        dnsLogger.error("DNSServiceResolve callback error: \(errorCode, privacy: .public)")
        dnsContext.completion(nil, nil)
    }
    Unmanaged<DNSResolveContext>.fromOpaque(context).release()
}

private func callDNSServiceResolve(serviceRef: inout DNSServiceRef?,
                                   namePtr: UnsafePointer<CChar>,
                                   typePtr: UnsafePointer<CChar>,
                                   domainPtr: UnsafePointer<CChar>,
                                   context: UnsafeMutableRawPointer?) -> DNSServiceErrorType {
    typealias ResolveFunc = @convention(c) (
        UnsafeMutablePointer<DNSServiceRef?>?,
        UInt32,
        UInt32,
        UnsafePointer<CChar>?,
        UnsafePointer<CChar>?,
        UnsafePointer<CChar>?,
        MyDNSServiceResolveReply?,
        UnsafeMutableRawPointer?
    ) -> DNSServiceErrorType

    let functionPtr: ResolveFunc = DNSServiceResolve
    let tmpFlags: UInt32 = 0
    let tmpInterfaceIndex: UInt32 = 0

    let ptr = UnsafeMutablePointer<DNSServiceRef?>.allocate(capacity: 1)
    ptr.initialize(to: serviceRef)

    let error: DNSServiceErrorType = functionPtr(ptr,
                                                 tmpFlags,
                                                 tmpInterfaceIndex,
                                                 namePtr,
                                                 typePtr,
                                                 domainPtr,
                                                 dnsServiceResolveCallback,
                                                 context)
    serviceRef = ptr.pointee
    ptr.deinitialize(count: 1)
    ptr.deallocate()

    return error
}

public class DNSServiceResolver {
    public static func resolve(name: String, type: String, domain: String, completion: @escaping DNSResolveCompletion) {
        var serviceRef: DNSServiceRef?
        let context = Unmanaged.passRetained(DNSResolveContext(completion)).toOpaque()

        let result: DNSServiceErrorType = name.withCString { namePtr in
            return type.withCString { typePtr in
                return domain.withCString { domainPtr in
                    return callDNSServiceResolve(serviceRef: &serviceRef,
                                                 namePtr: namePtr,
                                                 typePtr: typePtr,
                                                 domainPtr: domainPtr,
                                                 context: context)
                }
            }
        }

        if result != kDNSServiceErr_NoError {
            dnsLogger.error("DNSServiceResolve error: \(result, privacy: .public) for service \(name, privacy: .public)")
            Unmanaged<DNSResolveContext>.fromOpaque(context).release()
            completion(nil, nil)
            return
        }

        if let serviceRef = serviceRef {
            let fd = DNSServiceRefSockFD(serviceRef)
            if fd != -1 {
                let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: DispatchQueue.global())
                source.setEventHandler {
                    let processResult = DNSServiceProcessResult(serviceRef)
                    if processResult != kDNSServiceErr_NoError {
                        dnsLogger.error("DNSServiceProcessResult error: \(processResult, privacy: .public) for service \(name, privacy: .public)")
                    }
                }
                source.resume()
            } else {
                dnsLogger.error("Failed to get valid file descriptor for DNSServiceRef for service \(name, privacy: .public)")
                completion(nil, nil)
            }
        } else {
            dnsLogger.error("DNSServiceResolve did not return a valid DNSServiceRef for service \(name, privacy: .public)")
            completion(nil, nil)
        }
    }
}

