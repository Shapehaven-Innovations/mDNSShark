/// Coarse OS-family guess from a received IP packet's TTL, based on common
/// OS default initial TTLs (64 Linux/macOS/iOS/most embedded & IoT, 128
/// Windows, 255 some Cisco/Solaris gear) minus however many hops the packet
/// crossed. This is the WEAKEST signal in the pipeline — Linux, macOS, iOS,
/// UniFi firmware, and most IoT devices are indistinguishable by TTL alone.
/// Never let this override a real answer; see DeviceEnrichment.merge.
public func guessOSFamily(ttl: UInt8) -> String? {
    switch ttl {
    case 50...64: return "Linux/Unix-like (likely)"
    case 100...128: return "Windows (likely)"
    case 240...255: return "Cisco/Solaris (likely)"
    default: return nil
    }
}
