import Foundation

/// The literal fields of an RTSP reply to our single OPTIONS request. Pure parsing: tolerant of short, binary or oversized input and never throws.
public struct RTSPReply: Equatable {
    /// The first line exactly as received, for example `RTSP/1.0 401 Unauthorized`.
    public let statusLine: String
    public let statusCode: Int?
    public let server: String?
    public let publicMethods: String?
    /// Every `WWW-Authenticate` line, in order, as received.
    public let wwwAuthenticate: [String]

    /// Replies are read in one bounded chunk; anything past this many bytes is ignored.
    public static let maxParsedBytes = 8192

    /// The one request this app sends to an RTSP port. Nothing else is ever written.
    public static func optionsRequest(ip: String, port: Int = 554) -> Data {
        let host = ip.contains(":") ? "[\(ip)]" : ip
        return Data("OPTIONS rtsp://\(host):\(port)/ RTSP/1.0\r\nCSeq: 1\r\n\r\n".utf8)
    }

    public static func parse(_ data: Data) -> RTSPReply? {
        let head = data.prefix(maxParsedBytes)
        guard !head.isEmpty else { return nil }
        let text = String(data: head, encoding: .utf8) ?? String(data: head, encoding: .isoLatin1) ?? ""
        return parse(text)
    }

    public static func parse(_ text: String) -> RTSPReply? {
        var lines = text.prefix(maxParsedBytes)
            .split(omittingEmptySubsequences: false, whereSeparator: { $0 == "\r\n" || $0 == "\n" || $0 == "\r" })
            .map(String.init)
        guard let first = lines.first, first.hasPrefix("RTSP/") else { return nil }
        lines.removeFirst()
        let code = first.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true).dropFirst().first.flatMap { Int($0) }

        var server: String?, methods: String?
        var auth: [String] = []
        for line in lines {
            if line.isEmpty { break }
            guard let colon = line.firstIndex(of: ":") else { continue }
            let name = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            switch name {
            case "server": server = server ?? value
            case "public": methods = methods ?? value
            case "www-authenticate": auth.append(value)
            default: break
            }
        }
        return RTSPReply(statusLine: first, statusCode: code, server: server, publicMethods: methods, wwwAuthenticate: auth)
    }

    /// The reply as one banner string for `guessFromBanner`: the status line plus each field present, joined with ` | `.
    public var bannerText: String {
        var parts = [statusLine]
        if let server { parts.append("Server: \(server)") }
        if let publicMethods { parts.append("Public: \(publicMethods)") }
        parts += wwwAuthenticate.map { "WWW-Authenticate: \($0)" }
        return parts.joined(separator: " | ")
    }
}
