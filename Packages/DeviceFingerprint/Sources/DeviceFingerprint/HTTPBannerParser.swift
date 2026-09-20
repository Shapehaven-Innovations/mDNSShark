import Foundation

public struct HTTPBannerInfo {
    public let server: String?
    public let title: String?
    public let authRealm: String?

    public init(server: String?, title: String?, authRealm: String?) {
        self.server = server
        self.title = title
        self.authRealm = authRealm
    }
}

/// Parses raw bytes read off an HTTP(S) TCP connection into whatever
/// identifying scraps can be pulled out: the `Server:` header, the HTML
/// `<title>`, and the `realm=` portion of a `WWW-Authenticate:` header
/// (router/IoT admin-UI login prompts frequently put the vendor/model there).
///
/// Input is untrusted bytes straight off the LAN — a device can send
/// anything, truncated mid-header, non-UTF8, or not HTTP at all. Every code
/// path here must degrade to nil fields rather than crash, same discipline
/// as `SSDPDeviceDescription.parse` and `guessFromBanner`.
public enum HTTPBannerParser {
    public static func parse(_ response: Data) -> HTTPBannerInfo? {
        guard !response.isEmpty else {
            return HTTPBannerInfo(server: nil, title: nil, authRealm: nil)
        }

        // Decode leniently: a truncated read can split a multi-byte UTF-8
        // sequence, so fall back to Latin-1 (which never fails to decode)
        // rather than giving up on the whole response.
        guard let text = String(data: response, encoding: .utf8)
            ?? String(data: response, encoding: .isoLatin1) else {
            return HTTPBannerInfo(server: nil, title: nil, authRealm: nil)
        }

        // Split header block from body on the first blank line. HTTP uses
        // CRLF, but be tolerant of bare LF too. If there's no blank-line
        // separator at all, treat the whole thing as headers-less body text
        // (still worth scanning for a <title>).
        let headerBlock: String
        let body: String
        if let range = text.range(of: "\r\n\r\n") {
            headerBlock = String(text[text.startIndex..<range.lowerBound])
            body = String(text[range.upperBound...])
        } else if let range = text.range(of: "\n\n") {
            headerBlock = String(text[text.startIndex..<range.lowerBound])
            body = String(text[range.upperBound...])
        } else {
            headerBlock = ""
            body = text
        }

        let headers = parseHeaders(headerBlock)
        let server = headers["server"]
        let authRealm = headers["www-authenticate"].flatMap(extractRealm)
        let title = extractTitle(body)

        return HTTPBannerInfo(server: server, title: title, authRealm: authRealm)
    }

    /// Splits a header block into a lowercase-keyed name->value map. Skips
    /// the request/status line (no ":" or it's the first line and doesn't
    /// look like "name: value"), and any line that isn't well-formed.
    private static func parseHeaders(_ block: String) -> [String: String] {
        var result: [String: String] = [:]
        let lines = block.split(whereSeparator: { $0 == "\r\n" || $0 == "\n" })
        for rawLine in lines {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard let colonIndex = line.firstIndex(of: ":") else { continue }
            let name = line[line.startIndex..<colonIndex]
                .trimmingCharacters(in: .whitespaces)
                .lowercased()
            guard !name.isEmpty else { continue }
            // A status line ("HTTP/1.1 401 Unauthorized") has no colon, so
            // it's already skipped by the guard above; nothing further to
            // exclude here.
            let value = line[line.index(after: colonIndex)...]
                .trimmingCharacters(in: .whitespaces)
            guard !value.isEmpty else { continue }
            // First-wins: don't let a duplicate/continuation header clobber
            // the first value seen.
            if result[name] == nil {
                result[name] = value
            }
        }
        return result
    }

    /// Pulls the `realm="..."` (or unquoted `realm=...`) portion out of a
    /// `WWW-Authenticate` header value, e.g.
    /// `Basic realm="NETGEAR R7000"` -> "NETGEAR R7000".
    private static func extractRealm(_ headerValue: String) -> String? {
        guard let range = headerValue.range(of: "realm=", options: .caseInsensitive) else {
            return nil
        }
        var rest = headerValue[range.upperBound...]
        if rest.first == "\"" {
            rest = rest.dropFirst()
            guard let endQuote = rest.firstIndex(of: "\"") else {
                // Unterminated quote: take whatever remains rather than nil.
                let value = rest.trimmingCharacters(in: .whitespaces)
                return value.isEmpty ? nil : value
            }
            let value = String(rest[rest.startIndex..<endQuote])
            return value.isEmpty ? nil : value
        } else {
            // Unquoted realm; ends at the next comma or end of string.
            let end = rest.firstIndex(of: ",") ?? rest.endIndex
            let value = rest[rest.startIndex..<end].trimmingCharacters(in: .whitespaces)
            return value.isEmpty ? nil : value
        }
    }

    /// Pulls the content of an HTML `<title>` element, case-insensitively,
    /// tolerant of attributes on the tag and surrounding whitespace/newlines.
    /// Searches directly on the original string (rather than a separately
    /// lowercased copy) so indices never need translating between two
    /// strings that could in principle differ in length after case folding.
    private static func extractTitle(_ body: String) -> String? {
        guard let openRange = body.range(of: "<title", options: .caseInsensitive) else {
            return nil
        }
        guard let openEnd = body.range(of: ">", range: openRange.upperBound..<body.endIndex) else {
            return nil
        }
        guard let closeRange = body.range(of: "</title>", options: .caseInsensitive, range: openEnd.upperBound..<body.endIndex) else {
            return nil
        }
        let content = body[openEnd.upperBound..<closeRange.lowerBound]
        let trimmed = content.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}
