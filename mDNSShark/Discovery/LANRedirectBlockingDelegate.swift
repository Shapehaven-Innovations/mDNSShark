import Foundation

/// Blocks all HTTP redirects on a `URLSession` request. Shared by every
/// LAN-only fetcher (`SSDPDescriptionFetcher`, `JNAPHNAPProbe`,
/// `GoogleWifiStatusProbe`) so a validated LAN-local starting URL can never
/// be redirected off-LAN by the responding device.
final class LANRedirectBlockingDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}
