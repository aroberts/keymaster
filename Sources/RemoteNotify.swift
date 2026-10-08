import Foundation

// Pushover is only a doorbell: it carries the link to the approval page.
// Losing a notification costs a timeout, never an approval.
func sendPushover(config: RemoteConfig, title: String, message: String, url: URL, expiry: Date) -> Bool {
  guard let token = config.pushoverToken, let user = config.pushoverUser else { return false }
  var components = URLComponents()
  components.queryItems = [
    URLQueryItem(name: "token", value: token),
    URLQueryItem(name: "user", value: user),
    URLQueryItem(name: "title", value: String(title.prefix(250))),
    URLQueryItem(name: "message", value: String(message.prefix(1000))),
    URLQueryItem(name: "url", value: url.absoluteString),
    URLQueryItem(name: "url_title", value: "Review request"),
    // Pushover deletes the message from the phone once the request expires.
    URLQueryItem(name: "ttl", value: String(max(1, Int(expiry.timeIntervalSinceNow)))),
  ]
  if let priority = config.pushoverPriority, priority != 0 {
    components.queryItems?.append(URLQueryItem(name: "priority", value: String(priority)))
  }
  var request = URLRequest(url: URL(string: "https://api.pushover.net/1/messages.json")!, timeoutInterval: 15)
  request.httpMethod = "POST"
  request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
  // URLComponents leaves "+" alone, which a form body would read as a space.
  let body = components.percentEncodedQuery?.replacingOccurrences(of: "+", with: "%2B") ?? ""
  request.httpBody = Data(body.utf8)
  do {
    let (_, response) = try blockingRequest(request)
    guard response.statusCode == 200 else {
      printErr("Pushover answered HTTP \(response.statusCode)")
      return false
    }
    return true
  } catch {
    printErr("Pushover failed: \(error)")
    return false
  }
}
