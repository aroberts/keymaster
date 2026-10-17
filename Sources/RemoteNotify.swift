import Foundation

// Pushover and ntfy are only doorbells: they carry the link to the approval
// page. Losing a notification costs a timeout, never an approval.
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
  return sendNotification(request, service: "Pushover")
}

// The message's sequence ID is the request ID, so ntfyDeleteRequest can find
// it again. Sent as JSON because a title can hold characters that an HTTP
// header can't.
func ntfyPublishRequest(config: RemoteConfig, requestId: String, title: String, message: String, url: URL) -> URLRequest? {
  guard let server = config.ntfyServer, let topic = config.ntfyTopic,
        let endpoint = URL(string: "\(server)/") else { return nil }
  var body: [String: Any] = [
    "topic": topic,
    "sequence_id": requestId,
    "title": String(title.prefix(250)),
    "message": String(message.prefix(1000)),
    "click": url.absoluteString,
    "actions": [["action": "view", "label": "Review request", "url": url.absoluteString, "clear": true]],
  ]
  if let priority = config.ntfyPriority, priority != 3 {
    body["priority"] = priority
  }
  guard let data = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]) else { return nil }
  var request = URLRequest(url: endpoint, timeoutInterval: 15)
  request.httpMethod = "POST"
  request.setValue("application/json", forHTTPHeaderField: "Content-Type")
  if let token = config.ntfyToken {
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
  }
  request.httpBody = data
  return request
}

// ntfy has no per-message TTL, so the message is deleted once the request
// is denied or expires. The iOS app ignores deletes (ntfy issue #1945).
// The caller waits on this, so it gets a short timeout.
func ntfyDeleteRequest(config: RemoteConfig, requestId: String) -> URLRequest? {
  guard let server = config.ntfyServer, let topic = config.ntfyTopic,
        let endpoint = URL(string: "\(server)/\(topic)/\(requestId)") else { return nil }
  var request = URLRequest(url: endpoint, timeoutInterval: 5)
  request.httpMethod = "DELETE"
  if let token = config.ntfyToken {
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
  }
  return request
}

func sendNtfy(config: RemoteConfig, requestId: String, title: String, message: String, url: URL) -> Bool {
  guard let request = ntfyPublishRequest(config: config, requestId: requestId, title: title, message: message, url: url) else {
    return false
  }
  return sendNotification(request, service: "ntfy")
}

func deleteNtfy(config: RemoteConfig, requestId: String) {
  guard let request = ntfyDeleteRequest(config: config, requestId: requestId) else { return }
  if sendNotification(request, service: "ntfy delete") {
    debug("ntfy notification deleted")
  }
}

private func sendNotification(_ request: URLRequest, service: String) -> Bool {
  do {
    let (_, response) = try blockingRequest(request)
    guard response.statusCode == 200 else {
      printErr("\(service) answered HTTP \(response.statusCode)")
      return false
    }
    return true
  } catch {
    printErr("\(service) failed: \(error)")
    return false
  }
}
