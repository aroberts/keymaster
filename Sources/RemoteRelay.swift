import Foundation

// A blocking client for the relay's API. keymaster is a one-shot CLI with
// nothing else to do while it waits, so each call waits on a semaphore.
struct RelayClient {
  let baseURL: URL
  let token: String

  enum Result {
    case pending
    case responded([String: Any])
    case denied
    case expired
  }

  struct RelayError: Error, CustomStringConvertible {
    let description: String
  }

  func pageURL(for request: RemoteRequest) -> URL {
    baseURL.appendingPathComponent("r").appendingPathComponent(request.id)
  }

  func create(_ request: RemoteRequest) throws {
    let body = try JSONSerialization.data(withJSONObject: ["request": request.bytes.base64URL])
    let (status, json) = try send("POST", path: "api/requests", body: body, timeout: 15)
    guard status == 201 else {
      throw RelayError(description: "relay refused the request (HTTP \(status)): \(json["error"] ?? "no detail")")
    }
  }

  // One long-poll. The relay holds the call for up to 25 seconds.
  func result(for request: RemoteRequest) throws -> Result {
    let (status, json) = try send("GET", path: "api/requests/\(request.id)/result", body: nil, timeout: 40)
    switch status {
    case 404:
      return .expired
    case 200:
      break
    default:
      throw RelayError(description: "relay answered HTTP \(status): \(json["error"] ?? "no detail")")
    }
    switch json["status"] as? String {
    case "pending":
      return .pending
    case "denied":
      return .denied
    case "responded":
      guard let response = json["response"] as? [String: Any] else {
        throw RelayError(description: "relay result has no response")
      }
      return .responded(response)
    default:
      throw RelayError(description: "relay result has an unknown status")
    }
  }

  // Poll until the phone answers or the request expires. Network errors are
  // retried until expiry, since a phone approval can outlast a blip.
  func waitForResult(_ request: RemoteRequest) -> Result {
    while Date() < request.expiry {
      do {
        let result = try result(for: request)
        if case .pending = result { continue }
        return result
      } catch {
        debug("Relay poll failed: \(error)")
        Thread.sleep(forTimeInterval: 2)
      }
    }
    return .expired
  }

  private func send(_ method: String, path: String, body: Data?, timeout: TimeInterval) throws -> (Int, [String: Any]) {
    var request = URLRequest(url: baseURL.appendingPathComponent(path), timeoutInterval: timeout)
    request.httpMethod = method
    request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
    if let body = body {
      request.httpBody = body
      request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    }
    let (data, response) = try blockingRequest(request)
    let json = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
    return (response.statusCode, json)
  }
}

struct HTTPError: Error, CustomStringConvertible {
  let description: String
}

// URLSession with an ephemeral configuration, so nothing about the request
// lands in a shared cache or cookie store.
let httpSession = URLSession(configuration: .ephemeral)

func blockingRequest(_ request: URLRequest) throws -> (Data, HTTPURLResponse) {
  let semaphore = DispatchSemaphore(value: 0)
  var outcome: Swift.Result<(Data, HTTPURLResponse), Error> = .failure(HTTPError(description: "no response"))
  let task = httpSession.dataTask(with: request) { data, response, error in
    if let error = error {
      outcome = .failure(error)
    } else if let http = response as? HTTPURLResponse {
      outcome = .success((data ?? Data(), http))
    }
    semaphore.signal()
  }
  task.resume()
  semaphore.wait()
  return try outcome.get()
}
