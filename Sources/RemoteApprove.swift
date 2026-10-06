import CoreGraphics
import Foundation
import LocalAuthentication

// How a request that misses the cache gets approved.
// - local: TouchID only (the default).
// - remote: skip TouchID and ask the phone.
// - auto: ask the phone at once if the screen is locked or TouchID is
//   unavailable; otherwise show TouchID and ask the phone if nobody answers
//   it within KEYMASTER_LOCAL_TIMEOUT seconds.
enum ApprovalMode: String {
  case local, remote, auto
}

let defaultRemoteLifetime: TimeInterval = 300
let maxRemoteLifetime: TimeInterval = 900
let defaultLocalTimeout: TimeInterval = 20

func environmentSeconds(_ name: String, default fallback: TimeInterval, range: ClosedRange<TimeInterval>) -> TimeInterval {
  guard let text = ProcessInfo.processInfo.environment[name], let value = TimeInterval(text) else { return fallback }
  return min(max(value, range.lowerBound), range.upperBound)
}

// How long the phone has to answer. A longer wait widens nothing: the grant's
// TTL is fixed separately and shown on the phone.
func remoteLifetime() -> TimeInterval {
  environmentSeconds("KEYMASTER_REMOTE_TIMEOUT", default: defaultRemoteLifetime, range: 30...maxRemoteLifetime)
}

func localTimeout() -> TimeInterval {
  environmentSeconds("KEYMASTER_LOCAL_TIMEOUT", default: defaultLocalTimeout, range: 1...600)
}

// CGSSessionScreenIsLocked is only present while the screen is locked. A
// session that isn't on the console (fast user switching) can't see TouchID
// either.
func screenIsLocked() -> Bool {
  guard let session = CGSessionCopyCurrentDictionary() as? [String: Any] else { return false }
  if session["CGSSessionScreenIsLocked"] as? Bool == true { return true }
  if session[kCGSessionOnConsoleKey as String] as? Bool == false { return true }
  return false
}

struct RemoteSetup {
  let config: RemoteConfig?
  let credentials: [EnrolledCredential]
  let allowlist: [String]

  static func load() -> RemoteSetup {
    RemoteSetup(config: loadRemoteConfig(), credentials: loadCredentials(), allowlist: loadAllowlist())
  }

  // Why this request can't be approved remotely, or nil if it can.
  func ineligibility(for request: RequestContext) -> String? {
    if request.action != "get" {
      return "remote approval only releases reads (get), not \(request.action)"
    }
    if isReservedKey(request.key) {
      return "keymaster's own items can't be released remotely"
    }
    guard config != nil else {
      return "remote approval is not set up (keymaster remote setup)"
    }
    if credentials.isEmpty {
      return "no passkey is enrolled (keymaster remote enroll)"
    }
    if !allowlistCovers(allowlist, key: request.key, scope: request.scope) {
      if let scope = request.scope {
        return "scope \"\(scope)\" is not covered by a prefix on the remote allowlist (keymaster remote allow)"
      }
      return "\"\(request.key)\" is not on the remote allowlist (keymaster remote allow)"
    }
    return nil
  }
}

enum PhoneResult {
  case responded([String: Any])
  case denied
  case expired
  case failed(String)
}

// Post a request to the relay, ring the phone and wait for its answer. The
// answer is unverified; the caller checks it against `remote`.
func askPhone(_ remote: RemoteRequest, config: RemoteConfig, title: String, message: String) -> PhoneResult {
  guard let baseURL = config.url else { return .failed("relay URL \(config.relayURL) is invalid") }
  let relay = RelayClient(baseURL: baseURL, token: config.relayToken)
  do {
    try relay.create(remote)
  } catch {
    return .failed("\(error)")
  }
  let page = relay.pageURL(for: remote)
  let until = DateFormatter.localizedString(from: remote.expiry, dateStyle: .none, timeStyle: .medium)
  printErr("Waiting for approval on your phone until \(until) (request code \(remote.code))")
  printErr("  \(page.absoluteString)")
  if config.pushoverConfigured {
    if sendPushover(config: config, title: title, message: message, url: page, expiry: remote.expiry) {
      debug("Pushover notification sent")
    }
  } else {
    debug("Pushover not configured; open the link yourself")
  }
  switch relay.waitForResult(remote) {
  case .responded(let response): return .responded(response)
  case .denied: return .denied
  case .expired, .pending: return .expired
  }
}

// The notification names what is being approved and who asked, so the
// approval page is not the only place to spot a surprising request.
func notificationText(for request: RequestContext) -> (title: String, message: String) {
  let title = "keymaster: \(request.verb) \(sanitizeForPrompt(request.key))"
  var message = "On \(localHostName())"
  if let scope = request.scope {
    message += ". Also allows keys starting with \"\(sanitizeForPrompt(scope))\" for \(Int(request.ttl))s"
  }
  message += ". Requested by \(summarizeChain(request.chain))"
  if let why = request.reason {
    message += ". Reason given: \"\(sanitizeForPrompt(why, maxLength: 120))\""
  }
  return (title, message)
}

// Ask the phone, verify its assertion locally, and finish the request the
// same way a TouchID approval does. Never returns.
func approveRemotelyAndExit(_ request: RequestContext, setup: RemoteSetup, secret: String) -> Never {
  guard let config = setup.config else {
    printErr("Remote approval is not set up")
    exit(EXIT_FAILURE)
  }
  let remote = makeApprovalRequest(for: request, lifetime: remoteLifetime())
  debug("Remote request \(remote.id): \(String(decoding: remote.bytes, as: UTF8.self))")
  let text = notificationText(for: request)
  switch askPhone(remote, config: config, title: text.title, message: text.message) {
  case .responded(let response):
    do {
      let credential = try verifyAssertion(response, for: remote, credentials: setup.credentials)
      debug("Assertion verified with \(credential.label) (\(credential.id))")
      auditLog(request, outcome: "approved", extra: ["approval": "remote", "credential": credential.label])
      if request.action == "get" {
        updateSession(for: request.key, sessionName: request.sessionName, scope: request.scope)
      }
      performAction(action: request.action, key: request.key, secret: secret)
      exit(EXIT_SUCCESS)
    } catch {
      auditLog(request, outcome: "denied", error: "assertion rejected: \(error)", extra: ["approval": "remote"])
      printErr("Remote approval rejected: \(error)")
    }
  case .denied:
    auditLog(request, outcome: "denied", error: "denied on phone", extra: ["approval": "remote"])
    printErr("Denied on phone")
  case .expired:
    auditLog(request, outcome: "denied", error: "remote request expired", extra: ["approval": "remote"])
    printErr("Remote request expired without an answer")
  case .failed(let message):
    auditLog(request, outcome: "denied", error: "remote approval failed: \(message)", extra: ["approval": "remote"])
    printErr("Remote approval failed: \(message)")
  }
  exit(EXIT_FAILURE)
}

// TouchID errors that mean nobody could answer, as opposed to someone saying
// no. In auto mode these fall back to the phone; a cancel or a failed match
// never does.
func touchIDUnanswerable(_ error: Error?) -> Bool {
  guard let code = (error as? LAError)?.code else { return false }
  switch code {
  case .appCancel, .systemCancel, .notInteractive, .biometryNotAvailable, .biometryLockout, .biometryNotEnrolled:
    return true
  default:
    return false
  }
}
