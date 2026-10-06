import Foundation
import LocalAuthentication

// keymaster remote …: set up, enroll and manage remote approval. Every command
// that changes what a remote approval can do needs local TouchID, and none of
// them can be approved remotely.

func remoteUsage() {
  printErr("""
  keymaster remote setup --relay <https-url>   relay URL, relay token and Pushover keys (TouchID)
  keymaster remote enroll [--label <name>]     create a passkey on your phone (TouchID)
  keymaster remote list                        show the relay, passkeys and allowlist
  keymaster remote revoke <credential-id|label>  remove a passkey (TouchID)
  keymaster remote allow <key|prefix*>         let a key or key prefix be approved remotely (TouchID)
  keymaster remote disallow <key|prefix*>      remove an allowlist entry (TouchID)
  keymaster remote test                        round trip to the phone; releases nothing
  """)
}

func runRemoteCommand(_ args: [String]) -> Never {
  guard let command = args.first else {
    remoteUsage()
    exit(EXIT_FAILURE)
  }
  let rest = Array(args.dropFirst())
  switch command {
  case "setup": remoteSetup(rest)
  case "enroll": remoteEnroll(rest)
  case "list": remoteList()
  case "revoke": remoteRevoke(rest)
  case "allow": remoteAllow(rest, add: true)
  case "disallow": remoteAllow(rest, add: false)
  case "test": remoteTest()
  case "help", "-h", "--help":
    remoteUsage()
    exit(EXIT_SUCCESS)
  default:
    printErr("Unknown remote command \"\(command)\"")
    remoteUsage()
    exit(EXIT_FAILURE)
  }
  exit(EXIT_SUCCESS)
}

// Value of `--name <value>` in args, removing both.
func takeOption(_ name: String, from args: inout [String]) -> String? {
  guard let idx = args.firstIndex(of: name) else { return nil }
  guard idx + 1 < args.count else {
    printErr("Missing value for \(name)")
    exit(EXIT_FAILURE)
  }
  let value = args[idx + 1]
  args.removeSubrange(idx...idx + 1)
  return value
}

// A RequestContext for the audit log and the phone page, describing a remote
// admin command rather than a key access.
func adminRequest(_ action: String, key: String) -> RequestContext {
  RequestContext(
    action: action,
    key: key,
    sessionName: nil,
    scope: nil,
    reason: nil,
    ttl: 0,
    chain: processChain(),
    workingDirectory: FileManager.default.currentDirectoryPath
  )
}

// Block until local TouchID succeeds, or exit.
func requireLocalTouchID(_ request: RequestContext, reason: String) {
  let context = LAContext()
  var error: NSError?
  guard context.canEvaluatePolicy(policy, error: &error) else {
    printErr("This command needs TouchID, which is unavailable: \(error?.localizedDescription ?? "unknown")")
    exit(EXIT_FAILURE)
  }
  let semaphore = DispatchSemaphore(value: 0)
  var approved = false
  var message = "Unknown error"
  let prompt = "\(reason). Requested by \(summarizeChain(request.chain))"
  context.evaluatePolicy(policy, localizedReason: prompt) { success, error in
    approved = success
    if let error = error { message = error.localizedDescription }
    semaphore.signal()
  }
  semaphore.wait()
  guard approved else {
    auditLog(request, outcome: "denied", error: message, extra: ["approval": "touchid"])
    printErr("Authentication failed or was canceled: \(message)")
    exit(EXIT_FAILURE)
  }
  auditLog(request, outcome: "approved", extra: ["approval": "touchid"])
}

// Read a secret from the terminal without echo, or a line from stdin when
// there is no terminal. An empty answer returns nil.
func readSecret(_ prompt: String) -> String? {
  var buffer = [CChar](repeating: 0, count: 1024)
  let value: String?
  if isatty(STDIN_FILENO) != 0 {
    value = readpassphrase(prompt, &buffer, buffer.count, RPP_REQUIRE_TTY).map { String(cString: $0) }
  } else {
    value = readLine()
  }
  guard let text = value?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty else { return nil }
  return text
}

// The relay must be HTTPS, since WebAuthn only runs in a secure context.
// Plain HTTP is accepted for localhost, which browsers also treat as secure.
func validRelayURL(_ text: String) -> URL? {
  guard let url = URL(string: text), let host = url.host, let scheme = url.scheme?.lowercased() else { return nil }
  guard url.query == nil, url.fragment == nil else { return nil }
  if scheme == "https" { return url }
  if scheme == "http" && (host == "localhost" || host == "127.0.0.1") { return url }
  return nil
}

func remoteSetup(_ args: [String]) {
  var args = args
  let existing = loadRemoteConfig()
  let relayText = takeOption("--relay", from: &args) ?? existing?.relayURL
  guard args.isEmpty, let relayText = relayText else {
    printErr("Usage: keymaster remote setup --relay <https-url>")
    exit(EXIT_FAILURE)
  }
  guard let relayURL = validRelayURL(relayText) else {
    printErr("Relay URL must be https:// (or http://localhost for testing), without a query: \(relayText)")
    exit(EXIT_FAILURE)
  }
  let trimmedURL = relayURL.absoluteString.hasSuffix("/") ? String(relayURL.absoluteString.dropLast()) : relayURL.absoluteString
  let request = adminRequest("remote-setup", key: trimmedURL)
  requireLocalTouchID(request, reason: "Change keymaster remote approval settings: relay \(sanitizeForPrompt(trimmedURL))")

  let keep = existing == nil ? "" : " (empty keeps the current value)"
  guard let token = readSecret("Relay token\(keep): ") ?? existing?.relayToken else {
    printErr("A relay token is required")
    exit(EXIT_FAILURE)
  }
  let pushoverUser = readSecret("Pushover user key\(existing == nil ? " (empty skips Pushover)" : keep): ") ?? existing?.pushoverUser
  let pushoverToken = pushoverUser == nil ? nil : (readSecret("Pushover app token\(keep): ") ?? existing?.pushoverToken)
  let config = RemoteConfig(relayURL: trimmedURL, relayToken: token, pushoverToken: pushoverToken, pushoverUser: pushoverUser)
  guard storeJSONItem(config, key: remoteConfigItem) else {
    printErr("Could not store the remote approval settings")
    exit(EXIT_FAILURE)
  }
  printErr("Saved. Relay \(trimmedURL), Pushover \(config.pushoverConfigured ? "on" : "off").")
  let stale = loadCredentials().filter { $0.origin != config.origin }
  if !stale.isEmpty {
    printErr("Warning: \(stale.count) enrolled passkey(s) belong to another origin and won't work with this relay:")
    for credential in stale { printErr("  \(credential.label) (\(credential.origin))") }
  }
}

func remoteEnroll(_ args: [String]) {
  var args = args
  let label = takeOption("--label", from: &args) ?? "keymaster on \(localHostName())"
  guard args.isEmpty else {
    printErr("Usage: keymaster remote enroll [--label <name>]")
    exit(EXIT_FAILURE)
  }
  guard let config = loadRemoteConfig(), let rpId = config.rpId, let origin = config.origin else {
    printErr("Run keymaster remote setup first")
    exit(EXIT_FAILURE)
  }
  let request = adminRequest("remote-enroll", key: label)
  requireLocalTouchID(request, reason: "Enroll a passkey for keymaster remote approval as \"\(sanitizeForPrompt(label))\"")

  let remote = makeEnrollRequest(label: label, lifetime: remoteLifetime())
  if let base = config.url {
    printQRCode(RelayClient(baseURL: base, token: config.relayToken).pageURL(for: remote).absoluteString)
  }
  let result = askPhone(
    remote,
    config: config,
    title: "keymaster: enroll a passkey",
    message: "Create a passkey for keymaster on \(localHostName()) as \"\(label)\""
  )
  guard case .responded(let response) = result else {
    printErr("Enrollment did not finish: \(result)")
    exit(EXIT_FAILURE)
  }
  let credential: EnrolledCredential
  do {
    credential = try verifyEnrollment(response, for: remote, rpId: rpId, origin: origin, label: label)
  } catch {
    printErr("Enrollment rejected: \(error)")
    exit(EXIT_FAILURE)
  }
  var credentials = loadCredentials()
  credentials.append(credential)
  guard storeJSONItem(credentials, key: remoteCredentialsItem) else {
    printErr("Could not store the new passkey")
    exit(EXIT_FAILURE)
  }
  auditLog(request, outcome: "enrolled", extra: ["credential": credential.label, "credentialId": credential.id])
  printErr("Enrolled \"\(label)\".")
  printErr("  Credential ID:   \(credential.id)")
  printErr("  Key fingerprint: \(credential.fingerprint)")
  printErr("Check that the phone shows the same fingerprint.")
}

func remoteList() {
  let config = loadRemoteConfig()
  print("Relay:    \(config?.relayURL ?? "not set up")")
  if let config = config {
    print("Pushover: \(config.pushoverConfigured ? "on" : "off")")
  }
  let credentials = loadCredentials()
  print("\nPasskeys (\(credentials.count)):")
  let formatter = ISO8601DateFormatter()
  for credential in credentials {
    let created = formatter.string(from: Date(timeIntervalSince1970: TimeInterval(credential.created)))
    print("  \(credential.label)")
    print("    id \(credential.id)")
    print("    fingerprint \(credential.fingerprint), \(credential.origin), enrolled \(created)")
  }
  let allowlist = loadAllowlist()
  print("\nRemote allowlist (\(allowlist.count)):")
  for entry in allowlist.sorted() { print("  \(entry)") }
}

func remoteRevoke(_ args: [String]) {
  guard args.count == 1, let target = args.first else {
    printErr("Usage: keymaster remote revoke <credential-id|label>")
    exit(EXIT_FAILURE)
  }
  var credentials = loadCredentials()
  let matches = credentials.filter { $0.id == target || $0.label == target }
  guard matches.count == 1, let credential = matches.first else {
    printErr(matches.isEmpty ? "No passkey matches \"\(target)\"" : "\"\(target)\" matches more than one passkey; use its id")
    exit(EXIT_FAILURE)
  }
  let request = adminRequest("remote-revoke", key: credential.label)
  requireLocalTouchID(request, reason: "Revoke keymaster remote-approval passkey \"\(sanitizeForPrompt(credential.label))\"")
  credentials.removeAll { $0 == credential }
  guard storeJSONItem(credentials, key: remoteCredentialsItem) else {
    printErr("Could not store the passkey list")
    exit(EXIT_FAILURE)
  }
  printErr("Revoked \"\(credential.label)\". Delete the passkey on the phone too (Settings > Passwords).")
}

func remoteAllow(_ args: [String], add: Bool) {
  let verb = add ? "allow" : "disallow"
  guard args.count == 1, let entry = args.first, !entry.isEmpty else {
    printErr("Usage: keymaster remote \(verb) <key|prefix*>")
    exit(EXIT_FAILURE)
  }
  var allowlist = loadAllowlist()
  if add {
    if entry.hasSuffix("*") {
      let prefix = String(entry.dropLast())
      guard !prefix.isEmpty, !prefix.contains("*") else {
        printErr("A prefix entry needs at least one character before the trailing *")
        exit(EXIT_FAILURE)
      }
      guard !prefixCoversReserved(prefix) else {
        printErr("\"\(entry)\" would cover keymaster's own items")
        exit(EXIT_FAILURE)
      }
    } else if isReservedKey(entry) {
      printErr("\"\(entry)\" is one of keymaster's own items")
      exit(EXIT_FAILURE)
    }
    guard !allowlist.contains(entry) else {
      printErr("\"\(entry)\" is already on the allowlist")
      exit(EXIT_SUCCESS)
    }
  } else {
    guard allowlist.contains(entry) else {
      printErr("\"\(entry)\" is not on the allowlist")
      exit(EXIT_FAILURE)
    }
  }
  let what = entry.hasSuffix("*") ? "keys starting with \"\(sanitizeForPrompt(String(entry.dropLast())))\"" : "\"\(sanitizeForPrompt(entry))\""
  let request = adminRequest("remote-\(verb)", key: entry)
  let reason = add ? "Allow phone approval for \(what)" : "Stop allowing phone approval for \(what)"
  requireLocalTouchID(request, reason: reason)
  if add { allowlist.append(entry) } else { allowlist.removeAll { $0 == entry } }
  guard storeJSONItem(allowlist, key: remoteAllowlistItem) else {
    printErr("Could not store the allowlist")
    exit(EXIT_FAILURE)
  }
  printErr(add ? "Allowed \(what)." : "Removed \(what).")
}

// A full round trip that proves the relay, the notification, the passkey and
// verification all work. The request's action is "test", which releases
// nothing, so it needs no TouchID and no allowlist entry.
func remoteTest() {
  let setup = RemoteSetup.load()
  guard let config = setup.config else {
    printErr("Run keymaster remote setup first")
    exit(EXIT_FAILURE)
  }
  guard !setup.credentials.isEmpty else {
    printErr("Enroll a passkey first (keymaster remote enroll)")
    exit(EXIT_FAILURE)
  }
  let request = adminRequest("test", key: "remote approval test")
  let remote = makeApprovalRequest(for: request, lifetime: remoteLifetime())
  let result = askPhone(
    remote,
    config: config,
    title: "keymaster: test approval",
    message: "A test from \(localHostName()). Approving releases nothing."
  )
  switch result {
  case .responded(let response):
    do {
      let credential = try verifyAssertion(response, for: remote, credentials: setup.credentials)
      auditLog(request, outcome: "approved", extra: ["approval": "remote", "credential": credential.label])
      printErr("Verified an approval from \"\(credential.label)\". Remote approval works.")
    } catch {
      auditLog(request, outcome: "denied", error: "assertion rejected: \(error)", extra: ["approval": "remote"])
      printErr("The phone answered, but verification failed: \(error)")
      exit(EXIT_FAILURE)
    }
  case .denied:
    printErr("Denied on phone. The relay and notification work.")
  case .expired:
    printErr("No answer before the request expired")
    exit(EXIT_FAILURE)
  case .failed(let message):
    printErr("Remote approval failed: \(message)")
    exit(EXIT_FAILURE)
  }
}
