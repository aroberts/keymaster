import CryptoKit
import Foundation
import LocalAuthentication

var verbose = false

func printErr(_ message: String) {
  FileHandle.standardError.write(Data((message + "\n").utf8))
}

func debug(_ message: String) {
  if verbose {
    printErr("[debug] \(message)")
  }
}

extension Data {
  init?(hexString: String) {
    let len = hexString.count
    guard len.isMultiple(of: 2) else { return nil }
    var data = Data(capacity: len / 2)
    var index = hexString.startIndex
    while index < hexString.endIndex {
      let nextIndex = hexString.index(index, offsetBy: 2)
      guard let byte = UInt8(hexString[index..<nextIndex], radix: 16) else { return nil }
      data.append(byte)
      index = nextIndex
    }
    self = data
  }
}

let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics

let sessionFilePath: String = {
  let dir = ProcessInfo.processInfo.environment["TMPDIR"] ?? "/tmp/"
  let base = dir.hasSuffix("/") ? dir : dir + "/"
  return base + "keymaster_session"
}()

let lockFilePath = sessionFilePath + ".lock"
let hmacKeyName = "keymaster_session_hmac_key"

// Duration for which authentication can be reused (in seconds)
let defaultReuseDuration: TimeInterval = 300

func getOrCreateHMACKey() -> SymmetricKey {
  if let existingBase64 = getPassword(key: hmacKeyName),
     let keyData = Data(base64Encoded: existingBase64) {
    debug("Loaded existing HMAC key from keychain")
    return SymmetricKey(data: keyData)
  }
  debug("No HMAC key found, generating new key")
  let newKey = SymmetricKey(size: .bits256)
  let keyData = newKey.withUnsafeBytes { Data($0) }
  let base64String = keyData.base64EncodedString()
  guard setPassword(key: hmacKeyName, password: base64String) else {
    printErr("Failed to store HMAC key in keychain")
    exit(EXIT_FAILURE)
  }
  return newKey
}

func deriveKeys() -> (naming: SymmetricKey, signing: SymmetricKey) {
  let master = getOrCreateHMACKey()
  let naming = HKDF<SHA256>.deriveKey(
    inputKeyMaterial: master,
    info: Data("keymaster.key-naming".utf8),
    outputByteCount: 32
  )
  let signing = HKDF<SHA256>.deriveKey(
    inputKeyMaterial: master,
    info: Data("keymaster.session-signing".utf8),
    outputByteCount: 32
  )
  return (naming, signing)
}

func computeHMAC(for message: String, using key: SymmetricKey) -> String {
  let mac = HMAC<SHA256>.authenticationCode(
    for: Data(message.utf8),
    using: key
  )
  return mac.map { String(format: "%02x", $0) }.joined()
}

func readSessionEntries(hmacKey: SymmetricKey) -> [String: Double] {
  guard let sessionData = try? String(contentsOfFile: sessionFilePath, encoding: .utf8) else {
    debug("No session file at \(sessionFilePath)")
    return [:]
  }
  var lines = sessionData.components(separatedBy: "\n")
    .filter { !$0.isEmpty }
  // Last line is the file-level HMAC
  guard lines.count >= 2 else {
    debug("Session file malformed (fewer than 2 lines)")
    return [:]
  }
  let fileHMAC = lines.removeLast()
  let body = lines.joined(separator: "\n")
  guard let fileHMACData = Data(hexString: fileHMAC),
        HMAC<SHA256>.isValidAuthenticationCode(fileHMACData, authenticating: Data(body.utf8), using: hmacKey)
  else {
    debug("Session file HMAC verification failed")
    return [:]
  }
  debug("Session file verified, \(lines.count) entry(s)")
  // Parse entries: each line is "hashedKey:timestamp"
  var entries: [String: Double] = [:]
  for line in lines {
    guard let separatorIndex = line.lastIndex(of: ":"),
          separatorIndex > line.startIndex else { continue }
    let hashedKey = String(line[..<separatorIndex])
    let timestampStr = String(line[line.index(after: separatorIndex)...])
    if let timestamp = Double(timestampStr) {
      entries[hashedKey] = timestamp
    }
  }
  return entries
}

func writeSessionEntries(_ entries: [String: Double], hmacKey: SymmetricKey) {
  let lines = entries.map { "\($0.key):\($0.value)" }
  let body = lines.joined(separator: "\n")
  let fileHMAC = computeHMAC(for: body, using: hmacKey)
  let content = body + "\n" + fileHMAC
  try? content.write(to: URL(fileURLWithPath: sessionFilePath), atomically: true, encoding: .utf8)
}

func withSessionLock<T>(exclusive: Bool, _ body: () -> T) -> T {
  let mode = exclusive ? "exclusive" : "shared"
  let fd = open(lockFilePath, O_CREAT | O_RDWR, 0o600)
  if fd >= 0 {
    debug("Acquiring \(mode) lock on \(lockFilePath)")
    flock(fd, exclusive ? LOCK_EX : LOCK_SH)
  } else {
    debug("Could not open lock file, proceeding without lock")
  }
  defer {
    if fd >= 0 {
      flock(fd, LOCK_UN)
      close(fd)
    }
  }
  return body()
}

func withValidSession(for keyName: String, sessionName: String? = nil, perform action: () -> Void) -> Bool {
  return withSessionLock(exclusive: false) {
    let sid = getsid(0)
    let scope = sessionName ?? keyName
    let bound = sessionName == nil
    debug("Session leader PID: \(sid)\(bound ? "" : " (unbound, named session)")")
    debug("Session scope: \(scope)\(sessionName != nil ? " (explicit session)" : " (key)")")
    let keys = deriveKeys()
    let entries = readSessionEntries(hmacKey: keys.signing)
    let cacheKeyInput = bound ? "\(scope)\0\(sid)" : scope
    let hashedKey = computeHMAC(for: cacheKeyInput, using: keys.naming)
    guard let lastAuthTime = entries[hashedKey] else {
      debug("No session entry for key")
      return false
    }
    let currentTime = Date().timeIntervalSince1970
    let age = currentTime - lastAuthTime
    let ttl = reuseDuration()
    guard age <= ttl else {
      debug("Session expired (age: \(Int(age))s, ttl: \(Int(ttl))s)")
      return false
    }
    debug("Session valid (age: \(Int(age))s, ttl: \(Int(ttl))s)")
    action()
    return true
  }
}

func updateSession(for keyName: String, sessionName: String? = nil) {
  withSessionLock(exclusive: true) {
    let scope = sessionName ?? keyName
    let keys = deriveKeys()
    var entries = readSessionEntries(hmacKey: keys.signing)
    let cacheKeyInput = sessionName != nil ? scope : "\(scope)\0\(getsid(0))"
    let hashedKey = computeHMAC(for: cacheKeyInput, using: keys.naming)
    let currentTime = Date().timeIntervalSince1970
    entries[hashedKey] = currentTime
    let ttl = reuseDuration()
    let before = entries.count
    entries = entries.filter { currentTime - $0.value <= ttl }
    debug("Session updated, \(entries.count) entry(s) (\(before - entries.count) pruned)")
    writeSessionEntries(entries, hmacKey: keys.signing)
  }
}

func reuseDuration() -> TimeInterval {
  let envReuseDuration = ProcessInfo.processInfo.environment["KEYMASTER_TTL"]
  return envReuseDuration.flatMap(TimeInterval.init) ?? defaultReuseDuration
}

func usage() {
  printErr("keymaster [-v] [-s|--session <name>] [get|delete] <key>")
  printErr("echo <secret> | keymaster [-v] [-s|--session <name>] set <key>")
}

// Strip characters that could be used to forge a misleading TouchID prompt
// (newlines, control chars, bidi/zero-width format chars) and cap the length,
// so an attacker-controlled key or session name can't spoof the dialog text.
func sanitizeForPrompt(_ value: String) -> String {
  let scalars = value.unicodeScalars.filter { scalar in
    switch scalar.properties.generalCategory {
    case .control, .format, .lineSeparator, .paragraphSeparator:
      return false
    default:
      return true
    }
  }
  let cleaned = String(String.UnicodeScalarView(scalars))
  let maxLength = 64
  if cleaned.count > maxLength {
    return String(cleaned.prefix(maxLength)) + "…"
  }
  return cleaned
}

// Build the TouchID reason string. Naming the key (and session) ties the
// biometric gesture to a specific action so the user can catch an unexpected
// access instead of approving a generic prompt reflexively.
func authReason(action: String, key: String, sessionName: String?) -> String {
  let verb: String
  switch action {
  case "get": verb = "read"
  case "set": verb = "store"
  case "delete": verb = "delete"
  default: verb = sanitizeForPrompt(action)
  }
  var reason = "Authenticate to \(verb) \"\(sanitizeForPrompt(key))\""
  if let sessionName = sessionName {
    reason += " in session \"\(sanitizeForPrompt(sessionName))\""
  }
  return reason
}

func main() {
  var inputArgs: [String] = Array(CommandLine.arguments.dropFirst())
  if let idx = inputArgs.firstIndex(of: "-v") {
    verbose = true
    inputArgs.remove(at: idx)
  }
  var sessionName: String? = nil
  if let idx = inputArgs.firstIndex(of: "-s") ?? inputArgs.firstIndex(of: "--session") {
    guard idx + 1 < inputArgs.count else {
      printErr("Missing value for \(inputArgs[idx])")
      exit(EXIT_FAILURE)
    }
    sessionName = inputArgs[idx + 1]
    inputArgs.removeSubrange(idx...idx + 1)
  }
  if sessionName == nil {
    sessionName = ProcessInfo.processInfo.environment["KEYMASTER_SESSION"]
  }
  if inputArgs.count != 2 {
    usage()
    exit(EXIT_FAILURE)
  }
  let action = inputArgs[0]
  let key = inputArgs[1]
  debug("pid: \(getpid()), action: \(action), key: \(key)")
  debug("Session file: \(sessionFilePath)")
  debug("TTL: \(Int(reuseDuration()))s")
  if let s = sessionName { debug("Session name: \(s)") }
  var secret = ""
  if action == "set" {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard let input = String(data: data, encoding: .utf8), !input.isEmpty else {
      printErr("Failed to read secret from stdin")
      exit(EXIT_FAILURE)
    }
    secret = input
    if secret.hasSuffix("\n") { secret.removeLast() }
  }

  // Check if there is a valid session for this key
  let acted = withValidSession(for: key, sessionName: sessionName) {
    performAction(action: action, key: key, secret: secret)
  }
  if acted { exit(EXIT_SUCCESS) }

  // No valid session, proceed with TouchID authentication
  debug("No valid session, requesting TouchID")
  let context = LAContext()
  var error: NSError?
  guard context.canEvaluatePolicy(policy, error: &error) else {
    printErr("This Mac doesn't support deviceOwnerAuthenticationWithBiometrics")
    exit(EXIT_FAILURE)
  }

  let reason = authReason(action: action, key: key, sessionName: sessionName)
  debug("TouchID reason: \(reason)")
  context.evaluatePolicy(policy, localizedReason: reason) { success, error in
    if success {
      debug("TouchID succeeded")
      updateSession(for: key, sessionName: sessionName)
      performAction(action: action, key: key, secret: secret)
      exit(EXIT_SUCCESS)
    } else {
      printErr("Authentication failed or was canceled: \(error?.localizedDescription ?? "Unknown error")")
      exit(EXIT_FAILURE)
    }
  }
  dispatchMain()
}

func performAction(action: String, key: String, secret: String) {
  if action == "set" {
    guard setPassword(key: key, password: secret) else {
      exit(EXIT_FAILURE)
    }
    printErr("Key \(key) has been successfully set in the keychain")
  } else if action == "get" {
    guard let password = getPassword(key: key) else {
      exit(EXIT_FAILURE)
    }
    print(password)
  } else if action == "delete" {
    guard deletePassword(key: key) else {
      exit(EXIT_FAILURE)
    }
    printErr("Key \(key) has been successfully deleted from the keychain")
  }
}

func setPassword(key: String, password: String) -> Bool {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecValueData as String: password.data(using: .utf8)!
  ]
  let status = SecItemAdd(query as CFDictionary, nil)
  if status != errSecSuccess {
    if let errorMessage = SecCopyErrorMessageString(status, nil) {
      printErr("Error setting password: \(errorMessage)")
    } else {
      printErr("Unknown error occurred while setting password")
    }
  }
  return status == errSecSuccess
}

func getPassword(key: String) -> String? {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key,
    kSecMatchLimit as String: kSecMatchLimitOne,
    kSecReturnData as String: true
  ]
  var item: CFTypeRef?
  let status = SecItemCopyMatching(query as CFDictionary, &item)
  if status == errSecItemNotFound {
    return nil
  }
  if status != errSecSuccess {
    if let errorMessage = SecCopyErrorMessageString(status, nil) {
      printErr("Error getting password: \(errorMessage)")
    } else {
      printErr("Unknown error occurred while getting password")
    }
    return nil
  }
  guard let passwordData = item as? Data else { return nil }
  return String(data: passwordData, encoding: .utf8)
}

func deletePassword(key: String) -> Bool {
  let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: key
  ]
  let status = SecItemDelete(query as CFDictionary)
  if status != errSecSuccess {
    if let errorMessage = SecCopyErrorMessageString(status, nil) {
      printErr("Error deleting password: \(errorMessage)")
    } else {
      printErr("Unknown error occurred while deleting password")
    }
  }
  return status == errSecSuccess
}

main()
