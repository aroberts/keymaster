import CryptoKit
import Foundation

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

// A cache entry records when TouchID succeeded and when the grant expires.
// The expiry is fixed by the authenticating process, so a later caller's
// KEYMASTER_TTL can shorten its own reuse window but never extend a grant.
struct SessionEntry {
  let authTime: Double
  let expiry: Double
}

func readSessionEntries(hmacKey: SymmetricKey) -> [String: SessionEntry] {
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
  // Parse entries: each line is "hashedKey:authTime:expiry"
  var entries: [String: SessionEntry] = [:]
  for line in lines {
    let fields = line.split(separator: ":", omittingEmptySubsequences: false)
    guard fields.count == 3,
          !fields[0].isEmpty,
          let authTime = Double(fields[1]),
          let expiry = Double(fields[2]) else { continue }
    entries[String(fields[0])] = SessionEntry(authTime: authTime, expiry: expiry)
  }
  return entries
}

func writeSessionEntries(_ entries: [String: SessionEntry], hmacKey: SymmetricKey) {
  let lines = entries.map { "\($0.key):\($0.value.authTime):\($0.value.expiry)" }
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

// Derive the cache identity that ties a cached auth to what was approved.
//
// - No session name: the requested key, bound to the POSIX session leader
//   (getsid) so an unrelated same-UID process can't race the TTL window.
// - Named session without a scope: the requested key only, unbound so it is
//   shared across processes.
// - Named session with a scope: every key starting with the scope prefix.
//
// The leading tags keep the namespaces from colliding, e.g. a key named the
// same as a scope prefix.
func sessionCacheInput(forKey keyName: String, sessionName: String?, scope: String?) -> String {
  guard let sessionName = sessionName else {
    return "key\u{0}\(keyName)\u{0}\(getsid(0))"
  }
  if let scope = scope {
    return "session\u{0}\(sessionName)\u{0}prefix\u{0}\(scope)"
  }
  return "session\u{0}\(sessionName)\u{0}key\u{0}\(keyName)"
}

func describeScope(forKey keyName: String, sessionName: String?, scope: String?) -> String {
  guard let sessionName = sessionName else {
    return "\"\(keyName)\" bound to session leader \(getsid(0))"
  }
  if let scope = scope {
    return "keys starting with \"\(scope)\" in named session \"\(sessionName)\" (unbound)"
  }
  return "\"\(keyName)\" in named session \"\(sessionName)\" (unbound)"
}

func withValidSession(for keyName: String, sessionName: String?, scope: String?, perform action: () -> Void) -> Bool {
  return withSessionLock(exclusive: false) {
    debug("Session scope: \(describeScope(forKey: keyName, sessionName: sessionName, scope: scope))")
    let keys = deriveKeys()
    let entries = readSessionEntries(hmacKey: keys.signing)
    let hashedKey = computeHMAC(
      for: sessionCacheInput(forKey: keyName, sessionName: sessionName, scope: scope),
      using: keys.naming
    )
    guard let entry = entries[hashedKey] else {
      debug("No session entry for key")
      return false
    }
    let currentTime = Date().timeIntervalSince1970
    let age = currentTime - entry.authTime
    let ttl = reuseDuration()
    guard currentTime <= entry.expiry else {
      debug("Session expired (age: \(Int(age))s, granted until \(Int(entry.expiry - entry.authTime))s)")
      return false
    }
    guard age <= ttl else {
      debug("Session older than caller's TTL (age: \(Int(age))s, ttl: \(Int(ttl))s)")
      return false
    }
    debug("Session valid (age: \(Int(age))s, expires in \(Int(entry.expiry - currentTime))s)")
    action()
    return true
  }
}

func updateSession(for keyName: String, sessionName: String?, scope: String?) {
  withSessionLock(exclusive: true) {
    let keys = deriveKeys()
    var entries = readSessionEntries(hmacKey: keys.signing)
    let hashedKey = computeHMAC(
      for: sessionCacheInput(forKey: keyName, sessionName: sessionName, scope: scope),
      using: keys.naming
    )
    let currentTime = Date().timeIntervalSince1970
    entries[hashedKey] = SessionEntry(authTime: currentTime, expiry: currentTime + reuseDuration())
    let before = entries.count
    entries = entries.filter { currentTime <= $0.value.expiry }
    debug("Session updated, \(entries.count) entry(s) (\(before - entries.count) pruned)")
    writeSessionEntries(entries, hmacKey: keys.signing)
  }
}

func reuseDuration() -> TimeInterval {
  let envReuseDuration = ProcessInfo.processInfo.environment["KEYMASTER_TTL"]
  return envReuseDuration.flatMap(TimeInterval.init) ?? defaultReuseDuration
}
