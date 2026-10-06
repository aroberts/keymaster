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

func usage() {
  printErr("keymaster [-v] [--reason <text>] [-s|--session <name> [--scope <prefix>]] [get|delete] <key>")
  printErr("echo <secret> | keymaster [-v] [--reason <text>] [-s|--session <name>] set <key>")
}

// Strip characters that could be used to forge a misleading TouchID prompt
// (newlines, control chars, bidi/zero-width format chars) and cap the length,
// so an attacker-controlled key or session name can't spoof the dialog text.
func sanitizeForPrompt(_ value: String, maxLength: Int = 64) -> String {
  let scalars = value.unicodeScalars.filter { scalar in
    switch scalar.properties.generalCategory {
    case .control, .format, .lineSeparator, .paragraphSeparator:
      return false
    default:
      return true
    }
  }
  // Double quotes delimit caller-supplied values in the prompt, so a value
  // can't close its own quote and append text that reads as keymaster's.
  let cleaned = String(String.UnicodeScalarView(scalars)).replacingOccurrences(of: "\"", with: "'")
  if cleaned.count > maxLength {
    return String(cleaned.prefix(maxLength)) + "…"
  }
  return cleaned
}

// One process above keymaster. The executable path comes from the kernel
// (proc_pidpath) and can't be faked by a same-UID caller. argv is whatever the
// process set, so it is only used to name scripts run by an interpreter.
struct ProcessEntry {
  let pid: pid_t
  let path: String
  let argv: [String]

  var name: String { (path as NSString).lastPathComponent }
}

func executablePath(of pid: pid_t) -> String? {
  var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
  guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
  return String(cString: buffer)
}

func parentPID(of pid: pid_t) -> pid_t? {
  var info = proc_bsdinfo()
  let size = Int32(MemoryLayout<proc_bsdinfo>.size)
  guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
  return pid_t(info.pbi_ppid)
}

// Read argv via KERN_PROCARGS2: an argc word, the saved executable path, NUL
// padding, then argc NUL-terminated arguments. Fails for other users'
// processes, which is fine for display.
func arguments(of pid: pid_t) -> [String] {
  var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
  var size = 0
  guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return [] }
  var buffer = [UInt8](repeating: 0, count: size)
  guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return [] }
  let argc = Int(buffer.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) })
  var index = MemoryLayout<Int32>.size
  while index < size && buffer[index] != 0 { index += 1 }
  while index < size && buffer[index] == 0 { index += 1 }
  var args: [String] = []
  while args.count < argc && index < size {
    let start = index
    while index < size && buffer[index] != 0 { index += 1 }
    args.append(String(decoding: buffer[start..<index], as: UTF8.self))
    index += 1
  }
  return args
}

// Walk from keymaster's parent up to (not including) launchd.
func processChain() -> [ProcessEntry] {
  var chain: [ProcessEntry] = []
  var pid = getppid()
  while pid > 1 && chain.count < 32 {
    guard let path = executablePath(of: pid) else { break }
    chain.append(ProcessEntry(pid: pid, path: path, argv: arguments(of: pid)))
    guard let parent = parentPID(of: pid), parent != pid else { break }
    pid = parent
  }
  return chain
}

let shellNames: Set<String> = ["sh", "bash", "zsh", "dash", "fish", "ksh", "tcsh", "csh"]
let interpreterPrefixes = ["python", "node", "ruby", "perl", "osascript", "bun", "deno"]
let hiddenProcessNames: Set<String> = ["login", "env"]

// A short name for one process in the prompt, or nil to leave it out.
// - A shell or interpreter running a script or module is named by that
//   script. With -c, or interactive, it adds nothing and is skipped.
// - An app bundle is named by the bundle ("Ghostty" for Ghostty.app).
// - A binary installed under a version number (Claude Code's
//   versions/2.1.290) is named by its argv[0].
func displayName(for entry: ProcessEntry) -> String? {
  let name = entry.name
  if hiddenProcessNames.contains(name) { return nil }
  let lowered = name.lowercased()
  let isShell = shellNames.contains(lowered)
  if isShell || interpreterPrefixes.contains(where: { lowered.hasPrefix($0) }) {
    for arg in entry.argv.dropFirst() {
      if arg.hasPrefix("-") {
        if arg == "-c" || (isShell && !arg.hasPrefix("--") && arg.contains("c")) { return nil }
        continue
      }
      return (arg as NSString).lastPathComponent
    }
    return nil
  }
  if let appRange = entry.path.range(of: ".app/Contents/MacOS/") {
    let bundlePath = String(entry.path[..<appRange.lowerBound])
    return ((bundlePath as NSString).lastPathComponent as NSString).deletingPathExtension
  }
  if !name.contains(where: \.isLetter), let argv0 = entry.argv.first {
    return (argv0 as NSString).lastPathComponent
  }
  return name
}

// "ansible-vault-keymaster ← ansible-playbook ← … ← tmux": the nearest
// callers, then the outermost one, which is usually the terminal, tmux, an
// app or a launchd job.
func summarizeChain(_ chain: [ProcessEntry]) -> String {
  var names: [String] = []
  for name in chain.compactMap(displayName) where names.last != name {
    names.append(name)
  }
  if names.isEmpty { return "launchd" }
  if names.count > 4 {
    names = Array(names.prefix(3)) + ["…", names.last!]
  }
  return names.map { sanitizeForPrompt($0, maxLength: 32) }.joined(separator: " ← ")
}

func abbreviateHome(_ path: String) -> String {
  let home = NSHomeDirectory()
  if path == home { return "~" }
  if path.hasPrefix(home + "/") { return "~" + path.dropFirst(home.count) }
  return path
}

// Everything known about one request, gathered once so the prompt and the
// debug output describe the same thing.
struct RequestContext {
  let action: String
  let key: String
  let sessionName: String?
  let scope: String?
  let reason: String?
  let ttl: TimeInterval
  let chain: [ProcessEntry]
  let workingDirectory: String

  var verb: String {
    switch action {
    case "get": return "read"
    case "set": return "store"
    case "delete": return "delete"
    default: return sanitizeForPrompt(action)
    }
  }
}

let auditLogPath = NSHomeDirectory() + "/Library/Logs/keymaster.log"
let auditLogMaxBytes: off_t = 1_000_000

// Append one JSON line per access to the audit log, so reads served from the
// cache, which never show a prompt, are still visible. The process chain is
// logged by executable path and display name only: ancestors' argv can hold
// whole command lines, including secrets. There is deliberately no setting to
// turn the log off or move it, since a caller could set that too.
func auditLog(_ request: RequestContext, outcome: String, error: String? = nil) {
  var record: [String: Any] = [
    "ts": ISO8601DateFormatter().string(from: Date()),
    "pid": Int(getpid()),
    "action": request.action,
    "key": request.key,
    "outcome": outcome,
    "caller": summarizeChain(request.chain),
    "cwd": request.workingDirectory,
    "chain": request.chain.map { entry -> [String: Any] in
      var item: [String: Any] = ["pid": Int(entry.pid), "path": entry.path]
      if let name = displayName(for: entry) { item["name"] = name }
      return item
    }
  ]
  if let sessionName = request.sessionName { record["session"] = sessionName }
  if let scope = request.scope { record["scope"] = scope }
  if let reason = request.reason { record["reason"] = reason }
  if outcome != "cached" && request.action == "get" { record["ttl"] = Int(request.ttl) }
  if let error = error { record["error"] = error }
  guard var line = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys, .withoutEscapingSlashes]) else {
    return
  }
  line.append(UInt8(ascii: "\n"))

  guard let fd = openAuditLog() else {
    debug("Could not open audit log \(auditLogPath)")
    return
  }
  _ = line.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
  flock(fd, LOCK_UN)
  close(fd)
}

// Open the audit log locked, rotating it to .1 once it passes the size cap.
// Another writer may rename the file between our open and our lock, so after
// locking, check the fd still refers to the file at the path, and retry if not.
// Without the check, a late writer would see the old oversized inode and
// rotate the fresh file over .1.
func openAuditLog() -> Int32? {
  for _ in 0..<5 {
    let fd = open(auditLogPath, O_WRONLY | O_APPEND | O_CREAT, 0o600)
    guard fd >= 0 else { return nil }
    flock(fd, LOCK_EX)
    var opened = stat()
    var current = stat()
    guard fstat(fd, &opened) == 0,
          stat(auditLogPath, &current) == 0,
          opened.st_ino == current.st_ino && opened.st_dev == current.st_dev else {
      flock(fd, LOCK_UN)
      close(fd)
      continue
    }
    if opened.st_size > auditLogMaxBytes {
      // Rename while holding the lock on the old file, then start over on a
      // fresh one. Writers waiting on the old file will fail the inode check.
      rename(auditLogPath, auditLogPath + ".1")
      flock(fd, LOCK_UN)
      close(fd)
      continue
    }
    return fd
  }
  return nil
}

// Build the TouchID reason string. It states what the gesture approves (the
// key, session and any scope), who asked (the process chain and directory,
// which keymaster reads itself), and why, as claimed by the caller. Each part
// is its own sentence so a long one doesn't run into the next.
func authReason(for request: RequestContext) -> String {
  var reason = "Authenticate to \(request.verb) \"\(sanitizeForPrompt(request.key))\""
  if let sessionName = request.sessionName {
    reason += " in session \"\(sanitizeForPrompt(sessionName))\""
  }
  // A scoped approval is reused for other keys, so the prompt has to say which
  // ones. Only reads warm the cache, so the scope only applies to "get".
  if request.action == "get", let scope = request.scope {
    reason += ". Also allows reading keys starting with \"\(sanitizeForPrompt(scope))\" for \(Int(request.ttl))s"
  }
  reason += ". Requested by \(summarizeChain(request.chain))"
  reason += " in \(sanitizeForPrompt(abbreviateHome(request.workingDirectory), maxLength: 48))"
  if let why = request.reason {
    reason += ". Reason given: \"\(sanitizeForPrompt(why, maxLength: 120))\""
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
  // --reason is the caller's own account of why it wants the key. It is shown
  // as a claim, so an environment variable is fine: it can't widen access.
  var callerReason: String? = nil
  if let idx = inputArgs.firstIndex(of: "--reason") {
    guard idx + 1 < inputArgs.count else {
      printErr("Missing value for --reason")
      exit(EXIT_FAILURE)
    }
    callerReason = inputArgs[idx + 1]
    inputArgs.removeSubrange(idx...idx + 1)
  }
  if callerReason == nil {
    callerReason = ProcessInfo.processInfo.environment["KEYMASTER_REASON"]
  }
  if callerReason?.isEmpty == true { callerReason = nil }
  var scope: String? = nil
  if let idx = inputArgs.firstIndex(of: "--scope") {
    guard idx + 1 < inputArgs.count else {
      printErr("Missing value for --scope")
      exit(EXIT_FAILURE)
    }
    scope = inputArgs[idx + 1]
    inputArgs.removeSubrange(idx...idx + 1)
  }
  if inputArgs.count != 2 {
    usage()
    exit(EXIT_FAILURE)
  }
  let action = inputArgs[0]
  let key = inputArgs[1]
  // --scope widens one named-session approval to a family of keys. An empty
  // prefix would cover every key, and the key being accessed must be inside
  // the scope the user is approving.
  if let scope = scope {
    guard sessionName != nil else {
      printErr("--scope requires a named session (-s/--session or KEYMASTER_SESSION)")
      exit(EXIT_FAILURE)
    }
    guard !scope.isEmpty else {
      printErr("--scope requires a non-empty key prefix")
      exit(EXIT_FAILURE)
    }
    guard key.hasPrefix(scope) else {
      printErr("Key \"\(key)\" does not start with --scope prefix \"\(scope)\"")
      exit(EXIT_FAILURE)
    }
  }
  debug("pid: \(getpid()), action: \(action), key: \(key)")
  debug("Session file: \(sessionFilePath)")
  debug("TTL: \(Int(reuseDuration()))s")
  if let s = sessionName { debug("Session name: \(s)") }
  if let p = scope { debug("Scope prefix: \(p)") }
  let request = RequestContext(
    action: action,
    key: key,
    sessionName: sessionName,
    scope: scope,
    reason: callerReason,
    ttl: reuseDuration(),
    chain: processChain(),
    workingDirectory: FileManager.default.currentDirectoryPath
  )
  for entry in request.chain {
    debug("Caller: \(entry.pid) \(entry.path) \(entry.argv.dropFirst().joined(separator: " "))")
  }
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

  // Only reads reuse a cached approval. Writes and deletes always need a fresh
  // TouchID, so approving a read never lets another process overwrite or
  // remove a secret within the TTL window.
  if action == "get" {
    let acted = withValidSession(for: key, sessionName: sessionName, scope: scope) {
      auditLog(request, outcome: "cached")
      performAction(action: action, key: key, secret: secret)
    }
    if acted { exit(EXIT_SUCCESS) }
    debug("No valid session, requesting TouchID")
  } else {
    debug("Action \(action) always requires TouchID")
  }

  let context = LAContext()
  var error: NSError?
  guard context.canEvaluatePolicy(policy, error: &error) else {
    printErr("This Mac doesn't support deviceOwnerAuthenticationWithBiometrics")
    exit(EXIT_FAILURE)
  }

  let reason = authReason(for: request)
  debug("TouchID reason: \(reason)")
  context.evaluatePolicy(policy, localizedReason: reason) { success, error in
    if success {
      debug("TouchID succeeded")
      auditLog(request, outcome: "approved")
      if action == "get" {
        updateSession(for: key, sessionName: sessionName, scope: scope)
      }
      performAction(action: action, key: key, secret: secret)
      exit(EXIT_SUCCESS)
    } else {
      let message = error?.localizedDescription ?? "Unknown error"
      auditLog(request, outcome: "denied", error: message)
      printErr("Authentication failed or was canceled: \(message)")
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
