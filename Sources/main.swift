import Foundation
import LocalAuthentication

func usage() {
  printErr("keymaster [-v] [--approve local|remote|auto] [--reason <text>] [-s|--session <name> [--scope <prefix>]] [get|delete] <key>")
  printErr("echo <secret> | keymaster [-v] [--reason <text>] [-s|--session <name>] set <key>")
  printErr("keymaster remote setup|enroll|list|revoke|allow|disallow|test  (keymaster remote help)")
}

func main() {
  var inputArgs: [String] = Array(CommandLine.arguments.dropFirst())
  if let idx = inputArgs.firstIndex(of: "-v") {
    verbose = true
    inputArgs.remove(at: idx)
  }
  if inputArgs.first == "remote" {
    runRemoteCommand(Array(inputArgs.dropFirst()))
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
  // --approve picks how a request that misses the cache is approved. The
  // environment variable is allowed because scheduled runs can only set the
  // mode that way, and every mode still needs a person's approval.
  var approvalName = ProcessInfo.processInfo.environment["KEYMASTER_APPROVE"]
  if let idx = inputArgs.firstIndex(of: "--approve") {
    guard idx + 1 < inputArgs.count else {
      printErr("Missing value for --approve")
      exit(EXIT_FAILURE)
    }
    approvalName = inputArgs[idx + 1]
    inputArgs.removeSubrange(idx...idx + 1)
  }
  if approvalName?.isEmpty == true { approvalName = nil }
  guard let approvalMode = ApprovalMode(rawValue: approvalName ?? "local") else {
    printErr("--approve must be local, remote or auto")
    exit(EXIT_FAILURE)
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
  debug("Approval mode: \(approvalMode.rawValue)")
  if action == "set" && key.hasPrefix(reservedPrefix) {
    printErr("\(key) is managed by \"keymaster remote\"; set it there")
    exit(EXIT_FAILURE)
  }
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
  // remove a secret within the TTL window. keymaster's own items never use the
  // cache, so a scope that happens to cover them can't release them.
  let cacheable = action == "get" && !isReservedKey(key)
  if cacheable {
    let acted = withValidSession(for: key, sessionName: sessionName, scope: scope) {
      auditLog(request, outcome: "cached")
      performAction(action: action, key: key, secret: secret)
    }
    if acted { exit(EXIT_SUCCESS) }
    debug("No valid session, requesting approval")
  } else {
    debug("\(key) with action \(action) always requires a fresh approval")
  }

  // Decide between TouchID and the phone. Remote settings load only when the
  // mode could use them, so the default path doesn't touch them.
  let setup = approvalMode == .local ? nil : RemoteSetup.load()
  let remoteBlocker = setup?.ineligibility(for: request)
  var fallbackAfter: TimeInterval? = nil
  switch approvalMode {
  case .local:
    break
  case .remote:
    if let why = remoteBlocker {
      auditLog(request, outcome: "denied", error: "can't approve remotely: \(why)", extra: ["approval": "remote"])
      printErr("Can't approve remotely: \(why)")
      exit(EXIT_FAILURE)
    }
    approveRemotelyAndExit(request, setup: setup!, secret: secret)
  case .auto:
    if let why = remoteBlocker {
      debug("Auto mode stays local: \(why)")
    } else if screenIsLocked() {
      debug("Screen is locked, asking the phone")
      approveRemotelyAndExit(request, setup: setup!, secret: secret)
    } else {
      fallbackAfter = localTimeout()
    }
  }

  let context = LAContext()
  var error: NSError?
  guard context.canEvaluatePolicy(policy, error: &error) else {
    if fallbackAfter != nil {
      debug("TouchID unavailable (\(error?.localizedDescription ?? "unknown")), asking the phone")
      approveRemotelyAndExit(request, setup: setup!, secret: secret)
    }
    printErr("This Mac doesn't support deviceOwnerAuthenticationWithBiometrics")
    exit(EXIT_FAILURE)
  }

  // In auto mode, give up on TouchID after the timeout and ask the phone.
  // timedOut is only touched on the main queue.
  var timedOut = false
  if let timeout = fallbackAfter {
    DispatchQueue.main.asyncAfter(deadline: .now() + timeout) {
      debug("TouchID not answered in \(Int(timeout))s")
      timedOut = true
      context.invalidate()
    }
  }

  let reason = authReason(for: request)
  debug("TouchID reason: \(reason)")
  context.evaluatePolicy(policy, localizedReason: reason) { success, error in
    DispatchQueue.main.async {
      if success {
        debug("TouchID succeeded")
        auditLog(request, outcome: "approved", extra: ["approval": "touchid"])
        if cacheable {
          updateSession(for: key, sessionName: sessionName, scope: scope)
        }
        performAction(action: action, key: key, secret: secret)
        exit(EXIT_SUCCESS)
      }
      if fallbackAfter != nil && (timedOut || touchIDUnanswerable(error)) {
        printErr("TouchID went unanswered; asking your phone instead")
        approveRemotelyAndExit(request, setup: setup!, secret: secret)
      }
      let message = error?.localizedDescription ?? "Unknown error"
      auditLog(request, outcome: "denied", error: message, extra: ["approval": "touchid"])
      printErr("Authentication failed or was canceled: \(message)")
      exit(EXIT_FAILURE)
    }
  }
  dispatchMain()
}

main()
