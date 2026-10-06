import Foundation
import LocalAuthentication

let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics

func usage() {
  printErr("keymaster [-v] [--reason <text>] [-s|--session <name> [--scope <prefix>]] [get|delete] <key>")
  printErr("echo <secret> | keymaster [-v] [--reason <text>] [-s|--session <name>] set <key>")
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

main()
