import CryptoKit
import Foundation
import LocalAuthentication

func printErr(_ message: String) {
  FileHandle.standardError.write(Data((message + "\n").utf8))
}

let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics

let sessionFilePath: String = {
  let dir = ProcessInfo.processInfo.environment["TMPDIR"] ?? "/tmp/"
  let base = dir.hasSuffix("/") ? dir : dir + "/"
  return base + "keymaster_session"
}()

let hmacKeyName = "keymaster_session_hmac_key"

// Duration for which authentication can be reused (in seconds)
let defaultReuseDuration: TimeInterval = 300

func getOrCreateHMACKey() -> SymmetricKey {
  if let existingBase64 = getPassword(key: hmacKeyName),
     let keyData = Data(base64Encoded: existingBase64) {
    return SymmetricKey(data: keyData)
  }
  let newKey = SymmetricKey(size: .bits256)
  let keyData = newKey.withUnsafeBytes { Data($0) }
  let base64String = keyData.base64EncodedString()
  guard setPassword(key: hmacKeyName, password: base64String) else {
    printErr("Failed to store HMAC key in keychain")
    exit(EXIT_FAILURE)
  }
  return newKey
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
    return [:]
  }
  var lines = sessionData.components(separatedBy: "\n")
    .filter { !$0.isEmpty }
  // Last line is the file-level HMAC
  guard lines.count >= 2 else { return [:] }
  let fileHMAC = lines.removeLast()
  let body = lines.joined(separator: "\n")
  let expectedFileHMAC = computeHMAC(for: body, using: hmacKey)
  guard fileHMAC == expectedFileHMAC else { return [:] }
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

func hasValidSession(for keyName: String) -> Bool {
  let hmacKey = getOrCreateHMACKey()
  let entries = readSessionEntries(hmacKey: hmacKey)
  let hashedKey = computeHMAC(for: keyName, using: hmacKey)
  guard let lastAuthTime = entries[hashedKey] else { return false }
  let currentTime = Date().timeIntervalSince1970
  return currentTime - lastAuthTime <= reuseDuration()
}

func updateSession(for keyName: String) {
  let hmacKey = getOrCreateHMACKey()
  var entries = readSessionEntries(hmacKey: hmacKey)
  let hashedKey = computeHMAC(for: keyName, using: hmacKey)
  let currentTime = Date().timeIntervalSince1970
  // Update this key and prune expired entries
  entries[hashedKey] = currentTime
  let ttl = reuseDuration()
  entries = entries.filter { currentTime - $0.value <= ttl }
  writeSessionEntries(entries, hmacKey: hmacKey)
}

func reuseDuration() -> TimeInterval {
  let envReuseDuration = ProcessInfo.processInfo.environment["KEYMASTER_TTL"]
  return envReuseDuration.flatMap(TimeInterval.init) ?? defaultReuseDuration
}

func usage() {
  printErr("keymaster [get|set|delete] [key] [secret]")
}

func main() {
  let inputArgs: [String] = Array(CommandLine.arguments.dropFirst())
  if inputArgs.count < 2 || inputArgs.count > 3 {
    usage()
    exit(EXIT_FAILURE)
  }
  let action = inputArgs[0]
  let key = inputArgs[1]
  var secret = ""
  if action == "set" && inputArgs.count == 3 {
    secret = inputArgs[2]
  }

  // Check if there is a valid session for this key
  if hasValidSession(for: key) {
    performAction(action: action, key: key, secret: secret)
    exit(EXIT_SUCCESS)
  }

  // No valid session, proceed with TouchID authentication
  let context = LAContext()
  var error: NSError?
  guard context.canEvaluatePolicy(policy, error: &error) else {
    printErr("This Mac doesn't support deviceOwnerAuthenticationWithBiometrics")
    exit(EXIT_FAILURE)
  }

  context.evaluatePolicy(policy, localizedReason: "Authenticate to proceed") { success, error in
    if success {
      updateSession(for: key)
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
