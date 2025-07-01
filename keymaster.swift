import Foundation
import LocalAuthentication

let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics
let sessionFilePath = "/tmp/keymaster_session"

// Duration for which authentication can be reused (in seconds)
let defaultReuseDuration: TimeInterval = 300

func hasValidSession() -> Bool {
  guard let sessionData = try? Data(contentsOf: URL(fileURLWithPath: sessionFilePath)),
        let lastAuthTime = Double(String(data: sessionData, encoding: .utf8) ?? "") else {
    return false
  }
  let currentTime = Date().timeIntervalSince1970
  return currentTime - lastAuthTime <= reuseDuration()
}

func updateSession() {
  let currentTime = String(Date().timeIntervalSince1970)
  try? currentTime.write(to: URL(fileURLWithPath: sessionFilePath), atomically: true, encoding: .utf8)
}

func reuseDuration() -> TimeInterval {
  let envReuseDuration = ProcessInfo.processInfo.environment["KEYMASTER_TTL"]
  let reuseDurationValue = envReuseDuration.flatMap(TimeInterval.init) ?? defaultReuseDuration
  print("TTL duration \(reuseDurationValue)")
  return reuseDurationValue
}

func usage() {
  print("keymaster [get|set|delete] [key] [secret]")
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

  // Check if there is a valid session
  if hasValidSession() {
    performAction(action: action, key: key, secret: secret)
    exit(EXIT_SUCCESS)
  }

  // No valid session, proceed with TouchID authentication
  let context = LAContext()
  var error: NSError?
  guard context.canEvaluatePolicy(policy, error: &error) else {
    print("This Mac doesn't support deviceOwnerAuthenticationWithBiometrics")
    exit(EXIT_FAILURE)
  }

  context.evaluatePolicy(policy, localizedReason: "Authenticate to proceed") { success, error in
    if success {
      updateSession()
      performAction(action: action, key: key, secret: secret)
      exit(EXIT_SUCCESS)
    } else {
      print("Authentication failed or was canceled: \(error?.localizedDescription ?? "Unknown error")")
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
    print("Key \(key) has been successfully set in the keychain")
  } else if action == "get" {
    guard let password = getPassword(key: key) else {
      exit(EXIT_FAILURE)
    }
    print(password)
  } else if action == "delete" {
    guard deletePassword(key: key) else {
      exit(EXIT_FAILURE)
    }
    print("Key \(key) has been successfully deleted from the keychain")
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
      print("Error setting password: \(errorMessage)")
    } else {
      print("Unknown error occurred while setting password")
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
      print("Error getting password: \(errorMessage)")
    } else {
      print("Unknown error occurred while getting password")
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
      print("Error deleting password: \(errorMessage)")
    } else {
      print("Unknown error occurred while deleting password")
    }
  }
  return status == errSecSuccess
}

main()
