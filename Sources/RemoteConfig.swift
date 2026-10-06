import Foundation

// Remote approval keeps its settings in keychain items next to the secrets.
// Changing any of them needs local TouchID (see RemoteCommands.swift), and the
// generic get/set/delete commands refuse to write them or to release them
// through a remote approval.
let remoteConfigItem = "keymaster_remote_config"
let remoteCredentialsItem = "keymaster_remote_credentials"
let remoteAllowlistItem = "keymaster_remote_allowlist"

// Keys only keymaster itself may change, and which no remote approval may
// release.
func isReservedKey(_ key: String) -> Bool {
  key == hmacKeyName || key.hasPrefix(reservedPrefix)
}

let reservedPrefix = "keymaster_remote_"

// Whether some reserved key starts with this prefix, so a grant for the
// prefix would cover it.
func prefixCoversReserved(_ prefix: String) -> Bool {
  hmacKeyName.hasPrefix(prefix) || reservedPrefix.hasPrefix(prefix) || prefix.hasPrefix(reservedPrefix)
}

struct RemoteConfig: Codable {
  var relayURL: String
  var relayToken: String
  var pushoverToken: String?
  var pushoverUser: String?

  var url: URL? { URL(string: relayURL) }

  // The WebAuthn RP ID and origin follow from the relay URL: the page is
  // served from it, so the passkey is created for its host.
  var rpId: String? { url?.host }

  var origin: String? {
    guard let url = url, let scheme = url.scheme, let host = url.host else { return nil }
    if let port = url.port { return "\(scheme)://\(host):\(port)" }
    return "\(scheme)://\(host)"
  }

  var pushoverConfigured: Bool { pushoverToken != nil && pushoverUser != nil }
}

func loadJSONItem<T: Decodable>(_ type: T.Type, key: String) -> T? {
  guard let text = getPassword(key: key) else { return nil }
  guard let value = try? JSONDecoder().decode(T.self, from: Data(text.utf8)) else {
    printErr("Keychain item \(key) is not valid; ignoring it")
    return nil
  }
  return value
}

func storeJSONItem<T: Encodable>(_ value: T, key: String) -> Bool {
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys]
  guard let data = try? encoder.encode(value) else { return false }
  return replacePassword(key: key, password: String(decoding: data, as: UTF8.self))
}

func loadRemoteConfig() -> RemoteConfig? { loadJSONItem(RemoteConfig.self, key: remoteConfigItem) }
func loadCredentials() -> [EnrolledCredential] { loadJSONItem([EnrolledCredential].self, key: remoteCredentialsItem) ?? [] }
func loadAllowlist() -> [String] { loadJSONItem([String].self, key: remoteAllowlistItem) ?? [] }

// An allowlist entry is an exact key, or a prefix followed by "*". A scoped
// request is only covered by a prefix entry that contains the whole scope,
// since the approval will also release every other key under that scope.
func allowlistCovers(_ allowlist: [String], key: String, scope: String?) -> Bool {
  if isReservedKey(key) { return false }
  if let scope = scope, prefixCoversReserved(scope) { return false }
  for entry in allowlist {
    if entry.hasSuffix("*") {
      let prefix = String(entry.dropLast())
      guard !prefix.isEmpty else { continue }
      if let scope = scope {
        if scope.hasPrefix(prefix) { return true }
      } else if key.hasPrefix(prefix) {
        return true
      }
    } else if scope == nil && entry == key {
      return true
    }
  }
  return false
}
