import Foundation
import LocalAuthentication
import Security

let policy = LAPolicy.deviceOwnerAuthenticationWithBiometrics

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

// WebAuthn and the relay use unpadded base64url throughout.
extension Data {
  init?(base64URL: String) {
    var base64 = base64URL.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
    base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
    self.init(base64Encoded: base64)
  }

  var base64URL: String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }

  var hex: String { map { String(format: "%02x", $0) }.joined() }
}

func randomBytes(_ count: Int) -> Data {
  var bytes = [UInt8](repeating: 0, count: count)
  guard SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess else {
    printErr("Could not generate random bytes")
    exit(EXIT_FAILURE)
  }
  return Data(bytes)
}

// "abcd-ef01-…": the first `bytes` bytes of a digest in groups of four hex
// digits, for a person to compare between the terminal and the phone.
func shortCode(_ digest: Data, bytes: Int) -> String {
  let digits = Array(digest.prefix(bytes).hex)
  return stride(from: 0, to: digits.count, by: 4)
    .map { String(digits[$0..<min($0 + 4, digits.count)]) }
    .joined(separator: "-")
}
