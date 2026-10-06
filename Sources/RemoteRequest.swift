import CryptoKit
import Foundation

// A request sent to the phone, as the exact bytes keymaster signs off on.
// The WebAuthn challenge is SHA-256 of these bytes, so the passkey's signature
// covers everything in them. keymaster keeps its own copy and never trusts
// the one the relay sends back.
struct RemoteRequest {
  let id: String
  let bytes: Data
  let expiry: Date

  var challenge: Data { Data(SHA256.hash(data: bytes)) }

  // Shown in the terminal and on the phone page, so someone at the Mac can
  // tell which request the phone is showing.
  var code: String { shortCode(challenge, bytes: 4) }
}

let remoteRequestVersion = 1

// Canonical form: sorted keys, no whitespace, slashes unescaped. Nothing
// depends on canonical bytes for security, since keymaster hashes the bytes
// it sends, but a stable form keeps requests diffable and reusable by other
// requesters.
func encodeRemoteRequest(_ fields: [String: Any], id: String, expiry: Date) -> RemoteRequest {
  guard let bytes = try? JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys, .withoutEscapingSlashes]) else {
    printErr("Could not encode the remote request")
    exit(EXIT_FAILURE)
  }
  return RemoteRequest(id: id, bytes: bytes, expiry: expiry)
}

// gethostname, which never blocks. ProcessInfo.hostName can wait on DNS.
func localHostName() -> String {
  var buffer = [CChar](repeating: 0, count: 256)
  guard gethostname(&buffer, buffer.count - 1) == 0 else { return "unknown" }
  return String(cString: buffer)
}

func baseRequestFields(kind: String, id: String, now: Date, expiry: Date) -> [String: Any] {
  [
    "v": remoteRequestVersion,
    "kind": kind,
    "id": id,
    "requester": "keymaster",
    "host": localHostName(),
    "user": NSUserName(),
    "iat": Int(now.timeIntervalSince1970),
    "exp": Int(expiry.timeIntervalSince1970),
  ]
}

// The approval request carries the same facts as the TouchID prompt: what is
// being approved (action, key, session, scope and how long the grant lasts),
// who asked (process chain and directory) and the caller's claimed reason.
func makeApprovalRequest(for request: RequestContext, lifetime: TimeInterval, now: Date = Date()) -> RemoteRequest {
  let id = randomBytes(16).base64URL
  let expiry = now.addingTimeInterval(lifetime)
  var fields = baseRequestFields(kind: "approve", id: id, now: now, expiry: expiry)
  fields["action"] = request.action
  fields["key"] = request.key
  fields["caller"] = summarizeChain(request.chain)
  fields["cwd"] = abbreviateHome(request.workingDirectory)
  if request.action == "get" { fields["ttl"] = Int(request.ttl) }
  if let sessionName = request.sessionName { fields["session"] = sessionName }
  if let scope = request.scope { fields["scope"] = scope }
  if let reason = request.reason { fields["reason"] = reason }
  return encodeRemoteRequest(fields, id: id, expiry: expiry)
}

// Enrollment asks the phone to create a passkey. userId is a fresh handle per
// enrollment, so enrolling again adds a passkey instead of silently replacing
// the one already enrolled.
func makeEnrollRequest(label: String, lifetime: TimeInterval, now: Date = Date()) -> RemoteRequest {
  let id = randomBytes(16).base64URL
  let expiry = now.addingTimeInterval(lifetime)
  var fields = baseRequestFields(kind: "enroll", id: id, now: now, expiry: expiry)
  fields["label"] = label
  fields["userId"] = randomBytes(16).base64URL
  return encodeRemoteRequest(fields, id: id, expiry: expiry)
}
