import CoreImage
import CryptoKit
import Foundation

// keymaster's tests, compiled by test.sh with every source file except
// Sources/main.swift. Nothing here touches the keychain or TouchID.
//
// With KM_RELAY and KM_FAKEPHONE set to built binaries, the integration
// tests also run a real relay on localhost and approve requests with the Go
// fake phone, which signs with Go's crypto rather than CryptoKit.

var failures = 0
var checks = 0

func check(_ condition: Bool, _ message: @autoclosure () -> String, file: String = #fileID, line: Int = #line) {
  checks += 1
  if !condition {
    failures += 1
    print("FAIL \(file):\(line): \(message())")
  }
}

func expectThrows(_ substring: String, _ body: () throws -> Void, line: Int = #line) {
  do {
    try body()
    check(false, "expected an error containing \"\(substring)\"", line: line)
  } catch {
    check("\(error)".contains(substring), "error \"\(error)\" does not contain \"\(substring)\"", line: line)
  }
}

func section(_ name: String) { print("• \(name)") }

func testRequestContext(action: String = "get", key: String = "svc/api_key", scope: String? = nil) -> RequestContext {
  RequestContext(
    action: action,
    key: key,
    sessionName: scope == nil ? nil : "deploy",
    scope: scope,
    reason: "nightly deploy",
    ttl: 300,
    chain: [],
    workingDirectory: "/tmp/work dir"
  )
}

// MARK: - Encoding helpers

section("base64url and short codes")
do {
  let bytes = Data([0xfb, 0xff, 0x00, 0x3e, 0x3f])
  check(bytes.base64URL == "-_8APj8", "base64url encoding: \(bytes.base64URL)")
  check(Data(base64URL: "-_8APj8") == bytes, "base64url decoding")
  check(Data(base64URL: "not base64!") == nil, "invalid base64url is rejected")
  check(shortCode(Data([0xab, 0xcd, 0xef, 0x01, 0x23]), bytes: 4) == "abcd-ef01", "short code grouping")
}

// MARK: - Allowlist

section("allowlist")
do {
  let list = ["exact_key", "fidelity_scraper_*", "*"]
  check(allowlistCovers(list, key: "exact_key", scope: nil), "exact entry covers its key")
  check(!allowlistCovers(list, key: "exact_key_2", scope: nil), "exact entry doesn't cover a longer key")
  check(allowlistCovers(list, key: "fidelity_scraper_pw", scope: nil), "prefix entry covers a key")
  check(allowlistCovers(list, key: "fidelity_scraper_pw", scope: "fidelity_scraper_"), "prefix entry covers an equal scope")
  check(allowlistCovers(list, key: "fidelity_scraper_pw", scope: "fidelity_scraper_p"), "prefix entry covers a narrower scope")
  check(!allowlistCovers(list, key: "fidelity_scraper_pw", scope: "fidelity_"), "prefix entry doesn't cover a wider scope")
  check(!allowlistCovers(["exact_key"], key: "exact_key", scope: "exact"), "exact entry never covers a scope")
  check(!allowlistCovers(["*"], key: "anything", scope: nil), "a bare * covers nothing")
  check(!allowlistCovers(["keymaster_*"], key: "keymaster_remote_config", scope: nil), "reserved key is never covered")
  check(!allowlistCovers(["keymaster_*"], key: "keymaster_other", scope: "keymaster_"), "scope covering reserved keys is refused")
  check(!allowlistCovers([hmacKeyName], key: hmacKeyName, scope: nil), "HMAC key is never covered")
  check(prefixCoversReserved("keymaster_"), "keymaster_ covers reserved keys")
  check(prefixCoversReserved("keymaster_remote_x"), "a prefix inside the reserved namespace is reserved")
  check(!prefixCoversReserved("fidelity_"), "unrelated prefix isn't reserved")
}

// MARK: - Relay URL and config

section("relay URL and config")
do {
  check(validRelayURL("https://approve.example.com") != nil, "https URL is valid")
  check(validRelayURL("http://localhost:8080") != nil, "http localhost is valid")
  check(validRelayURL("http://approve.example.com") == nil, "plain http elsewhere is refused")
  check(validRelayURL("https://approve.example.com/?x=1") == nil, "query is refused")
  let config = RemoteConfig(relayURL: "https://approve.example.com:8443/base", relayToken: "t", pushoverToken: nil, pushoverUser: nil)
  check(config.rpId == "approve.example.com", "rpId is the host")
  check(config.origin == "https://approve.example.com:8443", "origin keeps a non-default port: \(config.origin ?? "nil")")
  check(!config.pushoverConfigured, "pushover off without keys")
}

section("pushover priority in config")
do {
  let old = try? JSONDecoder().decode(RemoteConfig.self, from: Data(#"{"relayURL":"https://a.example","relayToken":"t","pushoverToken":"p","pushoverUser":"u"}"#.utf8))
  check(old != nil && old?.pushoverPriority == nil, "config saved before priority existed still loads")
  check(old.map(pushoverSummary) == "on, priority 0", "missing priority reads as 0")
  var config = old!
  config.pushoverPriority = 1
  check(pushoverSummary(config) == "on, priority 1", "summary shows the priority")
  check(pushoverPriorities.contains(-2) && pushoverPriorities.contains(1) && !pushoverPriorities.contains(2), "priority range is -2 to 1")
}

// MARK: - Passkey labels and history

section("passkey labels")
do {
  check(uniqueLabel("phone", taken: []) == "phone", "free label is kept")
  check(uniqueLabel("phone", taken: ["phone"]) == "phone (2)", "taken label gets (2)")
  check(uniqueLabel("phone", taken: ["phone", "phone (2)"]) == "phone (3)", "and then (3)")
  let label = defaultEnrollLabel(taken: [], now: Date(timeIntervalSince1970: 1_800_000_000))
  check(label.hasPrefix("keymaster on \(localHostName()) 2027-01-1"), "default label has host and date: \(label)")
}

section("last approval per passkey from the audit log")
do {
  let dir = FileManager.default.temporaryDirectory.appendingPathComponent("km-log-\(UUID().uuidString)")
  try! FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: dir) }
  let rotated = dir.appendingPathComponent("keymaster.log.1").path
  let current = dir.appendingPathComponent("keymaster.log").path
  try! """
  {"ts":"2026-10-01T10:00:00Z","approval":"remote","outcome":"approved","credentialId":"A"}
  {"ts":"2026-10-02T10:00:00Z","approval":"remote","outcome":"approved","credentialId":"B"}
  """.write(toFile: rotated, atomically: true, encoding: .utf8)
  try! """
  {"ts":"2026-10-03T10:00:00Z","approval":"remote","outcome":"approved","credentialId":"A"}
  {"ts":"2026-10-04T10:00:00Z","approval":"remote","outcome":"denied","credentialId":"B"}
  {"ts":"2026-10-05T10:00:00Z","approval":"touchid","outcome":"approved"}
  not json
  """.write(toFile: current, atomically: true, encoding: .utf8)
  let history = lastRemoteApprovals(paths: [rotated, current])
  check(history.byCredential["A"] == "2026-10-03T10:00:00Z", "latest approval wins: \(history.byCredential)")
  check(history.byCredential["B"] == "2026-10-02T10:00:00Z", "denials don't count")
  check(history.byCredential.count == 2, "only remote approvals with an id")
  check(history.since == "2026-10-01T10:00:00Z", "since is the oldest entry")
  let empty = lastRemoteApprovals(paths: [dir.appendingPathComponent("missing").path])
  check(empty.byCredential.isEmpty && empty.since == nil, "missing log is empty")
}

// MARK: - Request encoding

section("request encoding")
do {
  let now = Date(timeIntervalSince1970: 1_800_000_000)
  let remote = makeApprovalRequest(for: testRequestContext(scope: "svc/"), lifetime: 120, now: now)
  let text = String(decoding: remote.bytes, as: UTF8.self)
  check(text.hasPrefix("{\"action\":\"get\",\"caller\":"), "keys are sorted: \(text.prefix(40))")
  check(!text.contains("\\/"), "slashes are not escaped")
  check(!text.contains(" :") && !text.contains(", "), "no insignificant whitespace")
  let fields = (try? JSONSerialization.jsonObject(with: remote.bytes)) as? [String: Any] ?? [:]
  check(fields["v"] as? Int == 1, "version 1")
  check(fields["kind"] as? String == "approve", "kind approve")
  check(fields["key"] as? String == "svc/api_key", "key")
  check(fields["scope"] as? String == "svc/", "scope")
  check(fields["session"] as? String == "deploy", "session")
  check(fields["reason"] as? String == "nightly deploy", "reason")
  check(fields["ttl"] as? Int == 300, "ttl")
  check(fields["caller"] as? String == "launchd", "caller")
  check(fields["iat"] as? Int == 1_800_000_000 && fields["exp"] as? Int == 1_800_000_120, "iat and exp")
  check((fields["id"] as? String)?.count == 22 && fields["id"] as? String == remote.id, "22-character id")
  check(remote.challenge == Data(SHA256.hash(data: remote.bytes)), "challenge is SHA-256 of the bytes")
  check(remote.expiry == now.addingTimeInterval(120), "expiry")
  let other = makeApprovalRequest(for: testRequestContext(scope: "svc/"), lifetime: 120, now: now)
  check(other.id != remote.id && other.challenge != remote.challenge, "each request gets a fresh id and challenge")

  let enroll = makeEnrollRequest(label: "phone", lifetime: 60, now: now)
  let enrollFields = (try? JSONSerialization.jsonObject(with: enroll.bytes)) as? [String: Any] ?? [:]
  check(enrollFields["kind"] as? String == "enroll" && enrollFields["label"] as? String == "phone", "enroll fields")
  check((enrollFields["userId"] as? String).flatMap { Data(base64URL: $0) }?.count == 16, "enroll user handle")
}

// MARK: - Verifier, with assertions signed here by CryptoKit

let origin = "https://approve.example.com"
let rpId = "approve.example.com"

struct FakeAuthenticator {
  let key = P256.Signing.PrivateKey()
  let credentialID = randomBytes(16)

  var enrolled: EnrolledCredential {
    EnrolledCredential(
      id: credentialID.base64URL,
      publicKey: key.publicKey.derRepresentation.base64URL,
      algorithm: -7,
      rpId: rpId,
      origin: origin,
      label: "test phone",
      created: 0
    )
  }

  func clientData(_ type: String, challenge: Data, origin: String = origin, extra: [String: Any] = [:]) -> Data {
    var fields: [String: Any] = ["type": type, "challenge": challenge.base64URL, "origin": origin]
    fields.merge(extra) { _, new in new }
    return try! JSONSerialization.data(withJSONObject: fields)
  }

  func authenticatorData(rpId: String = rpId, flags: UInt8 = 0x05) -> Data {
    Data(SHA256.hash(data: Data(rpId.utf8))) + Data([flags, 0, 0, 0, 0])
  }

  func assertion(
    for remote: RemoteRequest,
    type: String = "webauthn.get",
    origin: String = origin,
    rpId: String = rpId,
    flags: UInt8 = 0x05,
    clientExtra: [String: Any] = [:],
    signer: P256.Signing.PrivateKey? = nil
  ) -> [String: Any] {
    let client = clientData(type, challenge: remote.challenge, origin: origin, extra: clientExtra)
    let auth = authenticatorData(rpId: rpId, flags: flags)
    let signature = try! (signer ?? key).signature(for: auth + Data(SHA256.hash(data: client)))
    return [
      "type": "assertion",
      "credentialId": credentialID.base64URL,
      "authenticatorData": auth.base64URL,
      "clientDataJSON": client.base64URL,
      "signature": signature.derRepresentation.base64URL,
    ]
  }
}

section("assertion verification")
do {
  let phone = FakeAuthenticator()
  let credentials = [phone.enrolled]
  let remote = makeApprovalRequest(for: testRequestContext(), lifetime: 60)

  let verified = try? verifyAssertion(phone.assertion(for: remote), for: remote, credentials: credentials)
  check(verified == phone.enrolled, "a good assertion verifies")

  let other = makeApprovalRequest(for: testRequestContext(), lifetime: 60)
  expectThrows("challenge") { _ = try verifyAssertion(phone.assertion(for: other), for: remote, credentials: credentials) }
  expectThrows("not enrolled") { _ = try verifyAssertion(phone.assertion(for: remote), for: remote, credentials: []) }
  expectThrows("type") { _ = try verifyAssertion(phone.assertion(for: remote, type: "webauthn.create"), for: remote, credentials: credentials) }
  expectThrows("origin") { _ = try verifyAssertion(phone.assertion(for: remote, origin: "https://evil.example"), for: remote, credentials: credentials) }
  expectThrows("relying party") { _ = try verifyAssertion(phone.assertion(for: remote, rpId: "evil.example"), for: remote, credentials: credentials) }
  expectThrows("user verification") { _ = try verifyAssertion(phone.assertion(for: remote, flags: 0x01), for: remote, credentials: credentials) }
  expectThrows("user presence") { _ = try verifyAssertion(phone.assertion(for: remote, flags: 0x04), for: remote, credentials: credentials) }
  expectThrows("cross-origin") { _ = try verifyAssertion(phone.assertion(for: remote, clientExtra: ["crossOrigin": true]), for: remote, credentials: credentials) }
  expectThrows("does not verify") { _ = try verifyAssertion(phone.assertion(for: remote, signer: P256.Signing.PrivateKey()), for: remote, credentials: credentials) }
  expectThrows("expired") {
    _ = try verifyAssertion(phone.assertion(for: remote), for: remote, credentials: credentials, now: remote.expiry)
  }

  var tampered = phone.assertion(for: remote)
  tampered["authenticatorData"] = phone.authenticatorData(flags: 0x05 | 0x08).base64URL
  expectThrows("does not verify") { _ = try verifyAssertion(tampered, for: remote, credentials: credentials) }
  var noSignature = phone.assertion(for: remote)
  noSignature["signature"] = nil
  expectThrows("missing signature") { _ = try verifyAssertion(noSignature, for: remote, credentials: credentials) }
  var notAssertion = phone.assertion(for: remote)
  notAssertion["type"] = "credential"
  expectThrows("not an assertion") { _ = try verifyAssertion(notAssertion, for: remote, credentials: credentials) }

  // Another enrolled passkey's origin is checked against that passkey's own
  // record, not the config.
  let second = FakeAuthenticator()
  let both = credentials + [second.enrolled]
  check((try? verifyAssertion(second.assertion(for: remote), for: remote, credentials: both)) == second.enrolled, "the signing passkey is picked by credential id")
}

section("enrollment verification")
do {
  let phone = FakeAuthenticator()
  let enroll = makeEnrollRequest(label: "test phone", lifetime: 60)

  func credentialResponse(
    type: String = "webauthn.create",
    reportedID: Data? = nil,
    publicKey: Data? = nil,
    algorithm: Int = -7,
    flags: UInt8 = 0x45
  ) -> [String: Any] {
    var auth = phone.authenticatorData(flags: flags)
    auth += Data(count: 16)
    auth += Data([0, UInt8(phone.credentialID.count)])
    auth += phone.credentialID
    auth += Data([0xa0])
    return [
      "type": "credential",
      "credentialId": (reportedID ?? phone.credentialID).base64URL,
      "publicKey": (publicKey ?? phone.key.publicKey.derRepresentation).base64URL,
      "publicKeyAlgorithm": algorithm,
      "authenticatorData": auth.base64URL,
      "clientDataJSON": phone.clientData(type, challenge: enroll.challenge).base64URL,
    ]
  }

  let enrolled = try? verifyEnrollment(credentialResponse(), for: enroll, rpId: rpId, origin: origin, label: "test phone")
  check(enrolled?.id == phone.credentialID.base64URL, "enrollment returns the credential id")
  check(enrolled?.publicKey == phone.key.publicKey.derRepresentation.base64URL, "enrollment stores the SPKI key")
  check(enrolled?.fingerprint.count == 19, "fingerprint is four groups of four: \(enrolled?.fingerprint ?? "nil")")
  expectThrows("type") { _ = try verifyEnrollment(credentialResponse(type: "webauthn.get"), for: enroll, rpId: rpId, origin: origin, label: "x") }
  expectThrows("does not match authenticatorData") {
    _ = try verifyEnrollment(credentialResponse(reportedID: randomBytes(16)), for: enroll, rpId: rpId, origin: origin, label: "x")
  }
  expectThrows("ES256") { _ = try verifyEnrollment(credentialResponse(algorithm: -8), for: enroll, rpId: rpId, origin: origin, label: "x") }
  expectThrows("P-256") { _ = try verifyEnrollment(credentialResponse(publicKey: Data("junk".utf8)), for: enroll, rpId: rpId, origin: origin, label: "x") }
  expectThrows("attested credential") { _ = try verifyEnrollment(credentialResponse(flags: 0x05), for: enroll, rpId: rpId, origin: origin, label: "x") }
  expectThrows("user verification") { _ = try verifyEnrollment(credentialResponse(flags: 0x41), for: enroll, rpId: rpId, origin: origin, label: "x") }
  expectThrows("origin") { _ = try verifyEnrollment(credentialResponse(), for: enroll, rpId: rpId, origin: "https://other.example", label: "x") }
}

// MARK: - QR code

section("terminal QR code")
do {
  let url = "https://approve.example.com/r/AAAAAAAAAAAAAAAAAAAAAA"
  if let text = qrCodeText(url) {
    // Turn the half-block cells back into modules and let CoreImage read it.
    var rows: [[Bool]] = []
    for line in text.split(separator: "\n") {
      var top: [Bool] = []
      var bottom: [Bool] = []
      let pattern = try! NSRegularExpression(pattern: "\u{1b}\\[(\\d+);(\\d+)m▀")
      let ns = String(line) as NSString
      for match in pattern.matches(in: String(line), range: NSRange(location: 0, length: ns.length)) {
        top.append(ns.substring(with: match.range(at: 1)) == "30")
        bottom.append(ns.substring(with: match.range(at: 2)) == "40")
      }
      rows.append(top)
      rows.append(bottom)
    }
    let scale = 8
    let height = rows.count * scale
    let width = (rows.first?.count ?? 0) * scale
    var pixels = [UInt8](repeating: 255, count: width * height)
    for (y, row) in rows.enumerated() {
      for (x, isDark) in row.enumerated() where isDark {
        for dy in 0..<scale {
          for dx in 0..<scale { pixels[(y * scale + dy) * width + x * scale + dx] = 0 }
        }
      }
    }
    let provider = CGDataProvider(data: Data(pixels) as CFData)!
    let image = CGImage(
      width: width, height: height, bitsPerComponent: 8, bitsPerPixel: 8, bytesPerRow: width,
      space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGBitmapInfo(rawValue: 0),
      provider: provider, decode: nil, shouldInterpolate: false, intent: .defaultIntent
    )!
    let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: nil)
    let decoded = detector?.features(in: CIImage(cgImage: image)).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
    check(decoded == [url], "terminal QR decodes to the URL: \(decoded ?? [])")
  } else {
    check(false, "QR generation failed")
  }
}

// MARK: - The real page in headless Chrome

// Drive Tests/browser-phone.mjs: one line in per page, one JSON line out.
final class BrowserPhone {
  let process = Process()
  let input = Pipe()
  let output = Pipe()
  var buffer = Data()

  init(script: String) {
    process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
    process.arguments = ["node", script]
    process.standardInput = input
    process.standardOutput = output
    try! process.run()
  }

  func open(_ action: String, _ url: URL) {
    input.fileHandleForWriting.write(Data("\(action) \(url.absoluteString)\n".utf8))
  }

  func readResult() -> [String: Any] {
    while !buffer.contains(UInt8(ascii: "\n")) {
      let chunk = output.fileHandleForReading.availableData
      if chunk.isEmpty { return [:] }
      buffer += chunk
    }
    let newline = buffer.firstIndex(of: UInt8(ascii: "\n"))!
    let line = buffer[buffer.startIndex..<newline]
    buffer = Data(buffer[(newline + 1)...])
    return (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] ?? [:]
  }

  func close() {
    try? input.fileHandleForWriting.close()
    process.waitUntilExit()
  }
}

func browserTests(script: String, port: Int, token: String) {
  section("integration: approval page in headless Chrome")
  // WebAuthn needs a hostname, so the browser reaches the relay as localhost.
  let base = URL(string: "http://localhost:\(port)")!
  let client = RelayClient(baseURL: base, token: token)
  let config = RemoteConfig(relayURL: base.absoluteString, relayToken: token, pushoverToken: nil, pushoverUser: nil)
  let phone = BrowserPhone(script: script)
  defer { phone.close() }

  let enroll = makeEnrollRequest(label: "browser", lifetime: 60)
  try? client.create(enroll)
  phone.open("approve", client.pageURL(for: enroll))
  var credential: EnrolledCredential? = nil
  if case .responded(let response) = client.waitForResult(enroll) {
    do {
      credential = try verifyEnrollment(response, for: enroll, rpId: config.rpId!, origin: config.origin!, label: "browser")
    } catch {
      check(false, "browser enrollment rejected: \(error)")
    }
  }
  let enrollPage = phone.readResult()
  check(credential != nil, "browser enrollment verifies (page: \(enrollPage))")
  let fields = enrollPage["fields"] as? [String: String] ?? [:]
  check(fields["Key fingerprint"] == credential?.fingerprint, "page and keymaster show the same fingerprint")
  check(fields["Request code"] == enroll.code, "page shows keymaster's request code")
  check(enrollPage["closeRequested"] as? Bool == false, "enrollment page stays open")
  let credentials = credential.map { [$0] } ?? []

  let context = RequestContext(
    action: "get", key: "svc/<b>key</b>", sessionName: "deploy", scope: "svc/", reason: "<img src=x onerror=alert(1)>",
    ttl: 300, chain: [], workingDirectory: "/tmp"
  )
  let approve = makeApprovalRequest(for: context, lifetime: 60)
  try? client.create(approve)
  phone.open("approve", client.pageURL(for: approve))
  if case .responded(let response) = client.waitForResult(approve) {
    do {
      let signer = try verifyAssertion(response, for: approve, credentials: credentials)
      check(signer == credential, "assertion from the page verifies")
    } catch {
      check(false, "assertion from the page rejected: \(error)")
    }
  } else {
    check(false, "page did not answer the approval request")
  }
  let approvePage = phone.readResult()
  let approveFields = approvePage["fields"] as? [String: String] ?? [:]
  check(approvePage["title"] as? String == "Read “svc/<b>key</b>”", "page title names the key as text: \(approvePage["title"] ?? "nil")")
  check(approveFields["Reason given by the caller"] == "<img src=x onerror=alert(1)>", "reason is rendered as text")
  check(approveFields["Also allows"]?.contains("“svc/”") == true, "page shows the scope")
  check(approveFields["Request code"] == approve.code, "page shows keymaster's request code")
  check(approvePage["closeRequested"] as? Bool == true, "page closes itself after approving")

  let deny = makeApprovalRequest(for: context, lifetime: 60)
  try? client.create(deny)
  phone.open("deny", client.pageURL(for: deny))
  if case .denied = client.waitForResult(deny) {
    check(true, "")
  } else {
    check(false, "deny on the page was not reported as denied")
  }
  let denyPage = phone.readResult()
  check(denyPage["closeRequested"] as? Bool == true, "page closes itself after denying")
  check(denyPage["status"] as? String == "Denied. You can close this tab.", "page shows the deny, then that the close was refused")
}

// MARK: - Integration with a real relay and the Go fake phone

func runProcess(_ path: String, _ args: [String], env: [String: String] = [:]) -> Process {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: path)
  process.arguments = args
  process.environment = ProcessInfo.processInfo.environment.merging(env) { _, new in new }
  try! process.run()
  return process
}

func fakePhone(_ relay: URL, _ remote: RemoteRequest, mode: String, keyFile: String, tamper: String? = nil, after delay: TimeInterval = 0) -> Process {
  var args = ["-relay", relay.absoluteString, "-id", remote.id, "-key", keyFile, "-mode", mode]
  if let tamper = tamper { args += ["-tamper", tamper] }
  let path = ProcessInfo.processInfo.environment["KM_FAKEPHONE"]!
  if delay > 0 {
    return runProcess("/bin/sh", ["-c", "sleep \(delay); exec \"$0\" \"$@\"", path] + args)
  }
  return runProcess(path, args)
}

if let relayBinary = ProcessInfo.processInfo.environment["KM_RELAY"], ProcessInfo.processInfo.environment["KM_FAKEPHONE"] != nil {
  section("integration: relay + fake phone")
  let port = 20000 + Int.random(in: 0..<20000)
  let token = randomBytes(24).base64URL
  let relay = runProcess(relayBinary, ["-listen", "127.0.0.1:\(port)"], env: ["RELAY_TOKEN": token])
  defer { relay.terminate() }
  let base = URL(string: "http://127.0.0.1:\(port)")!
  let client = RelayClient(baseURL: base, token: token)
  for _ in 0..<50 {
    if (try? blockingRequest(URLRequest(url: base.appendingPathComponent("healthz"))))?.1.statusCode == 200 { break }
    Thread.sleep(forTimeInterval: 0.1)
  }
  let config = RemoteConfig(relayURL: base.absoluteString, relayToken: token, pushoverToken: nil, pushoverUser: nil)
  let keyFile = NSTemporaryDirectory() + "keymaster-test-\(port).json"
  defer { try? FileManager.default.removeItem(atPath: keyFile) }

  // Enroll a passkey. The phone answers after keymaster starts waiting, so
  // the long-poll has to wake.
  let enroll = makeEnrollRequest(label: "fake phone", lifetime: 60)
  try? client.create(enroll)
  _ = fakePhone(base, enroll, mode: "enroll", keyFile: keyFile, after: 1)
  var credential: EnrolledCredential? = nil
  if case .responded(let response) = client.waitForResult(enroll) {
    credential = try? verifyEnrollment(response, for: enroll, rpId: config.rpId!, origin: config.origin!, label: "fake phone")
  }
  check(credential != nil, "enrollment through the relay verifies")
  let credentials = credential.map { [$0] } ?? []

  // Approve a request whose key and reason include characters JSON encoders
  // like to escape, to check the relay hands back the exact bytes.
  let context = RequestContext(
    action: "get", key: "a/b<c>&d \"é\"", sessionName: "s", scope: nil, reason: "line\nbreak ✓",
    ttl: 60, chain: [], workingDirectory: "/tmp"
  )
  let approve = makeApprovalRequest(for: context, lifetime: 60)
  try? client.create(approve)
  _ = fakePhone(base, approve, mode: "assert", keyFile: keyFile, after: 0.5)
  var approvedResponse: [String: Any]? = nil
  if case .responded(let response) = client.waitForResult(approve) {
    approvedResponse = response
    check((try? verifyAssertion(response, for: approve, credentials: credentials)) != nil, "assertion through the relay verifies")
  } else {
    check(false, "no response to the approval request")
  }

  // Replay: the old assertion against a new request.
  let next = makeApprovalRequest(for: context, lifetime: 60)
  if let old = approvedResponse {
    expectThrows("challenge") { _ = try verifyAssertion(old, for: next, credentials: credentials) }
  }

  // Each tampered response is rejected by the right check.
  let tampers = [
    ("challenge", "challenge"), ("origin", "origin"), ("rpid", "relying party"), ("uv", "user verification"),
    ("up", "user presence"), ("type", "type"), ("signature", "does not verify"), ("credential", "not enrolled"),
  ]
  for (tamper, expected) in tampers {
    let remote = makeApprovalRequest(for: context, lifetime: 60)
    try? client.create(remote)
    fakePhone(base, remote, mode: "assert", keyFile: keyFile, tamper: tamper).waitUntilExit()
    if case .responded(let response) = client.waitForResult(remote) {
      expectThrows(expected) { _ = try verifyAssertion(response, for: remote, credentials: credentials) }
    } else {
      check(false, "no response for tamper \(tamper)")
    }
  }

  // A deny comes back as a deny.
  let denied = makeApprovalRequest(for: context, lifetime: 60)
  try? client.create(denied)
  _ = fakePhone(base, denied, mode: "deny", keyFile: keyFile, after: 0.5)
  if case .denied = client.waitForResult(denied) {
    check(true, "")
  } else {
    check(false, "deny was not reported as denied")
  }

  // Nobody answers: keymaster stops waiting at expiry.
  let unanswered = makeApprovalRequest(for: context, lifetime: 2)
  try? client.create(unanswered)
  let started = Date()
  if case .expired = client.waitForResult(unanswered) {
    check(Date().timeIntervalSince(started) < 10, "expiry ends the wait promptly")
  } else {
    check(false, "an unanswered request did not expire")
  }

  // A wrong token can't create requests.
  let stranger = RelayClient(baseURL: base, token: "wrong")
  expectThrows("401") { try stranger.create(makeApprovalRequest(for: context, lifetime: 60)) }

  // The relay only accepts the first answer.
  let once = makeApprovalRequest(for: context, lifetime: 60)
  try? client.create(once)
  fakePhone(base, once, mode: "deny", keyFile: keyFile).waitUntilExit()
  let second = fakePhone(base, once, mode: "assert", keyFile: keyFile)
  second.waitUntilExit()
  check(second.terminationStatus != 0, "a second answer is refused")

  if let script = ProcessInfo.processInfo.environment["KM_BROWSER_PHONE"], !script.isEmpty {
    browserTests(script: script, port: port, token: token)
  }
} else {
  print("• integration tests skipped (set KM_RELAY and KM_FAKEPHONE, or run ./test.sh)")
}

print(failures == 0 ? "ok: \(checks) checks" : "FAILED: \(failures) of \(checks) checks")
exit(failures == 0 ? 0 : 1)
