import CryptoKit
import Foundation

// One enrolled passkey. rpId and origin are stored with the key, so changing
// the relay URL in the config can't change what an assertion is checked
// against.
struct EnrolledCredential: Codable, Equatable {
  let id: String
  let publicKey: String
  let algorithm: Int
  let rpId: String
  let origin: String
  let label: String
  let created: Int

  var fingerprint: String {
    shortCode(Data(SHA256.hash(data: Data(base64URL: publicKey) ?? Data())), bytes: 8)
  }
}

struct VerifyError: Error, CustomStringConvertible {
  let description: String
  init(_ description: String) { self.description = description }
}

let coseES256 = -7

// authenticatorData flags (WebAuthn §6.1).
let flagUserPresent: UInt8 = 0x01
let flagUserVerified: UInt8 = 0x04
let flagAttestedCredential: UInt8 = 0x40

func requireField(_ response: [String: Any], _ name: String) throws -> Data {
  guard let text = response[name] as? String, let data = Data(base64URL: text), !data.isEmpty else {
    throw VerifyError("response is missing \(name)")
  }
  return data
}

// Checks shared by enrollment and approval: the client data names the right
// ceremony, challenge and origin, and the authenticator data names the right
// RP with both user presence and user verification.
func checkClientAndAuthenticatorData(
  clientDataJSON: Data,
  authenticatorData: Data,
  type: String,
  challenge: Data,
  rpId: String,
  origin: String
) throws {
  guard let clientData = try? JSONSerialization.jsonObject(with: clientDataJSON) as? [String: Any] else {
    throw VerifyError("clientDataJSON is not a JSON object")
  }
  guard clientData["type"] as? String == type else {
    throw VerifyError("clientDataJSON type is not \(type)")
  }
  guard let sentChallenge = (clientData["challenge"] as? String).flatMap({ Data(base64URL: $0) }),
        sentChallenge == challenge else {
    throw VerifyError("signed challenge does not match this request")
  }
  guard clientData["origin"] as? String == origin else {
    throw VerifyError("origin \(clientData["origin"] ?? "none") is not \(origin)")
  }
  if clientData["crossOrigin"] as? Bool == true {
    throw VerifyError("ceremony ran in a cross-origin frame")
  }
  guard authenticatorData.count >= 37 else {
    throw VerifyError("authenticatorData is too short")
  }
  guard authenticatorData.prefix(32) == Data(SHA256.hash(data: Data(rpId.utf8))) else {
    throw VerifyError("authenticatorData is for a different relying party than \(rpId)")
  }
  let flags = authenticatorData[authenticatorData.startIndex + 32]
  guard flags & flagUserPresent != 0 else { throw VerifyError("user presence flag not set") }
  guard flags & flagUserVerified != 0 else { throw VerifyError("user verification flag not set") }
}

// Verify a WebAuthn assertion against the request keymaster holds in memory.
// Returns the credential that signed it. Every check must pass; see
// docs/remote-approval.md for why each one is there.
func verifyAssertion(
  _ response: [String: Any],
  for request: RemoteRequest,
  credentials: [EnrolledCredential],
  now: Date = Date()
) throws -> EnrolledCredential {
  guard response["type"] as? String == "assertion" else {
    throw VerifyError("response is not an assertion")
  }
  let credentialID = try requireField(response, "credentialId")
  let authenticatorData = try requireField(response, "authenticatorData")
  let clientDataJSON = try requireField(response, "clientDataJSON")
  let signatureDER = try requireField(response, "signature")

  guard let credential = credentials.first(where: { Data(base64URL: $0.id) == credentialID }) else {
    throw VerifyError("credential \(credentialID.base64URL) is not enrolled")
  }
  guard credential.algorithm == coseES256 else {
    throw VerifyError("credential \(credential.label) is not ES256")
  }
  try checkClientAndAuthenticatorData(
    clientDataJSON: clientDataJSON,
    authenticatorData: authenticatorData,
    type: "webauthn.get",
    challenge: request.challenge,
    rpId: credential.rpId,
    origin: credential.origin
  )
  guard let spki = Data(base64URL: credential.publicKey),
        let publicKey = try? P256.Signing.PublicKey(derRepresentation: spki) else {
    throw VerifyError("stored public key for \(credential.label) is unreadable")
  }
  guard let signature = try? P256.Signing.ECDSASignature(derRepresentation: signatureDER) else {
    throw VerifyError("signature is not DER-encoded ECDSA")
  }
  // ES256 signs SHA-256(authenticatorData || SHA-256(clientDataJSON));
  // isValidSignature(_:for:) applies the outer SHA-256.
  let signed = authenticatorData + Data(SHA256.hash(data: clientDataJSON))
  guard publicKey.isValidSignature(signature, for: signed) else {
    throw VerifyError("signature does not verify with \(credential.label)'s key")
  }
  guard now < request.expiry else {
    throw VerifyError("request expired before it was approved")
  }
  return credential
}

// Check a new passkey from enrollment. Apple passkeys use "none"
// attestation, so this can't prove the key lives on your phone; it checks the
// ceremony matches the enrollment request and the key is usable ES256.
func verifyEnrollment(
  _ response: [String: Any],
  for request: RemoteRequest,
  rpId: String,
  origin: String,
  label: String,
  now: Date = Date()
) throws -> EnrolledCredential {
  guard response["type"] as? String == "credential" else {
    throw VerifyError("response is not a new credential")
  }
  let credentialID = try requireField(response, "credentialId")
  let spki = try requireField(response, "publicKey")
  let authenticatorData = try requireField(response, "authenticatorData")
  let clientDataJSON = try requireField(response, "clientDataJSON")
  guard response["publicKeyAlgorithm"] as? Int == coseES256 else {
    throw VerifyError("passkey algorithm is not ES256")
  }
  guard (try? P256.Signing.PublicKey(derRepresentation: spki)) != nil else {
    throw VerifyError("public key is not a P-256 SubjectPublicKeyInfo")
  }
  try checkClientAndAuthenticatorData(
    clientDataJSON: clientDataJSON,
    authenticatorData: authenticatorData,
    type: "webauthn.create",
    challenge: request.challenge,
    rpId: rpId,
    origin: origin
  )
  // Attested credential data follows the 37-byte header: a 16-byte AAGUID, a
  // 2-byte big-endian length, then the credential ID. It must name the same
  // credential the page reported.
  let bytes = [UInt8](authenticatorData)
  guard bytes[32] & flagAttestedCredential != 0, bytes.count >= 55 else {
    throw VerifyError("authenticatorData has no attested credential")
  }
  let idLength = Int(bytes[53]) << 8 | Int(bytes[54])
  guard bytes.count >= 55 + idLength, Data(bytes[55..<55 + idLength]) == credentialID else {
    throw VerifyError("credential ID does not match authenticatorData")
  }
  guard now < request.expiry else {
    throw VerifyError("enrollment expired before it finished")
  }
  return EnrolledCredential(
    id: credentialID.base64URL,
    publicKey: spki.base64URL,
    algorithm: coseES256,
    rpId: rpId,
    origin: origin,
    label: label,
    created: Int(now.timeIntervalSince1970)
  )
}
