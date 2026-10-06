import Foundation

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
