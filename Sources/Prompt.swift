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

func formatDuration(_ seconds: TimeInterval) -> String {
  let whole = Int(seconds)
  if whole < 120 { return "\(whole) seconds" }
  if whole < 7200 { return "\(Int((seconds / 60).rounded())) minutes" }
  return "\(Int((seconds / 3600).rounded())) hours"
}

// Build the TouchID reason string. It states what the gesture approves (the
// key, session and any scope), who asked (the process chain and directory,
// which keymaster reads itself), and why, as claimed by the caller. Each part
// is its own paragraph, because the dialog is narrow and a single paragraph
// reads as a block. Only keymaster adds line breaks: sanitizeForPrompt strips
// them from every value the caller supplies, so a caller can't start a line
// that reads as keymaster's.
func authReason(for request: RequestContext) -> String {
  var what = "\(request.verb) \"\(sanitizeForPrompt(request.key))\""
  if let sessionName = request.sessionName {
    what += " in session \"\(sanitizeForPrompt(sessionName))\""
  }
  var parts = [what]
  // A scoped approval is reused for other keys, so the prompt has to say which
  // ones. Only reads warm the cache, so the scope only applies to "get".
  if request.action == "get", let scope = request.scope {
    parts.append("Also allows reading keys starting with \"\(sanitizeForPrompt(scope))\" for \(formatDuration(request.ttl))")
  }
  parts.append("Requested by: \(summarizeChain(request.chain))")
  parts.append("In: \(sanitizeForPrompt(abbreviateHome(request.workingDirectory), maxLength: 48))")
  if let why = request.reason {
    parts.append("Reason given: \"\(sanitizeForPrompt(why, maxLength: 120))\"")
  }
  return parts.joined(separator: "\n\n")
}
