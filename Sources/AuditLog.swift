import Foundation

let auditLogPath = NSHomeDirectory() + "/Library/Logs/keymaster.log"
let auditLogMaxBytes: off_t = 1_000_000

// Append one JSON line per access to the audit log, so reads served from the
// cache, which never show a prompt, are still visible. The process chain is
// logged by executable path and display name only: ancestors' argv can hold
// whole command lines, including secrets. There is deliberately no setting to
// turn the log off or move it, since a caller could set that too.
func auditLog(_ request: RequestContext, outcome: String, error: String? = nil, extra: [String: Any] = [:]) {
  var record: [String: Any] = [
    "ts": ISO8601DateFormatter().string(from: Date()),
    "pid": Int(getpid()),
    "action": request.action,
    "key": request.key,
    "outcome": outcome,
    "caller": summarizeChain(request.chain),
    "cwd": request.workingDirectory,
    "chain": request.chain.map { entry -> [String: Any] in
      var item: [String: Any] = ["pid": Int(entry.pid), "path": entry.path]
      if let name = displayName(for: entry) { item["name"] = name }
      return item
    }
  ]
  if let sessionName = request.sessionName { record["session"] = sessionName }
  if let scope = request.scope { record["scope"] = scope }
  if let reason = request.reason { record["reason"] = reason }
  if outcome != "cached" && request.action == "get" { record["ttl"] = Int(request.ttl) }
  if let error = error { record["error"] = error }
  record.merge(extra) { current, _ in current }
  guard var line = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys, .withoutEscapingSlashes]) else {
    return
  }
  line.append(UInt8(ascii: "\n"))

  guard let fd = openAuditLog() else {
    debug("Could not open audit log \(auditLogPath)")
    return
  }
  _ = line.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
  flock(fd, LOCK_UN)
  close(fd)
}

// Open the audit log locked, rotating it to .1 once it passes the size cap.
// Another writer may rename the file between our open and our lock, so after
// locking, check the fd still refers to the file at the path, and retry if not.
// Without the check, a late writer would see the old oversized inode and
// rotate the fresh file over .1.
func openAuditLog() -> Int32? {
  for _ in 0..<5 {
    let fd = open(auditLogPath, O_WRONLY | O_APPEND | O_CREAT, 0o600)
    guard fd >= 0 else { return nil }
    flock(fd, LOCK_EX)
    var opened = stat()
    var current = stat()
    guard fstat(fd, &opened) == 0,
          stat(auditLogPath, &current) == 0,
          opened.st_ino == current.st_ino && opened.st_dev == current.st_dev else {
      flock(fd, LOCK_UN)
      close(fd)
      continue
    }
    if opened.st_size > auditLogMaxBytes {
      // Rename while holding the lock on the old file, then start over on a
      // fresh one. Writers waiting on the old file will fail the inode check.
      rename(auditLogPath, auditLogPath + ".1")
      flock(fd, LOCK_UN)
      close(fd)
      continue
    }
    return fd
  }
  return nil
}
