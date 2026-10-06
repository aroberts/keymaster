import Foundation

// One process above keymaster. The executable path comes from the kernel
// (proc_pidpath) and can't be faked by a same-UID caller. argv is whatever the
// process set, so it is only used to name scripts run by an interpreter.
struct ProcessEntry {
  let pid: pid_t
  let path: String
  let argv: [String]

  var name: String { (path as NSString).lastPathComponent }
}

func executablePath(of pid: pid_t) -> String? {
  var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
  guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
  return String(cString: buffer)
}

func parentPID(of pid: pid_t) -> pid_t? {
  var info = proc_bsdinfo()
  let size = Int32(MemoryLayout<proc_bsdinfo>.size)
  guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
  return pid_t(info.pbi_ppid)
}

// Read argv via KERN_PROCARGS2: an argc word, the saved executable path, NUL
// padding, then argc NUL-terminated arguments. Fails for other users'
// processes, which is fine for display.
func arguments(of pid: pid_t) -> [String] {
  var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
  var size = 0
  guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return [] }
  var buffer = [UInt8](repeating: 0, count: size)
  guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return [] }
  let argc = Int(buffer.withUnsafeBytes { $0.loadUnaligned(as: Int32.self) })
  var index = MemoryLayout<Int32>.size
  while index < size && buffer[index] != 0 { index += 1 }
  while index < size && buffer[index] == 0 { index += 1 }
  var args: [String] = []
  while args.count < argc && index < size {
    let start = index
    while index < size && buffer[index] != 0 { index += 1 }
    args.append(String(decoding: buffer[start..<index], as: UTF8.self))
    index += 1
  }
  return args
}

// Walk from keymaster's parent up to (not including) launchd.
func processChain() -> [ProcessEntry] {
  var chain: [ProcessEntry] = []
  var pid = getppid()
  while pid > 1 && chain.count < 32 {
    guard let path = executablePath(of: pid) else { break }
    chain.append(ProcessEntry(pid: pid, path: path, argv: arguments(of: pid)))
    guard let parent = parentPID(of: pid), parent != pid else { break }
    pid = parent
  }
  return chain
}

let shellNames: Set<String> = ["sh", "bash", "zsh", "dash", "fish", "ksh", "tcsh", "csh"]
let interpreterPrefixes = ["python", "node", "ruby", "perl", "osascript", "bun", "deno"]
let hiddenProcessNames: Set<String> = ["login", "env"]

// A short name for one process in the prompt, or nil to leave it out.
// - A shell or interpreter running a script or module is named by that
//   script. With -c, or interactive, it adds nothing and is skipped.
// - An app bundle is named by the bundle ("Ghostty" for Ghostty.app).
// - A binary installed under a version number (Claude Code's
//   versions/2.1.290) is named by its argv[0].
func displayName(for entry: ProcessEntry) -> String? {
  let name = entry.name
  if hiddenProcessNames.contains(name) { return nil }
  let lowered = name.lowercased()
  let isShell = shellNames.contains(lowered)
  if isShell || interpreterPrefixes.contains(where: { lowered.hasPrefix($0) }) {
    for arg in entry.argv.dropFirst() {
      if arg.hasPrefix("-") {
        if arg == "-c" || (isShell && !arg.hasPrefix("--") && arg.contains("c")) { return nil }
        continue
      }
      return (arg as NSString).lastPathComponent
    }
    return nil
  }
  if let appRange = entry.path.range(of: ".app/Contents/MacOS/") {
    let bundlePath = String(entry.path[..<appRange.lowerBound])
    return ((bundlePath as NSString).lastPathComponent as NSString).deletingPathExtension
  }
  if !name.contains(where: \.isLetter), let argv0 = entry.argv.first {
    return (argv0 as NSString).lastPathComponent
  }
  return name
}

// "ansible-vault-keymaster ← ansible-playbook ← … ← tmux": the nearest
// callers, then the outermost one, which is usually the terminal, tmux, an
// app or a launchd job.
func summarizeChain(_ chain: [ProcessEntry]) -> String {
  var names: [String] = []
  for name in chain.compactMap(displayName) where names.last != name {
    names.append(name)
  }
  if names.isEmpty { return "launchd" }
  if names.count > 4 {
    names = Array(names.prefix(3)) + ["…", names.last!]
  }
  return names.map { sanitizeForPrompt($0, maxLength: 32) }.joined(separator: " ← ")
}

func abbreviateHome(_ path: String) -> String {
  let home = NSHomeDirectory()
  if path == home { return "~" }
  if path.hasPrefix(home + "/") { return "~" + path.dropFirst(home.count) }
  return path
}
