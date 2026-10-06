import Foundation

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
