import CoreImage
import Foundation

// Print a QR code for a URL so a phone camera can open it.
func printQRCode(_ text: String) {
  guard let code = qrCodeText(text) else { return }
  FileHandle.standardError.write(Data(code.utf8))
}

// Each character cell shows two modules with an upper half block, with
// colours set explicitly so the code scans on light and dark terminal themes
// alike.
func qrCodeText(_ text: String) -> String? {
  guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
  filter.setValue(Data(text.utf8), forKey: "inputMessage")
  filter.setValue("L", forKey: "inputCorrectionLevel")
  guard let image = filter.outputImage,
        let cgImage = CIContext().createCGImage(image, from: image.extent) else { return nil }
  let width = cgImage.width
  let height = cgImage.height
  // Draw into an 8-bit grey buffer. The context only borrows the buffer, so
  // it must not outlive withUnsafeMutableBytes.
  var pixels = [UInt8](repeating: 255, count: width * height)
  let drawn = pixels.withUnsafeMutableBytes { buffer -> Bool in
    guard let context = CGContext(
      data: buffer.baseAddress, width: width, height: height, bitsPerComponent: 8, bytesPerRow: width,
      space: CGColorSpaceCreateDeviceGray(), bitmapInfo: CGImageAlphaInfo.none.rawValue
    ) else { return false }
    context.draw(cgImage, in: CGRect(x: 0, y: 0, width: width, height: height))
    return true
  }
  guard drawn else { return nil }

  let quiet = 2
  func dark(_ x: Int, _ y: Int) -> Bool {
    let px = x - quiet
    let py = y - quiet
    guard px >= 0, py >= 0, px < width, py < height else { return false }
    return pixels[py * width + px] < 128
  }
  let black = 30
  let white = 37
  var output = ""
  for y in stride(from: 0, to: height + 2 * quiet, by: 2) {
    for x in 0..<(width + 2 * quiet) {
      let top = dark(x, y) ? black : white
      let bottom = dark(x, y + 1) ? black : white
      output += "\u{1b}[\(top);\(bottom + 10)m▀"
    }
    output += "\u{1b}[0m\n"
  }
  return output
}
