import Foundation

extension Data {
    /// Lowercase hex.
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Bytes from hex; nil when `hexString` has an odd length or a non-hex character.
    init?(hexString: String) {
        guard hexString.count.isMultiple(of: 2) else { return nil }
        var data = Data(capacity: hexString.count / 2)
        var i = hexString.startIndex
        while i < hexString.endIndex {
            let j = hexString.index(i, offsetBy: 2)
            guard let byte = UInt8(hexString[i..<j], radix: 16) else { return nil }
            data.append(byte)
            i = j
        }
        self = data
    }
}
