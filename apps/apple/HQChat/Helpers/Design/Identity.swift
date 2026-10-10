// The logo, wordmark, avatars and the key fingerprint glyph.

import SwiftUI
import CryptoKit

// MARK: - Logo mark

/// The hqchat 3×3 grid logo: a dark rounded tile with two lit cells
/// (green top-right, violet bottom-left) over soft brand glows.
struct HQLogoMark: View {
    var size: CGFloat = 56
    var lit: [Int: Color] = [2: HQColor.green, 6: HQColor.purple]   // 3×3 indices

    var body: some View {
        let corner = size * 0.21
        let cell = size * 0.62 / 3
        let gap = cell * 0.18
        ZStack {
            RoundedRectangle(cornerRadius: corner, style: .continuous)
                .fill(HQColor.screen)
                .overlay(
                    RoundedRectangle(cornerRadius: corner, style: .continuous)
                        .stroke(Color.white.opacity(0.06), lineWidth: 1)
                )
            // brand glows
            Circle().fill(RadialGradient(colors: [HQColor.green.opacity(0.7), .clear],
                                         center: .center, startRadius: 0, endRadius: size * 0.5))
                .frame(width: size, height: size)
                .blur(radius: size * 0.18)
                .offset(x: -size * 0.18, y: -size * 0.18)
            Circle().fill(RadialGradient(colors: [HQColor.purple.opacity(0.7), .clear],
                                         center: .center, startRadius: 0, endRadius: size * 0.5))
                .frame(width: size, height: size)
                .blur(radius: size * 0.18)
                .offset(x: size * 0.18, y: size * 0.18)

            LazyVGrid(columns: Array(repeating: GridItem(.fixed(cell), spacing: gap), count: 3), spacing: gap) {
                ForEach(0..<9, id: \.self) { i in
                    RoundedRectangle(cornerRadius: cell * 0.18)
                        .fill(lit[i] == nil ? Color.white.opacity(0.07) : Color.clear)
                        .overlay {
                            if let c = lit[i] {
                                RoundedRectangle(cornerRadius: cell * 0.18)
                                    .fill(RadialGradient(colors: [.white, c],
                                                         center: .init(x: 0.42, y: 0.36),
                                                         startRadius: 0, endRadius: cell))
                                    .shadow(color: c.opacity(0.9), radius: cell * 0.4)
                            }
                        }
                        .frame(width: cell, height: cell)
                }
            }
            .frame(width: cell * 3 + gap * 2, height: cell * 3 + gap * 2)
        }
        .frame(width: size, height: size)
    }
}

/// The "hq**chat**" wordmark (light "hq", bold "chat").
struct HQWordmark: View {
    var size: CGFloat = 34
    var body: some View {
        (Text("hq").fontWeight(.light) + Text("chat").fontWeight(.bold))
            .font(.system(size: size))
            .tracking(-1)
            .foregroundColor(.white)
    }
}

// MARK: - Avatar

/// A rounded-rect ("squircle") avatar showing a contact's initials over the
/// hqchat panel, with a brand glow and optional online dot. Used on the call
/// and chat screens.
struct HQAvatar: View {
    let name: String
    var size: CGFloat = 128
    var glow: Color = HQColor.purple
    var isOnline: Bool? = nil

    private var initials: String {
        let parts = name
            .replacingOccurrences(of: "_", with: " ")
            .replacingOccurrences(of: ".", with: " ")
            .split(separator: " ")
        let letters = parts.prefix(2).compactMap { $0.first }
        let s = String(letters).uppercased()
        return s.isEmpty ? "?" : s
    }

    var body: some View {
        let corner = size * 0.17
        ZStack(alignment: .bottomTrailing) {
            RoundedRectangle(cornerRadius: corner, style: .continuous)
                .fill(HQColor.panel)
                .overlay(
                    RoundedRectangle(cornerRadius: corner, style: .continuous)
                        .fill(RadialGradient(colors: [glow.opacity(0.5), .clear],
                                             center: .init(x: 0.5, y: 0.4),
                                             startRadius: 0, endRadius: size * 0.7))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: corner, style: .continuous)
                        .stroke(Color.white.opacity(0.08), lineWidth: 1)
                )
                .overlay(
                    Text(initials)
                        .font(.system(size: size * 0.34, weight: .semibold))
                        .foregroundColor(.white)
                )
                .frame(width: size, height: size)
                .shadow(color: glow.opacity(0.6), radius: size * 0.35, y: 4)

            if let isOnline {
                Circle()
                    .fill(isOnline ? HQColor.green : Color.gray)
                    .frame(width: size * 0.18, height: size * 0.18)
                    .overlay(Circle().stroke(HQColor.screen, lineWidth: size * 0.03))
                    .shadow(color: (isOnline ? HQColor.green : .clear).opacity(0.8), radius: 6)
                    .offset(x: -size * 0.04, y: -size * 0.04)
            }
        }
        .frame(width: size, height: size)
    }
}

/// Short display fingerprint of a public key (e.g. "7f3a 9c21 ee04 b8d3").
enum HQFingerprint {
    static func short(_ publicKey: Data) -> String {
        let hash = Array(SHA256.hash(data: publicKey)).prefix(8)
        let hex = hash.map { String(format: "%02x", $0) }.joined()
        return stride(from: 0, to: hex.count, by: 4).map {
            let start = hex.index(hex.startIndex, offsetBy: $0)
            let end = hex.index(start, offsetBy: 4)
            return String(hex[start..<end])
        }.joined(separator: " ")
    }
}
