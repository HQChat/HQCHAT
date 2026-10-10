// The palette, type scale and tap-target size every screen draws with.

import SwiftUI
#if os(iOS)
import UIKit
#endif

// MARK: - Color palette

/// The hqchat palette. Names map to the mockup tokens.
enum HQColor {
    // Surfaces
    static let bgTop      = Color(hex: 0x101116)
    static let bgBottom   = Color(hex: 0x16171d)
    static let screen     = Color(hex: 0x070809)   // the "phone screen" black
    static let panel      = Color(hex: 0x0a0b10)

    // Brand greens
    static let green       = Color(hex: 0x16c46e)
    static let greenBright = Color(hex: 0x1bd676)
    static let greenDeep   = Color(hex: 0x0f7d49)

    // Brand violets
    static let purple      = Color(hex: 0x7b2ff7)
    static let purpleLight = Color(hex: 0xa06bff)

    // Warning / caution
    static let warning     = Color(hex: 0xffb23b)

    // Danger
    static let danger      = Color(hex: 0xff5a3c)
    static let dangerLight = Color(hex: 0xff8a72)

    // Text. Every step clears WCAG AA for body text (4.5:1) against `bgTop`
    // (0x101116) and the standard card fill.
    static let textPrimary = Color(hex: 0xeef0f3)   // 16.5:1
    static let textSecond  = Color(hex: 0x9a9ca6)   //  6.9:1
    static let textMuted   = Color(hex: 0x83858f)   //  5.1:1
    static let textDim     = Color(hex: 0x8b8d96)   //  5.6:1
    static let textFaint   = Color(hex: 0x83858f)   //  5.1:1

    /// Dark ink for text sitting *on* a brand-green fill (primary buttons,
    /// unread pills, accept).
    static let onGreen     = Color(hex: 0x06140c)
    /// Body text one step below primary, on cards.
    static let textOnCard  = Color(hex: 0xcdcfd6)
    /// A disabled control's label.
    static let textOff     = Color(hex: 0x4a4b52)
    /// Message text inside an outgoing (green) bubble, and inside an incoming one.
    static let inkOnGreenBubble = Color(hex: 0xeafff4)
    static let inkOnGreyBubble  = Color(hex: 0xdfe1e8)

    // Hairlines / fills
    static let hairline    = Color.white.opacity(0.08)
    static let fillSoft     = Color.white.opacity(0.04)
}

extension Color {
    /// Hex literal initializer, e.g. `Color(hex: 0x16c46e)`.
    init(hex: UInt32, alpha: Double = 1) {
        self.init(
            .sRGB,
            red:   Double((hex >> 16) & 0xff) / 255,
            green: Double((hex >> 8) & 0xff) / 255,
            blue:  Double(hex & 0xff) / 255,
            opacity: alpha
        )
    }
}

// MARK: - Typography

/// Type, in two voices: monospace for anything machine-ish (keys, timestamps,
/// status, prompts) and a UI sans for prose.
///
/// Sizes are the design's points at the default text size, scaled by the
/// reader's Dynamic Type setting. `UIFontMetrics` reads the current
/// content-size category rather than the SwiftUI environment, so the root view
/// keys itself on `dynamicTypeSize` (see ContentView) to rebuild on change.
enum HQFont {
    /// Monospace machine label (SF Mono substitute for JetBrains Mono).
    static func mono(_ size: CGFloat, weight: Font.Weight = .medium) -> Font {
        .system(size: scaled(size), weight: weight, design: .monospaced)
    }
    /// UI text (SF Pro substitute for Hanken Grotesk).
    static func ui(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        .system(size: scaled(size), weight: weight)
    }

    /// A design point size, scaled for the reader. Also the way to scale a
    /// *frame* that has to keep pace with the text inside it.
    static func scaled(_ size: CGFloat) -> CGFloat {
        #if os(iOS)
        return UIFontMetrics.default.scaledValue(for: size)
        #else
        return size
        #endif
    }
}

// MARK: - Tap targets

extension View {
    /// Grow the hit area to Apple's 44×44 minimum without growing the artwork.
    /// Icon-only controls in this app were drawn at 30–38pt, which looks right
    /// and misses often.
    func hqTapTarget(_ side: CGFloat = 44) -> some View {
        frame(minWidth: side, minHeight: side)
            .contentShape(Rectangle())
    }
}
