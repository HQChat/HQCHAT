// The screen backdrop and the card surface.

import SwiftUI

// MARK: - Screen background

/// The full hqchat backdrop: vertical gradient, two blurred bokeh glows
/// (green + violet), scanlines and a vignette. Drop behind any screen with
/// `.hqScreenBackground()`.
struct HQScreenBackground: View {
    var animated: Bool = true
    /// Four animations in this app ran `repeatForever` with nothing to turn
    /// them off. Perpetual motion is exactly what Reduce Motion is for.
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var pulse = false

    var body: some View {
        ZStack {
            LinearGradient(colors: [HQColor.bgTop, HQColor.bgBottom],
                           startPoint: .top, endPoint: .bottom)

            GeometryReader { geo in
                let w = geo.size.width
                let h = geo.size.height
                ZStack {
                    bokeh(HQColor.green)
                        .frame(width: w * 1.1, height: w * 1.1)
                        .position(x: w * 0.12, y: h * 0.08)
                        .scaleEffect(pulse ? 1.08 : 1)
                    bokeh(HQColor.purple)
                        .frame(width: w * 1.1, height: w * 1.1)
                        .position(x: w * 0.92, y: h * 0.95)
                        .scaleEffect(pulse ? 1.05 : 1)
                }
                .blur(radius: 90)
                .opacity(0.42)
            }

            Scanlines()
                .opacity(0.62)
                .blendMode(.multiply)
                .allowsHitTesting(false)

            // Vignette
            RadialGradient(colors: [.clear, .black.opacity(0.65)],
                           center: .center, startRadius: 120, endRadius: 520)
                .allowsHitTesting(false)
        }
        .ignoresSafeArea()
        .onAppear {
            guard animated, !reduceMotion else { return }
            withAnimation(.easeInOut(duration: 11).repeatForever(autoreverses: true)) {
                pulse = true
            }
        }
    }

    private func bokeh(_ color: Color) -> some View {
        Circle().fill(
            RadialGradient(colors: [color, color.opacity(0)],
                           center: .center, startRadius: 0, endRadius: 220)
        )
    }
}

/// Lightweight repeating scanline texture drawn with a Canvas (static, cheap).
struct Scanlines: View {
    var body: some View {
        Canvas { ctx, size in
            var y: CGFloat = 0
            let line = Color.black.opacity(0.30)
            while y < size.height {
                ctx.fill(Path(CGRect(x: 0, y: y, width: size.width, height: 1)),
                         with: .color(line))
                y += 3
            }
        }
        .allowsHitTesting(false)
    }
}

extension View {
    /// Places the hqchat backdrop behind this view and forces dark text colors.
    func hqScreenBackground(animated: Bool = true) -> some View {
        self.background(HQScreenBackground(animated: animated))
            .foregroundColor(HQColor.textPrimary)
    }
}

// MARK: - Surface card

extension View {
    /// A standard hqchat surface panel: faint fill, hairline border.
    ///
    /// `accent` colours the border and adds a lit left rail. Settings uses one
    /// accent per section — identity, security, danger — so a screen of stacked
    /// grey cards stops reading as one undifferentiated wall.
    func hqCard(selected: Bool = false,
                cornerRadius: CGFloat = 0,
                padding: CGFloat = 14,
                accent: Color? = nil) -> some View {
        self
            .padding(padding)
            .background(selected ? HQColor.green.opacity(0.06)
                        : (accent?.opacity(0.05) ?? HQColor.fillSoft))
            .clipShape(RoundedRectangle(cornerRadius: cornerRadius))
            .overlay(alignment: .leading) {
                if let accent {
                    Rectangle()
                        .fill(accent)
                        .frame(width: 2)
                        .shadow(color: accent.opacity(0.7), radius: 4)
                }
            }
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius)
                    .stroke(selected ? HQColor.green.opacity(0.55)
                            : (accent?.opacity(0.40) ?? Color.white.opacity(0.08)), lineWidth: 1)
            )
    }
}
