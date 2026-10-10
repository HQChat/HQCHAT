// Blinks, glitches, swipe navigation and corner brackets.

import SwiftUI

// MARK: - Blink

/// Blinks a view's opacity.
struct BlinkModifier: ViewModifier {
    /// When false the content renders normally. Lets a caller keep the modifier
    /// in place while only some states should pulse.
    var active: Bool = true
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var on = true

    func body(content: Content) -> some View {
        content
            .opacity(active && !on ? 0.15 : 1)
            .onAppear {
                guard active, !reduceMotion else { return }
                withAnimation(.easeInOut(duration: 0.5).repeatForever(autoreverses: true)) {
                    on = false
                }
            }
    }
}

/// A one-shot flicker, fired when a value changes — the connection state
/// snapping between codes, rather than crossfading politely.
struct HQGlitch<V: Equatable>: ViewModifier {
    let value: V
    @State private var opacity: Double = 1

    func body(content: Content) -> some View {
        content
            .opacity(opacity)
            .onChange(of: value) { _, _ in
                opacity = 0.15
                withAnimation(.easeOut(duration: 0.28)) { opacity = 1 }
            }
    }
}

extension View {
    /// Flicker this view whenever `value` changes.
    func hqGlitch<V: Equatable>(on value: V) -> some View {
        modifier(HQGlitch(value: value))
    }
}

// MARK: - Swipe navigation

#if os(iOS)
/// Horizontal swipe as a way to move around, alongside the taps that already do
/// it. Before this, the only way between tabs was the tab bar and the only way
/// out of a conversation was the `[<]` glyph in its header — both fine, both a
/// reach on a large phone, and neither what a thumb tries first.
///
/// Deliberately conservative thresholds: the gesture is `simultaneous`, so it
/// runs alongside list scrolling and row swipe-actions rather than stealing from
/// them, and it only fires on a long, decidedly horizontal drag. A short or
/// diagonal drag belongs to whatever is underneath.
struct HQSwipeNavigation: ViewModifier {
    /// Swipe right — the "back" direction in every left-to-right iOS app.
    var onBack: (() -> Void)?
    /// Swipe left.
    var onForward: (() -> Void)?

    /// How far the finger must travel horizontally before this counts.
    private let distance: CGFloat = 90
    /// …and how little it may wander vertically, so a scroll is never mistaken
    /// for a swipe.
    private let drift: CGFloat = 55

    func body(content: Content) -> some View {
        content.simultaneousGesture(
            DragGesture(minimumDistance: 24, coordinateSpace: .local)
                .onEnded { value in
                    let dx = value.translation.width
                    let dy = value.translation.height
                    guard abs(dx) >= distance, abs(dy) <= drift, abs(dx) > abs(dy) * 2 else { return }
                    if dx > 0 { onBack?() } else { onForward?() }
                }
        )
    }
}

extension View {
    /// Swipe right / left to move between sibling screens, or out of this one.
    func hqSwipeNavigation(onBack: (() -> Void)? = nil,
                           onForward: (() -> Void)? = nil) -> some View {
        modifier(HQSwipeNavigation(onBack: onBack, onForward: onForward))
    }
}
#endif

// MARK: - Corner brackets (selected card)

/// Four neon corner brackets, as on the selected profile card.
struct CornerBrackets: View {
    var color: Color = HQColor.green
    var length: CGFloat = 11
    var thickness: CGFloat = 2

    var body: some View {
        GeometryReader { _ in
            ZStack {
                bracket(.topLeading)
                bracket(.topTrailing)
                bracket(.bottomLeading)
                bracket(.bottomTrailing)
            }
        }
        .allowsHitTesting(false)
    }

    private func bracket(_ corner: Alignment) -> some View {
        let isTop = corner == .topLeading || corner == .topTrailing
        let isLeading = corner == .topLeading || corner == .bottomLeading
        return ZStack(alignment: corner) {
            Color.clear
            VStack {
                if !isTop { Spacer(minLength: 0) }
                HStack {
                    if !isLeading { Spacer(minLength: 0) }
                    Path { p in
                        // horizontal arm
                        p.move(to: CGPoint(x: isLeading ? 0 : length, y: isTop ? 0 : thickness))
                        p.addLine(to: CGPoint(x: isLeading ? length : 0, y: isTop ? 0 : thickness))
                    }
                    .stroke(color, lineWidth: thickness)
                    .frame(width: length, height: length)
                    .overlay(
                        Path { p in
                            p.move(to: CGPoint(x: isLeading ? thickness : length - thickness, y: isTop ? 0 : length))
                            p.addLine(to: CGPoint(x: isLeading ? thickness : length - thickness, y: isTop ? length : 0))
                        }
                        .stroke(color, lineWidth: thickness)
                    )
                    if isLeading { Spacer(minLength: 0) }
                }
                if isTop { Spacer(minLength: 0) }
            }
        }
    }
}

extension View {
    /// Overlays neon corner brackets (selected state).
    func hqCornerBrackets(_ color: Color = HQColor.green, show: Bool = true) -> some View {
        overlay { if show { CornerBrackets(color: color) } }
    }
}
