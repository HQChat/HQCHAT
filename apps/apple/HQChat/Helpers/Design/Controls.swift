// Button styles, form fields and the day separator.

import SwiftUI

// MARK: - Button styles

/// Solid green-gradient primary button (dark text).
struct HQPrimaryButtonStyle: ButtonStyle {
    var height: CGFloat = 48
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(HQFont.ui(15, weight: .bold))
            .foregroundColor(HQColor.onGreen)
            .frame(maxWidth: .infinity, minHeight: height)
            .background(LinearGradient(colors: [HQColor.greenBright, HQColor.greenDeep],
                                       startPoint: .topLeading, endPoint: .bottomTrailing))
            .clipShape(Rectangle())
            .overlay(Rectangle().stroke(HQColor.green.opacity(0.75), lineWidth: 1))
            .shadow(color: HQColor.green.opacity(0.5), radius: 14, y: 2)
            .opacity(configuration.isPressed ? 0.8 : 1)
    }
}

/// Outlined neutral button.
struct HQSecondaryButtonStyle: ButtonStyle {
    var tint: Color = HQColor.textPrimary
    var height: CGFloat = 44
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(HQFont.mono(13.5, weight: .semibold))
            .foregroundColor(tint)
            .frame(maxWidth: .infinity, minHeight: height)
            .background(Color.white.opacity(0.07))
            .clipShape(Rectangle())
            .overlay(Rectangle().stroke(Color.white.opacity(0.28), lineWidth: 1))
            .opacity(configuration.isPressed ? 0.7 : 1)
    }
}

/// Danger button (red). A destructive control has to be *seen* first and
/// hesitated over second: the old 6%-fill / 30%-border version read as disabled
/// text on the dark backdrop, so "delete my account" was nearly invisible.
struct HQDangerButtonStyle: ButtonStyle {
    var height: CGFloat = 44
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(HQFont.mono(13.5, weight: .bold))
            .foregroundColor(HQColor.dangerLight)
            .frame(maxWidth: .infinity, minHeight: height)
            .background(Color(hex: 0x3a0f0a))
            .clipShape(Rectangle())
            .overlay(Rectangle().stroke(HQColor.danger, lineWidth: 1))
            .opacity(configuration.isPressed ? 0.7 : 1)
    }
}

/// An inline action inside a card — the `[change]` next to your username. Bare
/// coloured text read as a label, not something you could press.
struct HQInlineActionStyle: ButtonStyle {
    var tint: Color = HQColor.green
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(HQFont.mono(12, weight: .bold))
            .foregroundColor(tint)
            .padding(.horizontal, 9)
            .padding(.vertical, 5)
            .background(tint.opacity(0.10))
            .overlay(Rectangle().stroke(tint.opacity(0.55), lineWidth: 1))
            .opacity(configuration.isPressed ? 0.6 : 1)
    }
}

// MARK: - Form field

/// A monospace section label (e.g. "PROFILE NAME") used above inputs. `tint`
/// carries the section's accent so a label and its card read as one unit.
struct HQFieldLabel: View {
    let text: String
    var tint: Color = HQColor.textDim
    var body: some View {
        Text(text.uppercased())
            .font(HQFont.mono(11, weight: .semibold))
            .tracking(1.5)
            .foregroundColor(tint)
    }
}

/// A dark hard-edge text field with an optional leading green accent bar / "@"
/// prefix, matching the onboarding mockups.
struct HQTextField: View {
    let placeholder: String
    @Binding var text: String
    var monospaced: Bool = false
    var prefix: String? = nil
    var accent: Bool = false

    @FocusState private var focused: Bool

    var body: some View {
        HStack(spacing: 2) {
            // A caret rather than a rail: the field reads as a line you type on.
            Text(focused ? "\u{25B8}" : "\u{25B9}")
                .font(HQFont.mono(13, weight: .bold))
                .foregroundColor(focused ? HQColor.greenBright : HQColor.textDim)
                .padding(.trailing, 8)
                .shadow(color: focused ? HQColor.green.opacity(0.8) : .clear, radius: 4)

            if let prefix {
                Text(prefix)
                    .font(monospaced ? HQFont.mono(15) : HQFont.ui(15))
                    .foregroundColor(HQColor.textFaint)
            }
            field
                .font(monospaced ? HQFont.mono(15) : HQFont.ui(15))
                .foregroundColor(HQColor.textPrimary)
                .textFieldStyle(.plain)
                .focused($focused)
        }
        .padding(.horizontal, 14)
        // Scales with the text inside it — a fixed 50 clipped its own field at
        // larger text sizes.
        .frame(minHeight: HQFont.scaled(50))
        // Boxed on four sides, every input looked like a disabled panel. One
        // underline that lights on focus says "type here" and leaves the
        // surrounding card borders to do their own job.
        .background(Color.white.opacity(focused ? 0.055 : 0.03))
        .clipShape(Rectangle())
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(focused ? HQColor.green : Color.white.opacity(0.16))
                .frame(height: focused ? 1.5 : 1)
                .shadow(color: focused ? HQColor.green.opacity(0.6) : .clear, radius: 5)
        }
        .animation(.easeOut(duration: 0.16), value: focused)
    }

    @ViewBuilder private var field: some View {
        #if os(iOS)
        TextField(placeholder, text: $text)
            .textInputAutocapitalization(.never)
            .autocorrectionDisabled()
        #else
        TextField(placeholder, text: $text)
        #endif
    }
}

// MARK: - Day separator

/// `──── today ────`, drawn between messages when the calendar day changes.
/// Reads as a mono rule rather than a pill, matching the app's own chrome.
struct DaySeparator: View {
    let text: String

    var body: some View {
        HStack(spacing: 10) {
            HQRule()
            Text(text)
                .font(HQFont.mono(10.5, weight: .semibold))
                .tracking(1.2)
                .foregroundColor(HQColor.textMuted)
                .fixedSize()
            HQRule()
        }
        .padding(.vertical, 10)
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(text)
    }
}

// MARK: - Search field

/// A search box with a clear button.
struct HQSearchField: View {
    let placeholder: String
    @Binding var text: String

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .foregroundColor(HQColor.textMuted)
            TextField(placeholder, text: $text)
                .textFieldStyle(.plain)
                .foregroundColor(HQColor.textPrimary)
            if !text.isEmpty {
                Button {
                    text = ""
                } label: {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(HQColor.textMuted)
                        .hqTapTarget()
                }
                .buttonStyle(.plain)
                .accessibilityLabel("clear search")
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(HQColor.fillSoft)
        .overlay(Rectangle().stroke(Color.white.opacity(0.1), lineWidth: 1))
        .clipShape(Rectangle())
    }
}
