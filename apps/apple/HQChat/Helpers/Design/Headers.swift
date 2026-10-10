// Screen headers: the prompt line of a tab root and of a pushed screen.

import SwiftUI

// MARK: - Prompt header

/// A dashed ASCII rule — the separator this UI uses instead of `Divider`.
struct HQRule: View {
    var color: Color = HQColor.hairline
    var body: some View {
        Line()
            .stroke(style: StrokeStyle(lineWidth: 1, dash: [3, 3]))
            .foregroundColor(color)
            .frame(height: 1)
    }

    private struct Line: Shape {
        func path(in rect: CGRect) -> Path {
            var p = Path()
            p.move(to: CGPoint(x: 0, y: rect.midY))
            p.addLine(to: CGPoint(x: rect.maxX, y: rect.midY))
            return p
        }
    }
}

/// The top bar every screen except a conversation wears: a shell prompt naming
/// the app and the screen, a blinking cursor, and whatever status the caller
/// hands it.
///
/// It replaces `.navigationTitle`, which put a system-styled sentence-case title
/// on screens that are otherwise a terminal — and, on Contacts, said the word
/// "contacts" twice because the list already has a section by that name.
struct HQPromptHeader<Trailing: View>: View {
    /// The screen, as a path segment: `chats`, `contacts`, `settings`. The only
    /// thing that differs between screens — everything else here is identical
    /// by construction, so the three tabs cannot drift apart.
    let path: String
    @ViewBuilder var trailing: () -> Trailing

    private let size: CGFloat = 16

    var body: some View {
        VStack(spacing: 10) {
            HStack(spacing: 0) {
                Text("hqchat")
                    .font(HQFont.mono(size, weight: .bold))
                    .foregroundColor(HQColor.green)
                Text(":~/")
                    .font(HQFont.mono(size))
                    .foregroundColor(HQColor.textDim)
                Text(path)
                    .font(HQFont.mono(size, weight: .semibold))
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
                    .foregroundColor(HQColor.purpleLight)
                Text("$")
                    .font(HQFont.mono(size))
                    .foregroundColor(HQColor.textDim)
                Text(" \u{2588}")
                    .font(HQFont.mono(size))
                    .foregroundColor(HQColor.green)
                    .modifier(BlinkModifier())

                Spacer(minLength: 8)

                trailing()
            }
            .padding(.horizontal, 16)

            HQRule()
        }
        .padding(.top, 8)
        .padding(.bottom, 2)
    }
}

extension HQPromptHeader where Trailing == EmptyView {
    init(path: String) {
        self.init(path: path) { EmptyView() }
    }
}

/// The header a pushed screen wears: the same prompt, one path segment deeper,
/// with a `[<]` back control in place of the tab roots' status chips. Sheets
/// keep the system look.
struct HQSubScreenHeader: View {
    /// Full path, e.g. `settings/account`.
    let path: String
    let onBack: () -> Void

    var body: some View {
        VStack(spacing: 10) {
            HStack(spacing: 12) {
                Button(action: onBack) {
                    Text("[<]")
                        .font(HQFont.mono(15, weight: .bold))
                        .foregroundColor(HQColor.green)
                        .hqTapTarget()
                }
                .buttonStyle(.plain)
                .accessibilityLabel("back")

                HStack(spacing: 0) {
                    Text("hqchat")
                        .font(HQFont.mono(15, weight: .bold))
                        .foregroundColor(HQColor.green)
                    Text(":~/")
                        .font(HQFont.mono(15))
                        .foregroundColor(HQColor.textDim)
                    Text(path)
                        .font(HQFont.mono(15, weight: .semibold))
                        .lineLimit(1)
                        .minimumScaleFactor(0.7)
                        .foregroundColor(HQColor.purpleLight)
                    Text("$")
                        .font(HQFont.mono(15))
                        .foregroundColor(HQColor.textDim)
                }
                .accessibilityAddTraits(.isHeader)

                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12)

            HQRule()
        }
        .padding(.top, 6)
        .padding(.bottom, 2)
    }
}
