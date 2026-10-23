import SwiftUI

/// The message field and send button, or a read-only notice for a vanished or
/// blocked contact. Always shown otherwise: sending is what opens a session.
struct ChatComposer: View {
    let friend: Contact
    @Binding var text: String
    let isSending: Bool
    var focused: FocusState<Bool>.Binding
    let onSend: () -> Void

    var body: some View {
        // A vanished identity has no key and no topic; a blocked one's topic is refused.
        if friend.isVanished {
            ReadOnlyNotice(
                title: "you can't reply to this identity",
                detail: "@\(friend.username) signs in with a different key now, which makes them a separate contact. Open that one to keep talking."
            )
        } else if friend.isBlocked {
            ReadOnlyNotice(
                title: "you blocked this contact",
                detail: "nothing can be sent to @\(friend.username), and they can't add you again. unblock them from contacts to start over."
            )
        } else {
            HStack(alignment: .bottom, spacing: 8) {
                field
                sendButton
            }
        }
    }

    private var isFocused: Bool { focused.wrappedValue }
    private var hasText: Bool { !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }

    private var field: some View {
        HStack(alignment: .bottom, spacing: 8) {
            Text(">")
                .font(HQFont.mono(15, weight: .bold))
                .foregroundColor(isFocused ? HQColor.greenBright : HQColor.textDim)
                .padding(.bottom, 1)
                .accessibilityHidden(true)

            TextField("type a message…", text: $text, axis: .vertical)
                .textFieldStyle(.plain)
                .font(HQFont.ui(14.5))
                .foregroundColor(HQColor.textPrimary)
                .lineLimit(1...5)
                // What is typed here is the message: nothing learns from it.
                .hqPrivateTextEntry(capitalize: true)
                .focused(focused)
                .accessibilityLabel("message")
        }
        .padding(.horizontal, 11)
        .padding(.vertical, 9)
        .frame(maxWidth: .infinity)
        .background(Color.white.opacity(isFocused ? 0.05 : 0.03))
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(isFocused ? HQColor.green : Color.white.opacity(0.14))
                .frame(height: isFocused ? 1.5 : 1)
                .shadow(color: isFocused ? HQColor.green.opacity(0.7) : .clear, radius: 5)
        }
        .animation(.easeOut(duration: 0.16), value: isFocused)
        .disabled(isSending)
    }

    private var sendButton: some View {
        Button(action: onSend) {
            Group {
                if isSending {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: "paperplane.fill")
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundColor(HQColor.onGreen)
                }
            }
            .frame(width: 44, height: 44)
            .background(LinearGradient(colors: [HQColor.greenBright, HQColor.greenDeep],
                                       startPoint: .topLeading, endPoint: .bottomTrailing))
            .clipShape(Rectangle())
            .shadow(color: HQColor.green.opacity(0.6), radius: 12)
            .opacity(isSending ? 0.4 : 1)
        }
        .buttonStyle(.plain)
        .disabled(isSending || !hasText)
        .opacity(hasText ? 1 : 0.45)
        .accessibilityLabel("send")
    }
}

/// Why nothing can be sent here, in place of the composer.
private struct ReadOnlyNotice: View {
    let title: String
    let detail: String

    var body: some View {
        VStack(spacing: 4) {
            Text(title)
                .font(HQFont.mono(12, weight: .semibold))
                .foregroundColor(HQColor.textMuted)
            Text(detail)
                .font(HQFont.ui(12))
                .foregroundColor(HQColor.textDim)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
        .accessibilityElement(children: .combine)
    }
}
