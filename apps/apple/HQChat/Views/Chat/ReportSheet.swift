import SwiftUI

/// What a report is about, snapshotted when the user asks. A value with its own
/// UUID, so the sheet's identity cannot change under it the way a SwiftData
/// model's can. `excerpt` and `messageId` are nil for a conversation report.
struct ReportDraft: Identifiable {
    let id = UUID()
    /// The reporter's copy of one message, or nil to report the conversation.
    let excerpt: String?
    /// The frame's id, when the report is about a specific message.
    let messageId: String?
}

/// Reports a message or conversation to the server operator (App Store
/// Guideline 1.2), optionally blocking too. The copy states that a message
/// report uploads that message's text and that an excerpt is the reporter's
/// own, unverifiable copy. The report is sent before the block, because the
/// server only accepts reports from conversation members.
struct ReportSheet: View {
    let friend: Contact
    /// What is being reported.
    let draft: ReportDraft
    /// Called once filed, with whether the friend was blocked too.
    let onFinished: (Bool) -> Void

    @EnvironmentObject private var chat: ChatStore

    @Environment(\.dismiss) private var dismiss
    @State private var category = "harassment"
    @State private var note = ""
    @State private var alsoBlock = true
    @State private var sending = false
    @State private var appError: AppError?

    /// One row of the category picker.
    private struct Category: Identifiable {
        let id: String       // exactly what goes on the wire
        let label: String    // what the user reads
    }

    /// The categories the server accepts (`REPORT_CATEGORIES`).
    private static let categories: [Category] = [
        Category(id: "harassment", label: "harassment or bullying"),
        Category(id: "spam", label: "spam or a scam"),
        Category(id: "sexual", label: "sexual content"),
        Category(id: "violence", label: "violence or threats"),
        Category(id: "csae", label: "child sexual abuse or exploitation"),
        Category(id: "other", label: "something else"),
    ]

    var body: some View {
        VStack(spacing: 0) {
            navBar
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    subject
                    HQFieldLabel(text: "what happened").padding(.top, 26).padding(.bottom, 9)
                    categoryPicker
                    HQFieldLabel(text: "anything to add (optional)")
                        .padding(.top, 26).padding(.bottom, 9)
                    HQTextField(placeholder: "what should we know?", text: $note)
                    // What will be sent, stated above the button that sends it.
                    disclosure.padding(.top, 26)
                    blockToggle.padding(.top, 20)
                }
                .padding(.horizontal, 22)
                .padding(.top, 26)
                .padding(.bottom, 40)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .hqScreenBackground()
        .sheetSizing(minHeight: 620)
        .hqError($appError)
    }

    private var navBar: some View {
    HStack {
        Button("cancel") { dismiss() }
            .buttonStyle(.plain)
            .font(HQFont.ui(15))
            .foregroundColor(HQColor.textSecond)
        Spacer()
        Text("report message")
            .font(HQFont.ui(16, weight: .bold))
            .foregroundColor(.white)
        Spacer()
        Button(sending ? "sending…" : "send") { send() }
            .buttonStyle(.plain)
            .font(HQFont.ui(15, weight: .semibold))
            .foregroundColor(sending ? HQColor.textOff : HQColor.danger)
            .disabled(sending)
    }
    .padding(.horizontal, 22)
    .padding(.vertical, 16)
    .overlay(Rectangle().fill(HQColor.hairline).frame(height: 1), alignment: .bottom)
    }

    /// The quoted message, or what a conversation report covers.
    @ViewBuilder
    private var subject: some View {
        if let excerpt = draft.excerpt {
            HQFieldLabel(text: "the message").padding(.bottom, 9)
            Text(excerpt)
                .font(HQFont.ui(13.5))
                .foregroundColor(HQColor.textOnCard)
                .fixedSize(horizontal: false, vertical: true)
                .padding(13)
                // A minimum height, scaled with Dynamic Type.
                .frame(maxWidth: .infinity,
                       minHeight: HQFont.scaled(64),
                       alignment: .topLeading)
                .background(Color.white.opacity(0.03))
                .overlay(Rectangle().stroke(Color.white.opacity(0.08), lineWidth: 1))
        } else {
            HQFieldLabel(text: "what you're reporting").padding(.bottom, 9)
            Text("this conversation with @\(friend.username). no message text is "
                 + "attached — say what happened below, and name a message if you can.")
                .font(HQFont.ui(13.5))
                .foregroundColor(HQColor.textOnCard)
                .fixedSize(horizontal: false, vertical: true)
                .padding(13)
                .frame(maxWidth: .infinity, alignment: .topLeading)
                .background(Color.white.opacity(0.03))
                .overlay(Rectangle().stroke(Color.white.opacity(0.08), lineWidth: 1))
        }
    }

    private var categoryPicker: some View {
        VStack(spacing: 9) {
            ForEach(Self.categories) { option in
                Button { category = option.id } label: {
                    HStack(spacing: 11) {
                        Image(systemName: category == option.id
                              ? "largecircle.fill.circle" : "circle")
                            .font(.system(size: 14))
                            .foregroundColor(category == option.id ? HQColor.danger : HQColor.textDim)
                            .accessibilityHidden(true)
                            .frame(width: 30, height: 30)
                        Text(option.label)
                            .font(HQFont.ui(13.5))
                            .foregroundColor(HQColor.textPrimary)
                        Spacer(minLength: 0)
                    }
                }
                .buttonStyle(.plain)
                .accessibilityLabel(option.label)
                .accessibilityAddTraits(category == option.id ? [.isSelected] : [])
            }
        }
    }

    private var disclosure: some View {
        HStack(alignment: .top, spacing: 11) {
            Image(systemName: "arrow.up.doc")
                .font(.system(size: 14))
                .foregroundColor(HQColor.warning)
                .accessibilityHidden(true)
                .frame(width: 30, height: 30)
            VStack(alignment: .leading, spacing: 4) {
                Text(draft.excerpt == nil
                     ? "this sends what you type to the server"
                     : "this sends the message text to the server")
                    .font(HQFont.ui(13, weight: .semibold))
                    .foregroundColor(HQColor.textOnCard)
                Text(draft.excerpt == nil
                     ? "no message text is attached to this one — only your note, the "
                       + "category, and which conversation it is about. we cannot check "
                       + "whether a report is real, so it is read as what you handed in. "
                       + "it is deleted after 90 days."
                     : "it is the only thing in this app that does. we cannot check whether "
                       + "an excerpt is real — anyone could type anything here — so it is "
                       + "read as what you handed in, not as proof of what was said. "
                       + "it is deleted after 90 days.")
                    .font(HQFont.ui(11.5))
                    .foregroundColor(HQColor.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .background(Color.white.opacity(0.02))
        .overlay(Rectangle().stroke(HQColor.warning.opacity(0.25), lineWidth: 1))
    }

    private var blockToggle: some View {
        Button { alsoBlock.toggle() } label: {
            HStack(alignment: .top, spacing: 11) {
                Image(systemName: alsoBlock ? "checkmark.square.fill" : "square")
                    .font(.system(size: 14))
                    .foregroundColor(alsoBlock ? HQColor.danger : HQColor.textDim)
                    .accessibilityHidden(true)
                    .frame(width: 30, height: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text("also block @\(friend.username)")
                        .font(HQFont.ui(13.5, weight: .semibold))
                        .foregroundColor(HQColor.textPrimary)
                    Text("they can no longer reach you, and cannot add you again. "
                         + "your messages stay on this device.")
                        .font(HQFont.ui(11.5))
                        .foregroundColor(HQColor.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
        }
        .buttonStyle(.plain)
        .hqTapTarget()
        .accessibilityLabel("also block \(friend.username)")
        .accessibilityAddTraits(alsoBlock ? [.isSelected] : [])
    }

    private func send() {
        sending = true
        Task {
            do {
                // The core files the report first and blocks only once it is
                // in: the block ends the membership the server checks.
                try await chat.report(friend, category: category, note: note.isEmpty ? nil : note,
                                      messageID: draft.messageId, block: alsoBlock)
                sending = false
                onFinished(alsoBlock)
                dismiss()
            } catch {
                sending = false
                appError = .from(error)
            }
        }
    }
}
