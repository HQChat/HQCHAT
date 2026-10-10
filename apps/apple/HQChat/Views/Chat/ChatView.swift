import SwiftUI
import SwiftData

/// One conversation: notices, the header, the transcript and the composer.
struct ChatView: View {
    let friend: Friend
    let session: ChatSession
    let profileManager: ProfileManager?

    @Environment(\.modelContext) private var modelContext
    @Environment(\.dismiss) private var dismiss
    /// See `MessageKeyGate`: bodies are sealed at rest, and the single unlock
    /// that opens them is asked for when this screen appears, not per row.
    @ObservedObject private var messageKeys = MessageKeyGate.shared
    @Query private var messages: [Message]

    @State private var messageText = ""
    @State private var isSending = false
    @State private var appError: AppError?
    @State private var isSearching = false
    @State private var searchText = ""
    @State private var showingVerification = false
    /// What the user asked to report. Nil means no sheet: the target and the
    /// presentation state are one value, so they cannot disagree.
    @State private var reportDraft: ReportDraft?
    @FocusState private var composerFocused: Bool

    init(friend: Friend, session: ChatSession, profileManager: ProfileManager? = nil) {
        self.friend = friend
        self.session = session
        self.profileManager = profileManager

        // This friend's messages in this profile only.
        let friendUsername = friend.username
        let profileID = friend.profile?.id ?? profileManager?.currentProfile?.id
        _messages = Query(filter: #Predicate<Message> { message in
            message.friend?.username == friendUsername && message.profileID == profileID
        }, sort: \Message.timestamp)
    }

    var body: some View {
        VStack(spacing: 0) {
            ChatBanners(friend: friend, isEmpty: messages.isEmpty, onVerify: { showingVerification = true })
            ChatHeader(friend: friend,
                       profileManager: profileManager,
                       isSearching: $isSearching,
                       onVerify: { showingVerification = true },
                       onReport: { reportDraft = ReportDraft(excerpt: nil, messageId: nil) },
                       onError: { appError = $0 })
            if isSearching {
                ChatSearchBar(text: $searchText)
            }
            transcript
            ChatComposer(friend: friend, text: $messageText, isSending: isSending,
                         focused: $composerFocused, onSend: sendMessage)
                .padding(12)
                .background(HQColor.screen.opacity(0.5))
                .overlay(Rectangle().fill(HQColor.hairline).frame(height: 1), alignment: .top)
        }
        .sheet(isPresented: $showingVerification) { verification }
        // `item:` hands the draft to the sheet, so it can never present empty.
        .sheet(item: $reportDraft) { draft in
            ReportSheet(friend: friend, draft: draft, session: session) {
                // A block leaves nothing to do here, so close the conversation behind the sheet.
                if friend.isBlocked { dismiss() }
            }
        }
        .hqError($appError)
        .hqScreenBackground()
        #if os(iOS)
        // Full screen: no tab bar or navigation bar under a conversation, with a
        // back swipe from anywhere on the screen.
        .toolbar(.hidden, for: .tabBar)
        .toolbar(.hidden, for: .navigationBar)
        .hqSwipeNavigation(onBack: { dismiss() })
        #endif
        // One unlock for every sealed row in the thread.
        .task { await messageKeys.unlock() }
        .onAppear {
            // Opening the thread clears its unread badges and suppresses its banners.
            NotificationService.shared.visibleConversation = friend.username
            NotificationService.shared.markRead(friend: friend, modelContext: modelContext)
        }
        .onDisappear {
            if NotificationService.shared.visibleConversation == friend.username {
                NotificationService.shared.visibleConversation = nil
            }
        }
        .onChange(of: messages.count) { _, _ in
            NotificationService.shared.markRead(friend: friend, modelContext: modelContext)
        }
        .onChange(of: isSearching) { _, searching in
            if !searching { searchText = "" }
        }
    }

    // MARK: Transcript

    /// Messages shown in the list, filtered by the in-chat search query.
    private var displayedMessages: [Message] {
        guard !searchText.isEmpty else { return messages }
        return messages.filter { $0.content.localizedCaseInsensitiveContains(searchText) }
    }

    private var transcript: some View {
        ScrollViewReader { proxy in
            ScrollView {
                // No placeholder for an empty conversation; the composer is enough.
                if !messages.isEmpty {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        if !searchText.isEmpty && displayedMessages.isEmpty {
                            Text("no messages match \"\(searchText)\"")
                                .font(HQFont.mono(12.5))
                                .foregroundColor(HQColor.textMuted)
                                .frame(maxWidth: .infinity)
                                .padding(.top, 40)
                        }
                        ForEach(displayedMessages) { message in
                            if let day = daySeparator(before: message) {
                                DaySeparator(text: day)
                            }
                            MessageBubble(
                                message: message,
                                onRetry: { retrySend(message) },
                                // Incoming only; the text is copied now, while the finger is on the bubble.
                                onReport: message.isOutgoing ? nil : {
                                    reportDraft = ReportDraft(excerpt: message.content, messageId: message.messageId)
                                })
                                .id(message.id)
                        }
                    }
                    .padding()
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            // Dragging or tapping the transcript dismisses the keyboard; the bubbles' own gestures still win.
            .scrollDismissesKeyboard(.interactively)
            .onTapGesture { composerFocused = false }
            .onChange(of: messages.count) { _, _ in scrollToBottom(proxy, after: 0) }
            // Focusing the composer shrinks the list; follow the bottom once the keyboard has resized it.
            .onChange(of: composerFocused) { _, focused in
                if focused { scrollToBottom(proxy, after: 0.1) }
            }
            .onAppear { scrollToBottom(proxy, after: 0.1) }
        }
    }

    private func scrollToBottom(_ proxy: ScrollViewProxy, after delay: TimeInterval) {
        guard let last = messages.last else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) {
            withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
        }
    }

    /// The day label above `message`, or nil when the previous shown message
    /// was on the same day (so search results stay grouped).
    private func daySeparator(before message: Message) -> String? {
        let list = displayedMessages
        guard let i = list.firstIndex(where: { $0.id == message.id }) else { return nil }
        if i > 0, Calendar.current.isDate(list[i - 1].timestamp, inSameDayAs: message.timestamp) { return nil }
        return Self.dayLabel(message.timestamp)
    }

    /// `today` / `yesterday` / `mon 18 aug`, lowercase like the rest of the app's chrome.
    static func dayLabel(_ date: Date) -> String {
        let cal = Calendar.current
        if cal.isDateInToday(date) { return "today" }
        if cal.isDateInYesterday(date) { return "yesterday" }
        let f = DateFormatter()
        f.locale = Locale.current
        f.setLocalizedDateFormatFromTemplate(
            cal.isDate(date, equalTo: Date(), toGranularity: .year) ? "EEEddMMM" : "EEEddMMMyyyy"
        )
        return f.string(from: date).lowercased()
    }

    private var verification: some View {
        KeyVerificationView(
            friend: friend,
            myPublicKey: profileManager?.currentProfile?.publicKey,
            onMarkVerified: {
                friend.keyVerified = true
                try? modelContext.save()
            },
            onClearVerification: {
                friend.keyVerified = false
                try? modelContext.save()
            },
            onRotateKeys: {
                let svc = FriendService(session: session, modelContext: modelContext)
                svc.setModelContext(modelContext)
                svc.forceRatchetStep(friend: friend)
            }
        )
    }

    // MARK: Sending

    private func sendMessage() {
        // Only text is required: the first send opens the session.
        guard !messageText.isEmpty else { return }
        // Insert the row before sending, so a failed send stays visible and retryable.
        let message = Message(content: messageText, isOutgoing: true, friend: friend,
                              messageId: UUID().uuidString, deliveryStatus: .sending)
        modelContext.insert(message)
        save()
        messageText = ""
        isSending = true
        deliver(message) { isSending = false }
    }

    /// Re-sends a failed message under its id, so a delivery receipt still correlates.
    private func retrySend(_ message: Message) {
        guard message.deliveryStatus == .failed else { return }
        message.deliveryStatus = .sending
        save()
        deliver(message)
    }

    /// Seals and publishes one stored message (opening the session if needed)
    /// and records the outcome on its row.
    private func deliver(_ message: Message, then finish: @escaping () -> Void = {}) {
        let text = message.content
        let messageId = message.messageId ?? UUID().uuidString
        Task {
            do {
                let envelope = try await session.sealMessage(text, to: friend, msgId: messageId)
                session.publish(envelope, to: friend)
                // Advance, not assign: the delivery receipt may already have arrived.
                message.advanceDelivery(to: friend.isOnline ? .sent : .queued)
            } catch {
                message.advanceDelivery(to: .failed)
                appError = .from(error)
            }
            save()
            finish()
        }
    }

    /// Saves, surfacing failures.
    private func save() {
        do {
            try modelContext.save()
        } catch {
            appError = .unknown("Couldn't save to this device: \(error.localizedDescription)")
        }
    }
}
