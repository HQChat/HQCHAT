// HQChat (shared macOS + iOS)
//
// The first-contact trace, on the device, without a Mac attached.
//
// `ProtocolLog` already writes to the unified log, which is the better source
// when someone can plug the phone in and open Console. This screen is for the
// case that actually happens: a tester says "the bot never said anything" and
// is three time zones away. They can read the trace here and send it.
//
// Nothing on this screen is sensitive by construction — see ProtocolLog's
// header. It carries ids truncated to eight characters, counts, and reasons;
// no payloads, keys, tokens or message text pass through the type. The copy
// still stays on this device and expires: a trace says who talked to whom.

import SwiftUI
import UniformTypeIdentifiers

struct ProtocolLogView: View {
    @Environment(\.dismiss) private var dismiss

    /// Snapshotted rather than observed: the log is written from several actors,
    /// and a view that re-rendered on every frame would be unreadable exactly
    /// when it matters. Refresh is a deliberate tap.
    @State private var entries: [ProtocolLog.Entry] = []
    @State private var copied = false

    private static let clock: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()

    var body: some View {
        VStack(spacing: 0) {
            #if os(iOS)
            HQSubScreenHeader(path: "settings/diagnostics") { dismiss() }
            #endif

            if entries.isEmpty {
                emptyState
            } else {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 6) {
                        ForEach(Array(entries.enumerated()), id: \.offset) { _, entry in
                            HStack(alignment: .top, spacing: 8) {
                                Text(Self.clock.string(from: entry.at))
                                    .font(HQFont.mono(10))
                                    .foregroundColor(HQColor.textFaint)
                                Text(entry.line)
                                    .font(HQFont.mono(11))
                                    .foregroundColor(HQColor.textPrimary)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                }
            }

            controls
        }
        .background(HQScreenBackground())
        .onAppear { entries = ProtocolLog.entries() }
        #if os(iOS)
        .toolbar(.hidden, for: .navigationBar)
        .hqSwipeNavigation(onBack: { dismiss() })
        #else
        .navigationTitle("Diagnostics")
        .inlineNavTitle()
        #endif
    }

    private var emptyState: some View {
        VStack(spacing: 8) {
            Text("nothing yet")
                .font(HQFont.ui(15, weight: .semibold))
                .foregroundColor(HQColor.textPrimary)
            Text("connect and open a conversation — key exchange, greetings and\nanything dropped along the way show up here.")
                .font(HQFont.mono(11))
                .multilineTextAlignment(.center)
                .foregroundColor(HQColor.textSecond)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }

    private var controls: some View {
        HStack(spacing: 10) {
            Button("refresh") { entries = ProtocolLog.entries() }
                .font(HQFont.mono(12, weight: .semibold))
                .foregroundColor(HQColor.textSecond)

            Button(copied ? "copied" : "copy") {
                copyTranscript()
                copied = true
                Task {
                    try? await Task.sleep(nanoseconds: 1_500_000_000)
                    copied = false
                }
            }
            .font(HQFont.mono(12, weight: .semibold))
            .foregroundColor(HQColor.green)

            Spacer()

            Button("clear") {
                ProtocolLog.clear()
                entries = []
            }
            .font(HQFont.mono(12, weight: .semibold))
            .foregroundColor(HQColor.dangerLight)
        }
        .buttonStyle(.plain)
        .padding(.horizontal)
        .padding(.vertical, 12)
    }

    /// How long the copied transcript stays on the pasteboard.
    private static let pasteboardLifetime: TimeInterval = 120

    /// On this device's pasteboard only, never handed to Universal Clipboard,
    /// and gone after `pasteboardLifetime`: long enough to paste it into a
    /// message, not long enough to sit there for whatever reads it next.
    private func copyTranscript() {
        let text = ProtocolLog.transcript()
        #if os(iOS)
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: text]],
            options: [.localOnly: true,
                      .expirationDate: Date().addingTimeInterval(Self.pasteboardLifetime)]
        )
        #else
        let board = NSPasteboard.general
        // `.currentHostOnly` keeps it off Universal Clipboard. macOS has no
        // expiry, so the copy is cleared later unless something replaced it.
        board.prepareForNewContents(with: .currentHostOnly)
        board.setString(text, forType: .string)
        let generation = board.changeCount
        DispatchQueue.main.asyncAfter(deadline: .now() + Self.pasteboardLifetime) {
            if board.changeCount == generation { board.clearContents() }
        }
        #endif
    }
}
