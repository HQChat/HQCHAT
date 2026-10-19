import SwiftUI
import SwiftData

/// Settings root: the profile header, the pushed screens (account, security,
/// diagnostics), the published pages and the version.
struct SettingsView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) private var dismiss
    let profileManager: ProfileManager?
    /// True when hosted in the iOS tab bar, where a "Done" button would make no
    /// sense. macOS still presents this as a sheet.
    var isEmbedded = false

    /// Value-based navigation, so something outside this screen can push into
    /// it — the "username taken" banner sends people straight to Account.
    @State private var path = NavigationPath()

    private enum Route: Hashable { case account, security, diagnostics }

    private struct Entry {
        let icon: String
        let title: String
        let subtitle: String
        let tint: Color
    }

    private static let screens: [(Route, Entry)] = [
        (.account, Entry(icon: "person.crop.circle", title: "account",
                         subtitle: "username, keys, delete account", tint: HQColor.green)),
        (.security, Entry(icon: "lock.shield", title: "security",
                          subtitle: "unlock behaviour and what's encrypted", tint: HQColor.purpleLight)),
        (.diagnostics, Entry(icon: "waveform.path.ecg", title: "diagnostics",
                             subtitle: "key exchange, greetings, and what got dropped", tint: HQColor.warning)),
    ]

    /// The published pages, opened at the same URLs App Store Connect was given
    /// (Guideline 1.2 wants the terms and a contact point reachable).
    private static let pages: [(URL, Entry)] = [
        (Deployment.eulaURL, Entry(icon: "doc.text", title: "terms",
                                   subtitle: "what you agreed to · what gets you removed", tint: HQColor.textSecond)),
        (Deployment.privacyURL, Entry(icon: "hand.raised", title: "privacy",
                                      subtitle: "what this server holds, and what it cannot", tint: HQColor.textSecond)),
        (Deployment.supportURL, Entry(icon: "envelope", title: "support",
                                      subtitle: "report abuse, or ask a human", tint: HQColor.textSecond)),
    ]

    private var appVersion: String {
        let v = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0"
        let b = Bundle.main.infoDictionary?["CFBundleVersion"] as? String ?? "1"
        return "\(v) (\(b))"
    }

    var body: some View {
        NavigationStack(path: $path) {
            VStack(spacing: 0) {
                #if os(iOS)
                HQScreenHeader(path: "settings", appState: appState, profileManager: profileManager)
                #endif

                ScrollView {
                VStack(spacing: 22) {
                    profileHeader

                    menu

                    privacyStanceCard

                    Text("hqchat \(appVersion)")
                        .font(HQFont.mono(11))
                        .foregroundColor(HQColor.textFaint)
                        .padding(.top, 4)
                }
                .padding()
                }
            }
            .background(HQScreenBackground())
            #if os(iOS)
            // The prompt header names the screen (see HQPromptHeader).
            .toolbar(.hidden, for: .navigationBar)
            #else
            .navigationTitle("Settings")
            #endif
            .navigationDestination(for: Route.self) { route in
                switch route {
                case .account:
                    AccountSettingsView(profileManager: profileManager)
                case .security:
                    SecuritySettingsView()
                case .diagnostics:
                    ProtocolLogView()
                }
            }
            .toolbar {
                if !isEmbedded {
                    ToolbarItem(placement: .confirmationAction) {
                        Button("Done") { dismiss() }
                    }
                }
            }
        }
        // Something (usually a banner) asked for Account. On iOS this view is
        // alive in the tab bar when the flag flips; on macOS the flag is set
        // before the sheet exists, so both hooks are needed.
        .onAppear { consumeAccountRequest() }
        .onChange(of: appState.openAccountSettings) { _, wanted in
            guard wanted else { return }
            consumeAccountRequest()
        }
    }

    /// Lowercase, like the rest of the app's own chrome.
    private var menu: some View {
        VStack(spacing: 10) {
            ForEach(Self.screens, id: \.1.title) { route, entry in
                NavigationLink(value: route) { row(entry) }
                    .buttonStyle(.plain)
            }
            ForEach(Self.pages, id: \.1.title) { url, entry in
                Link(destination: url) { row(entry) }
                    .buttonStyle(.plain)
            }
        }
    }

    private func row(_ entry: Entry) -> some View {
        settingsRow(icon: entry.icon, title: entry.title, subtitle: entry.subtitle, tint: entry.tint)
    }

    /// Push Account if something asked for it, and clear the request so it is
    /// honoured once rather than on every appearance.
    private func consumeAccountRequest() {
        guard appState.openAccountSettings else { return }
        if !path.isEmpty { path = NavigationPath() }
        path.append(Route.account)
        appState.openAccountSettings = false
    }

    /// The handle in force right now: the server's answer if we have it, else
    /// the one this profile was created with. A handle the server *refused*
    /// counts as neither — showing it here would claim an identity this device
    /// does not own.
    private var handle: String? {
        if appState.usernameRejected != nil { return nil }
        return profileManager?.currentProfile?.username
    }

    /// Who you currently are, and a one-tap way to switch profile.
    private var profileHeader: some View {
        VStack(spacing: 12) {
            HQAvatar(name: handle ?? "?", size: 64, glow: HQColor.purple)

            VStack(spacing: 3) {
                Text(handle.map { "@\($0)" } ?? "no profile")
                    .font(HQFont.ui(18, weight: .semibold))
                    .foregroundColor(HQColor.textPrimary)

                // Labelled, so the eight hex characters read as a fingerprint.
                if let id = profileManager?.currentProfile?.peerID, !id.isEmpty {
                    Text("key \(HQFingerprint.short(clientID: id))")
                        .font(HQFont.mono(12))
                        .foregroundColor(HQColor.textMuted)
                        .accessibilityLabel("key fingerprint \(HQFingerprint.short(clientID: id))")
                }
            }

            #if os(iOS)
            Button("switch profile") {
                appState.showingProfileSwitcher = true
            }
            .buttonStyle(HQSecondaryButtonStyle())
            .frame(maxWidth: 220)
            #endif
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 18)
        .hqCard(accent: HQColor.purple)
    }

    /// What this app deliberately does *not* do. Read receipts and typing
    /// indicators are a product decision here, not an unfinished feature — but
    /// an absence that isn't stated reads as a gap, so it is stated.
    private var privacyStanceCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HQFieldLabel(text: "what we don't send", tint: HQColor.textMuted)
            ForEach(["no read receipts — nobody is told when you open a message",
                     "no typing indicators",
                     "no last-seen; presence is only shown to your contacts, only while you're connected"],
                    id: \.self) { line in
                HStack(alignment: .top, spacing: 8) {
                    Text("·")
                        .font(HQFont.mono(12, weight: .bold))
                        .foregroundColor(HQColor.textDim)
                    Text(line)
                        .font(HQFont.ui(12.5))
                        .foregroundColor(HQColor.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(14)
        .hqCard()
    }

    private func settingsRow(icon: String, title: String, subtitle: String, tint: Color) -> some View {
        HStack(spacing: 14) {
            Image(systemName: icon)
                .font(.system(size: 17))
                .foregroundColor(tint)
                .accessibilityHidden(true)
                .frame(width: 34, height: 34)
                .background(tint.opacity(0.08))
                .overlay(RoundedRectangle(cornerRadius: 8).stroke(tint.opacity(0.30), lineWidth: 1))
                .clipShape(RoundedRectangle(cornerRadius: 8))

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(HQFont.ui(15.5, weight: .semibold))
                    .foregroundColor(HQColor.textPrimary)
                Text(subtitle)
                    .font(HQFont.ui(12))
                    .foregroundColor(HQColor.textMuted)
            }

            Spacer()

            Image(systemName: "chevron.right")
                .accessibilityHidden(true)
                .font(.system(size: 13, weight: .semibold))
                .foregroundColor(HQColor.textFaint)
        }
        .padding(14)
        .hqCard(accent: tint)
    }
}
