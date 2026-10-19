// The technical detail, moved off the settings root: what's actually
// protected, and by what.

import SwiftUI

struct SecuritySettingsView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) private var dismiss

    /// Which gate the active profile's keys carry, read back from the tier marker.
    private var tier: KeyProtectionTier {
        guard let id = appState.profileManager?.currentProfile?.id else {
            return .biometryCurrentSet
        }
        return KeyProtectionTier.stored(for: id.uuidString)
    }

    var body: some View {
        VStack(spacing: 0) {
            #if os(iOS)
            HQSubScreenHeader(path: "settings/security") { dismiss() }
            #endif
            ScrollView {
                VStack(spacing: 22) {
                    protectionCard
                }
                .padding()
            }
        }
        .background(HQScreenBackground())
        #if os(iOS)
        .toolbar(.hidden, for: .navigationBar)
        .hqSwipeNavigation(onBack: { dismiss() })
        #else
        .navigationTitle("Security")
        .inlineNavTitle()
        #endif
    }

    private var protectionCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HQFieldLabel(text: "what's protected", tint: HQColor.green)

            protectionRow(icon: "key.fill",
                          title: "Identity key",
                          detail: "Sealed to this device's Secure Enclave key · \(tier.detail). "
                            + "Opened once per session, forgotten when the app goes to the background.",
                          ok: !tier.isReduced)
            if tier.isReduced {
                protectionRow(icon: "exclamationmark.triangle.fill",
                              title: "Reduced protection",
                              detail: "This profile uses quick unlock: one authentication per launch, then its key is held in memory. Anyone who can unlock this device can open the identity and read its messages, and it is not bound to the current Face ID enrolment. Fixed at creation — enrolling Face ID now does not upgrade this profile, only a new one.",
                              ok: false)
            }
            protectionRow(icon: "key.horizontal.fill",
                          title: "Session keys",
                          detail: "Sealed on this device, never in a backup",
                          ok: true)
            protectionRow(icon: "lock.fill",
                          title: "Messages in transit",
                          detail: "HQC + AES-256-GCM, end-to-end",
                          ok: true)
            protectionRow(icon: "externaldrive.fill",
                          title: "Messages at rest",
                          detail: "Sealed with a per-profile key only the Secure Enclave opens",
                          ok: true)
        }
        .padding(16)
        .hqCard(accent: HQColor.green)
    }

    private func protectionRow(icon: String, title: String, detail: String, ok: Bool) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 15))
                .foregroundColor(ok ? HQColor.green : HQColor.warning)
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(HQFont.ui(14.5, weight: .medium))
                    .foregroundColor(HQColor.textPrimary)
                Text(detail)
                    .font(HQFont.ui(11.5))
                    .foregroundColor(HQColor.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer()

            Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 14))
                .foregroundColor(ok ? HQColor.green : HQColor.warning)
        }
    }
}
