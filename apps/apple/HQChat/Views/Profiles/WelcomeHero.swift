import SwiftUI

/// The first-run welcome shown when no profile exists yet.
struct WelcomeHero: View {
    var body: some View {
        VStack(spacing: 22) {
            HQLogoMark(size: 72)

            VStack(spacing: 8) {
                HQWordmark(size: 34)
                Text("private, post-quantum messaging")
                    .font(HQFont.mono(11, weight: .semibold))
                    .tracking(2)
                    .foregroundColor(HQColor.textDim)
            }

            VStack(spacing: 14) {
                Feature(icon: "lock.fill", title: "end-to-end encrypted",
                        subtitle: "HQC + AES-256 on every message and call", tint: HQColor.green)
                Feature(icon: "key.fill", title: "keys stay on your device",
                        subtitle: "secured by the Secure Enclave & Keychain", tint: HQColor.purpleLight)
                Feature(icon: "person.2.fill", title: "multiple identities",
                        subtitle: "separate profiles, each with its own keys", tint: HQColor.green)
            }
            .padding(.horizontal, 8)
            .padding(.top, 4)

            Text("create a profile to get started")
                .font(HQFont.ui(13))
                .foregroundColor(HQColor.textMuted)
                .padding(.top, 4)
        }
        .padding(.top, 40)
        .padding(.horizontal)
    }
}

private struct Feature: View {
    let icon: String
    let title: String
    let subtitle: String
    let tint: Color

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: icon)
                .font(.system(size: 16))
                .foregroundColor(tint)
                .accessibilityHidden(true)
                .frame(width: 38, height: 38)
                .background(tint.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 5))
                .overlay(RoundedRectangle(cornerRadius: 5).stroke(tint.opacity(0.35), lineWidth: 1))
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(HQFont.ui(15, weight: .bold)).foregroundColor(HQColor.textPrimary)
                Text(subtitle).font(HQFont.ui(12.5)).foregroundColor(HQColor.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
    }
}
