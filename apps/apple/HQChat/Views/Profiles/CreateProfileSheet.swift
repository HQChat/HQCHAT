import SwiftUI

/// The new-profile form: handle, optional home server, protection tier and agreement.
struct CreateProfileSheet: View {
    @Binding var username: String
    @Binding var serverURL: String
    /// Which gate this profile's keys will carry. Nil until answered — there is
    /// no default, so nothing is chosen on the user's behalf.
    @Binding var tier: KeyProtectionTier?
    /// What the device can actually do — decides whether there is a choice here
    /// at all, and explains why when there isn't.
    let capability: DeviceAuthCapability
    /// Selection goes through the parent: picking "Secure" has to raise the
    /// biometric consent before it can be honoured, and that is async.
    let onSelectTier: (KeyProtectionTier) -> Void
    let onSave: () -> Void
    let onCancel: () -> Void

    /// The agreement version this person accepted, app-wide (see `EulaPrefs`).
    @AppStorage(EulaPrefs.acceptedVersionKey) private var acceptedEula: String = ""

    /// Why the handle is refused, once something has been typed.
    private var rejection: String? {
        username.isEmpty ? nil : UsernameRule.rejectionReason(username)
    }

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Button("cancel") { onCancel() }
                    .buttonStyle(.plain)
                    .font(HQFont.ui(15))
                    .foregroundColor(HQColor.textSecond)
                Spacer()
                Text("new profile")
                    .font(HQFont.ui(16, weight: .bold))
                    .foregroundColor(.white)
                Spacer()
                Button("create") { onSave() }
                    .buttonStyle(.plain)
                    .font(HQFont.ui(15, weight: .semibold))
                    .foregroundColor(canCreate ? HQColor.green : HQColor.textOff)
                    .disabled(!canCreate)
            }
            .padding(.horizontal, 22)
            .padding(.vertical, 16)
            .overlay(Rectangle().fill(HQColor.hairline).frame(height: 1), alignment: .bottom)

            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    // A profile has one name: its username.
                    HQFieldLabel(text: "username").padding(.bottom, 9)
                    HQTextField(placeholder: "handle", text: $username, monospaced: true, prefix: "@", ascii: true)
                        .onChange(of: username) { _, newValue in
                            // Filter as typed, with the same alphabet the server
                            // accepts — nothing else can be typed or pasted in.
                            let clean = UsernameRule.sanitized(newValue)
                            if clean != newValue { username = clean }
                        }
                        .onSubmit { if canCreate { onSave() } }

                    if let rejection {
                        Text(rejection)
                            .font(HQFont.mono(12))
                            .foregroundColor(HQColor.warning)
                            .padding(.top, 9).padding(.horizontal, 2)
                    } else {
                        Text("how friends find and add you · \(UsernameRule.hint)")
                            .font(HQFont.ui(12.5)).foregroundColor(HQColor.textDim)
                            .padding(.top, 9).padding(.horizontal, 2)
                    }

                    HQFieldLabel(text: "home server (optional)").padding(.top, 26).padding(.bottom, 9)
                    HQTextField(placeholder: "wss://… (leave blank for default)", text: $serverURL, monospaced: true, ascii: true)
                    Text("the server this profile connects to. friends must share it.")
                        .font(HQFont.ui(12.5)).foregroundColor(HQColor.textDim)
                        .padding(.top, 9).padding(.horizontal, 2)

                    protectionSection

                    agreementSection

                    // Key generation note
                    HStack(alignment: .top, spacing: 11) {
                        Image(systemName: "lock.fill")
                            .font(.system(size: 14))
                            .foregroundColor(HQColor.purpleLight)
                            .accessibilityHidden(true)
                            .frame(width: 30, height: 30)
                            .background(HQColor.purple.opacity(0.1))
                            .overlay(RoundedRectangle(cornerRadius: 4).stroke(HQColor.purple.opacity(0.35), lineWidth: 1))
                            .clipShape(RoundedRectangle(cornerRadius: 4))
                        VStack(alignment: .leading, spacing: 2) {
                            Text("a fresh keypair is forged on-device")
                                .font(HQFont.ui(13, weight: .semibold))
                                .foregroundColor(HQColor.textOnCard)
                            Text("HQC-256 · keys never leave this phone")
                                .font(HQFont.mono(11.5))
                                .foregroundColor(HQColor.textMuted)
                        }
                        Spacer(minLength: 0)
                    }
                    .padding(14)
                    .background(Color.white.opacity(0.02))
                    .overlay(RoundedRectangle(cornerRadius: 4).stroke(Color.white.opacity(0.07), lineWidth: 1))
                    .clipShape(RoundedRectangle(cornerRadius: 4))
                    .padding(.top, 30)
                }
                .padding(.horizontal, 22)
                .padding(.top, 26)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .hqScreenBackground()
        .sheetSizing(minHeight: 560)
    }

    /// All three answers are required: a valid handle, a protection tier (nothing
    /// is preselected) and the agreement, which App Store Guideline 1.2 wants
    /// before the app is used.
    private var canCreate: Bool {
        UsernameRule.isValid(username) && tier != nil && acceptedEula == EulaPrefs.currentVersion
    }

    /// The agreement checkbox. Already checked for a second profile, since the
    /// acceptance is app-wide; it unchecks itself when `EulaPrefs.currentVersion`
    /// changes.
    @ViewBuilder
    private var agreementSection: some View {
        HQFieldLabel(text: "agreement",
                     tint: acceptedEula == EulaPrefs.currentVersion ? HQColor.green : HQColor.textDim)
            .padding(.top, 26).padding(.bottom, 9)

        Button {
            acceptedEula = acceptedEula == EulaPrefs.currentVersion ? "" : EulaPrefs.currentVersion
        } label: {
            HStack(alignment: .top, spacing: 11) {
                Image(systemName: acceptedEula == EulaPrefs.currentVersion
                      ? "checkmark.square.fill" : "square")
                    .font(.system(size: 14))
                    .foregroundColor(acceptedEula == EulaPrefs.currentVersion
                                     ? HQColor.green : HQColor.textDim)
                    .accessibilityHidden(true)
                    .frame(width: 30, height: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text("i agree to the terms")
                        .font(HQFont.ui(13.5, weight: .semibold))
                        .foregroundColor(HQColor.textPrimary)
                    Text("no abuse, no harassment, no illegal content. people who do that get removed.")
                        .font(HQFont.ui(11.5))
                        .foregroundColor(HQColor.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
        }
        .buttonStyle(.plain)
        .hqTapTarget()
        .accessibilityLabel("i agree to the terms")
        .accessibilityAddTraits(acceptedEula == EulaPrefs.currentVersion ? [.isSelected] : [])

        Link("read the full agreement", destination: Deployment.eulaURL)
            .font(HQFont.ui(12.5))
            .foregroundColor(HQColor.purpleLight)
            .padding(.top, 9).padding(.horizontal, 2)
    }

    /// What unlocks this profile's keys: fixed at creation, so chosen here, with
    /// the weaker option's warning on screen while deciding.
    @ViewBuilder
    private var protectionSection: some View {
        HQFieldLabel(text: "protection",
                     tint: tier == nil ? HQColor.textDim
                         : (tier?.isReduced == true ? HQColor.warning : HQColor.green))
            .padding(.top, 26).padding(.bottom, 9)

        if capability.offersWeakerAlternative {
            VStack(spacing: 9) {
                protectionOption(.biometryCurrentSet,
                                 icon: "faceid",
                                 title: "Secure",
                                 subtitle: "Face ID every time your keys are used")
                protectionOption(.userPresence,
                                 icon: "bolt.fill",
                                 title: "Quick unlock",
                                 subtitle: "weaker · one unlock per launch, then never again")
            }
        } else {
            // A single option is shown as information, not as a choice.
            protectionOption(.userPresence,
                             icon: "bolt.fill",
                             title: "Quick unlock",
                             subtitle: capability.headline,
                             selectable: false)
        }

        Text(protectionFootnote)
            .font(HQFont.ui(12.5))
            .foregroundColor(tier?.isReduced == true ? HQColor.warning : HQColor.textDim)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.top, 9).padding(.horizontal, 2)
    }

    private var protectionFootnote: String {
        switch tier {
        case .none:
            return "Choose how this profile unlocks. It is fixed when the profile is created and cannot be changed later."
        case .userPresence:
            return "One unlock — Face ID or your passcode, whichever this device has — then the key stays in memory until the app closes. Anyone who can unlock this device can open this identity and read its messages. Fixed when the profile is created; it cannot be changed later."
        case .biometryCurrentSet:
            return "Fixed when the profile is created — it cannot be changed later."
        }
    }

    private func protectionOption(_ option: KeyProtectionTier,
                                  icon: String,
                                  title: String,
                                  subtitle: String,
                                  selectable: Bool = true) -> some View {
        let isOn = tier == option
        let tint = option.isReduced ? HQColor.warning : HQColor.green
        return Button {
            onSelectTier(option)
        } label: {
            HStack(spacing: 11) {
                Image(systemName: icon)
                    .font(.system(size: 14))
                    .foregroundColor(tint)
                    .accessibilityHidden(true)
                    .frame(width: 30, height: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(HQFont.ui(13.5, weight: .semibold))
                        .foregroundColor(HQColor.textPrimary)
                    Text(subtitle)
                        .font(HQFont.ui(11.5))
                        .foregroundColor(HQColor.textMuted)
                        .fixedSize(horizontal: false, vertical: true)
                        .multilineTextAlignment(.leading)
                }
                Spacer(minLength: 0)
                if selectable {
                    Image(systemName: isOn ? "checkmark.circle.fill" : "circle")
                        .font(.system(size: 17))
                        .foregroundColor(isOn ? tint : HQColor.textOff)
                        .accessibilityHidden(true)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            // The weaker option selects in amber, its warning colour, never green.
            .hqCard(selected: isOn && selectable && !option.isReduced,
                    cornerRadius: 4, padding: 12,
                    accent: isOn && option.isReduced ? HQColor.warning : nil)
        }
        .buttonStyle(.plain)
        // Inert rather than disabled, so an informational row stays readable.
        .allowsHitTesting(selectable)
        .accessibilityAddTraits(isOn ? [.isSelected] : [])
        .accessibilityLabel("\(title). \(subtitle)")
    }
}
