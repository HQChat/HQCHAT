import SwiftUI
import SwiftData
import LocalAuthentication

/// Picks, creates and deletes profiles. First run shows the welcome instead of a list.
struct ProfileSelectionView: View {
    @Environment(\.modelContext) private var modelContext
    @Environment(\.scenePhase) private var scenePhase
    @EnvironmentObject var appState: AppState
    /// Injected, never constructed here, so every screen reads the same profiles.
    @ObservedObject var profileManager: ProfileManager
    /// Set when presented over the app (the profile switcher), which needs a way
    /// out; the first-run presentation passes nil and shows no close control.
    var onClose: (() -> Void)?

    @State private var showingCreateProfile = false
    @State private var newProfileUsername = ""
    @State private var newProfileServerURL = ""
    @State private var errorMessage: String?
    @State private var showingResetConfirmation = false

    /// What this device can gate a key behind. Re-probed on every return to the
    /// foreground: two of the remedies are "set it up in Settings".
    @State private var capability: DeviceAuthCapability = .biometrics
    /// How the profile being created will unlock; nil until the user chooses,
    /// since it cannot be changed later. Filled in when only one option exists.
    @State private var selectedTier: KeyProtectionTier?

    var body: some View {
        VStack(spacing: 20) {
            if let onClose {
                HStack {
                    Spacer()
                    Button(action: onClose) {
                        Text("[esc]")
                            .font(HQFont.mono(13, weight: .bold))
                            .foregroundColor(HQColor.textSecond)
                            .padding(.horizontal, 10).padding(.vertical, 6)
                            .overlay(Rectangle().stroke(Color.white.opacity(0.18), lineWidth: 1))
                            .hqTapTarget()
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("close profile switcher")
                }
            }

            if profileManager.profiles.isEmpty {
                WelcomeHero()
            } else {
                profileList
            }

            VStack(spacing: 9) {
                protectionNotice
                Button(action: beginProfileCreation) {
                    HStack(spacing: 9) {
                        Image(systemName: "plus").font(.system(size: 15, weight: .heavy))
                        Text("new profile")
                    }
                }
                .buttonStyle(HQPrimaryButtonStyle())
                // No key can be stored at all in these states; the notice explains why.
                .disabled(capability.tier == nil)
                .opacity(capability.tier == nil ? 0.45 : 1)
                resetButton
            }
            .padding(.horizontal)
            .padding(.bottom, 20)
        }
        .padding()
        // Size before painting, so the backdrop fills the whole frame.
        #if os(macOS)
        .frame(width: 500, height: 640)
        #else
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        #endif
        .hqScreenBackground()
        .sheet(isPresented: $showingCreateProfile) {
            CreateProfileSheet(
                username: $newProfileUsername,
                serverURL: $newProfileServerURL,
                tier: $selectedTier,
                capability: capability,
                onSelectTier: selectTier,
                onSave: createProfile,
                onCancel: {
                    resetForm()
                    showingCreateProfile = false
                }
            )
        }
        .alert("Error", isPresented: Binding(get: { errorMessage != nil },
                                             set: { if !$0 { errorMessage = nil } })) {
            Button("OK") { errorMessage = nil }
        } message: {
            Text(errorMessage ?? "An unknown error occurred")
        }
        .alert("Reset All Data", isPresented: $showingResetConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Reset", role: .destructive, action: resetAllData)
        } message: {
            Text("This will delete ALL data:\n• All profiles\n• All friends and messages\n• All keys from Keychain\n• All UserDefaults\n\nThis action cannot be undone!")
        }
        .onAppear { capability = .current }
        .onChange(of: scenePhase) { _, phase in
            if phase == .active { capability = .current }
        }
    }

    private var profileList: some View {
        VStack(spacing: 20) {
            VStack(spacing: 8) {
                HQLogoMark(size: 56)
                    .padding(.bottom, 8)
                (Text("select ").fontWeight(.light) + Text("profile").fontWeight(.bold))
                    .font(.system(size: 26))
                    .foregroundColor(.white)
                Text("each identity carries its own keys, friends, and history")
                    .font(HQFont.ui(13.5))
                    .foregroundColor(HQColor.textMuted)
                    .multilineTextAlignment(.center)
            }
            .padding(.top, 40)

            ScrollView {
                LazyVStack(spacing: 12) {
                    ForEach(profileManager.profiles) { profile in
                        ProfileRow(profile: profile,
                                   isActive: profile.id == profileManager.currentProfile?.id,
                                   onSelect: { selectProfile(profile) },
                                   onDelete: { deleteProfile(profile) })
                    }
                }
                .padding(.horizontal)
            }
            .frame(maxHeight: 400)
        }
    }

    /// Shown, before the create button, only when no profile can be created here at all.
    @ViewBuilder
    private var protectionNotice: some View {
        if capability.tier == nil {
            VStack(alignment: .leading, spacing: 8) {
                HQFieldLabel(text: "cannot continue", tint: HQColor.danger)
                Text(capability.headline)
                    .font(HQFont.ui(14, weight: .semibold))
                    .foregroundColor(HQColor.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(capability.remedy)
                    .font(HQFont.ui(12.5))
                    .foregroundColor(HQColor.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .hqCard(accent: HQColor.danger)
            .padding(.horizontal)
        }
    }

    /// Debug builds only, and only when there is something to wipe.
    @ViewBuilder
    private var resetButton: some View {
        #if DEBUG
        if !profileManager.profiles.isEmpty {
            Button {
                showingResetConfirmation = true
            } label: {
                HStack(spacing: 8) {
                    Image(systemName: "trash")
                    Text("reset all")
                }
            }
            .buttonStyle(HQDangerButtonStyle())
            .help("Delete all profiles, keys, and data (dev mode only)")
        }
        #endif
    }

    // MARK: Actions

    /// Selecting a profile is one step: Face ID, then straight into the app.
    private func selectProfile(_ profile: Profile) {
        do {
            try profileManager.switchToProfile(profile)
            enter()
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    /// Hands off to the main app with the now-active profile.
    private func enter() {
        appState.hasActiveProfile = true
        Task { await appState.initialize() }
    }

    /// Opens the creation sheet, preselecting the tier only when there is no choice.
    private func beginProfileCreation() {
        capability = .current
        guard let only = capability.tier else { return }
        selectedTier = capability.offersWeakerAlternative ? nil : only
        showingCreateProfile = true
    }

    /// Choosing "Secure" is what asks for Face ID: the choice and the consent are
    /// one act, and a refusal leaves the tier unchosen.
    private func selectTier(_ tier: KeyProtectionTier) {
        guard tier == .biometryCurrentSet else {
            selectedTier = tier
            return
        }
        Task {
            if await confirmBiometricConsent() {
                selectedTier = .biometryCurrentSet
            }
        }
    }

    private func createProfile() {
        let username = UsernameRule.normalized(newProfileUsername)
        // The server's rule, checked before a keypair is generated.
        if let reason = UsernameRule.rejectionReason(username) {
            errorMessage = "Username: \(reason)."
            return
        }
        Task { await create(username: username) }
    }

    /// Asks for Face ID before writing a key only biometrics can open: writing
    /// such a key raises no prompt, so a denied or missing permission would only
    /// surface at the first read, with the profile already unopenable.
    private func confirmBiometricConsent() async -> Bool {
        // Never beside another biometric prompt: iOS cancels one of the two.
        _ = await BiometricCoordinator.waitUntilFree(timeout: 15)
        BiometricCoordinator.begin()
        defer { BiometricCoordinator.end() }

        do {
            return try await LAContext().evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Confirm it's you, so this profile's keys can be locked to your Face ID")
        } catch {
            // A refusal can change what the device offers; re-probe and say which happened.
            let previous = capability
            capability = .current
            errorMessage = previous != capability
                ? "\(capability.headline) \(capability.remedy)"
                : "Face ID was not confirmed, so no profile was created. Nothing has been changed."
            return false
        }
    }

    private func create(username: String) async {
        guard selectedTier != nil else { return }
        do {
            let profile = try profileManager.createProfile(
                username: username,
                serverURL: newProfileServerURL,
                consentedTier: selectedTier
            )
            // Claimed with the server after the first sign-in (AppState.claimDesiredUsername).
            profile.desiredUsername = username
            try? modelContext.save()
            try profileManager.switchToProfile(profile, skipBiometricVerification: true)
            resetForm()
            showingCreateProfile = false
            enter()
        } catch {
            // The sheet stays open so the user can correct and retry.
            errorMessage = error.localizedDescription
        }
    }

    private func resetForm() {
        newProfileUsername = ""
        newProfileServerURL = ""
        selectedTier = nil
    }

    private func deleteProfile(_ profile: Profile) {
        do {
            try profileManager.deleteProfile(profile)
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func resetAllData() {
        if DataResetService.resetAllData(modelContext: modelContext, profileManager: profileManager) {
            profileManager.loadProfiles()
            profileManager.loadActiveProfile()
            appState.hasActiveProfile = false
        } else {
            errorMessage = "Failed to reset all data. Some items may not have been deleted."
        }
    }
}
