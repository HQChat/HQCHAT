import SwiftUI

/// One profile in the selector: handle, creation date, key prefix, select and delete.
struct ProfileRow: View {
    let profile: Profile
    let isActive: Bool
    let onSelect: () -> Void
    let onDelete: () -> Void
    
    @State private var showingDeleteConfirmation = false

    private static let createdFormat: DateFormatter = {
        let formatter = DateFormatter()
        formatter.dateStyle = .short
        formatter.timeStyle = .none
        formatter.locale = Locale(identifier: "en_US_POSIX")
        return formatter
    }()

    var body: some View {
        HStack(spacing: 13) {
            HQAvatar(name: profile.username, size: 46, glow: isActive ? HQColor.green : HQColor.purple)

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 7) {
                    Text("@\(profile.username)")
                        .font(HQFont.ui(16.5, weight: .semibold))
                        .foregroundColor(HQColor.textPrimary)

                    if isActive {
                        Image(systemName: "checkmark")
                            .accessibilityHidden(true)
                            .font(.system(size: 9, weight: .heavy))
                            .foregroundColor(HQColor.onGreen)
                            .frame(width: 16, height: 16)
                            .background(HQColor.green)
                            .clipShape(Circle())
                            .shadow(color: HQColor.green.opacity(0.8), radius: 6)
                    }
                }

                Text("created \(Self.createdFormat.string(from: profile.createdAt))")
                    .font(HQFont.mono(11))
                    .foregroundColor(HQColor.textDim)

                Text("id \(profile.peerID.prefix(5))…")
                    .font(HQFont.mono(11))
                    .foregroundColor(HQColor.textFaint)
            }

            Spacer()

            HStack(spacing: 8) {
                if !isActive {
                    Button {
                        onSelect()
                    } label: {
                        Text("select")
                            .font(HQFont.ui(13, weight: .semibold))
                            .foregroundColor(HQColor.green)
                            .padding(.horizontal, 14).padding(.vertical, 7)
                            .background(HQColor.green.opacity(0.08))
                            .overlay(RoundedRectangle(cornerRadius: 3).stroke(HQColor.green.opacity(0.4), lineWidth: 1))
                            .clipShape(RoundedRectangle(cornerRadius: 3))
                    }
                    .buttonStyle(.plain)
                }

                Button {
                    showingDeleteConfirmation = true
                } label: {
                    Image(systemName: "trash")
                        .font(.system(size: 14))
                        .foregroundColor(HQColor.danger)
                        .frame(width: 32, height: 32)
                        .background(HQColor.danger.opacity(0.06))
                        .overlay(RoundedRectangle(cornerRadius: 3).stroke(HQColor.danger.opacity(0.28), lineWidth: 1))
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                        .hqTapTarget()
                }
                .buttonStyle(.plain)
                .accessibilityLabel("delete profile @\(profile.username)")
            }
        }
        .hqCard(selected: isActive, padding: 14)
        .hqCornerBrackets(HQColor.green, show: isActive)
        .alert("Delete Profile", isPresented: $showingDeleteConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Delete", role: .destructive) {
                onDelete()
            }
        } message: {
            Text("Are you sure you want to delete @\(profile.username)? This will also delete all friends and messages for this profile.")
        }
    }
}
